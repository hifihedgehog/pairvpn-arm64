#!/usr/bin/perl
# Patch PairVPN 1.9.16 (PairVPN.exe, x86) so it can run on Windows on ARM.
#
# PairVPN normally talks to its own x64-only kernel driver (pveth.sys) through
# \\.\PVETH using four DeviceIoControl codes:
#   0x220008  wait for "adapter ready"   (overlapped, 4-byte output)
#   0x220000  read frames                (overlapped, 32 KB of [u32 len][frame] records)
#   0x220004  write one Ethernet frame   (overlapped, input = frame)
#   0x22000C  stop                       (overlapped, no buffers)
# This patch points it at the named pipe \\.\pipe\pveth instead (served by
# PairVPN-ARM64-Bridge.exe, which relays to an ARM64 TAP-Windows6 adapter):
#   * "\\.\PVETH"  -> "\\.\pipe\pveth"
#   * adapter ComponentId "pveth" -> "tap0901"
#   * the 5 DeviceIoControl call sites -> a small position-independent stub that
#     issues ReadFile (0x220000/0x220008) or WriteFile (0x220004/0x22000C) with
#     the same handle, buffer, length, bytes-pointer and OVERLAPPED.
#   * base relocations under the patched call operands are neutralised (ASLR stays on)
#   * the (now invalid) Authenticode signature is removed and the PE checksum fixed.
#
# Usage: perl patch_pairvpn.pl <original PairVPN.exe> <patched output.exe>
use strict;
use warnings;

my ($in, $out) = @ARGV;
die "usage: $0 original.exe patched.exe\n" unless $in && $out;
open my $fh, '<:raw', $in or die "$in: $!";
my $d = do { local $/; <$fh> };
close $fh;

my $pe = unpack("V", substr($d, 0x3C, 4));
die "not a PE file\n" unless substr($d, $pe, 4) eq "PE\0\0";
my $nsec  = unpack("v", substr($d, $pe + 6, 2));
my $optsz = unpack("v", substr($d, $pe + 20, 2));
my $opt   = $pe + 24;
die "expected PE32\n" unless unpack("v", substr($d, $opt, 2)) == 0x10b;
my $base = unpack("V", substr($d, $opt + 28, 4));
die "unexpected image base\n" unless $base == 0x400000;
my $secoff = $opt + $optsz;
my @secs;
for my $i (0 .. $nsec - 1) {
    my ($name, $vsize, $va, $rsize, $rptr) = unpack("a8 V V V V", substr($d, $secoff + 40 * $i, 40));
    $name =~ s/\0.*//s;
    push @secs, { name => $name, vsize => $vsize, va => $va, rsize => $rsize, rptr => $rptr, hdr => $secoff + 40 * $i };
}
sub va2off {
    my $va = shift;
    my $rva = $va - $base;
    for my $s (@secs) {
        return $s->{rptr} + $rva - $s->{va} if $rva >= $s->{va} && $rva < $s->{va} + $s->{rsize};
    }
    die sprintf("VA 0x%X not in file\n", $va);
}
sub expect {
    my ($va, $hex, $what) = @_;
    my $o = va2off($va);
    my $have = unpack("H*", substr($d, $o, length($hex) / 2));
    die sprintf("%s at 0x%X: expected %s, found %s (wrong PairVPN version?)\n", $what, $va, $hex, $have)
        unless $have eq $hex;
}
sub put { my ($va, $bytes) = @_; substr($d, va2off($va), length $bytes) = $bytes; }

# ---- 0. Sanity: this must be PairVPN 1.9.16 exactly -------------------------
my $IAT_DIOC  = 0x49D104;   # KERNEL32!DeviceIoControl
my $IAT_READ  = 0x49D17C;   # KERNEL32!ReadFile
my $IAT_WRITE = 0x49D0EC;   # KERNEL32!WriteFile
my @sites = (0x407840, 0x4079A2, 0x407A52, 0x407B6F, 0x407C39);
my $calldioc = "ff15" . unpack("H*", pack("V", $IAT_DIOC));
expect($_, $calldioc, "DeviceIoControl call") for @sites;
expect(0x4AEF40, unpack("H*", "\\\\.\\PVETH\0\0\0\0\0\0\0"), "device path string");
expect(0x4AEED4, unpack("H*", "pveth\0\0\0"), "ComponentId string");
expect(0x407722, "6840ef4a00", "push device path");
expect(0x40735E, "b8d4ee4a00", "mov ComponentId string");

# ---- 1. Strip the Authenticode signature (it cannot survive patching) -------
my $secdir = $opt + 96 + 4 * 8;
my ($certoff, $certsz) = unpack("V V", substr($d, $secdir, 8));
if ($certoff) {
    die "certificate table not at end of file\n" unless $certoff + $certsz == length $d;
    $d = substr($d, 0, $certoff);
    substr($d, $secdir, 8) = pack("V V", 0, 0);
}

# ---- 2. Strings ---------------------------------------------------------------
put(0x4AEF40, "\\\\.\\pipe\\pveth\0\0");     # 16-byte slot
put(0x4AEED4, "tap0901\0");                   # 8-byte slot

# ---- 3. Stub in the zero padding at the end of .text --------------------------
my ($text) = grep { $_->{name} eq '.text' } @secs;
my $STUB = 0x49C140;
my $textEndVA = $base + $text->{va} + $text->{vsize};
die "stub would overlap code\n" if $STUB < $textEndVA;
die "stub area not empty\n" if substr($d, va2off($textEndVA), $base + $text->{va} + $text->{rsize} - $textEndVA) =~ /[^\0]/;

my $code = '';
my %lbl;
my @fix;    # [offset in $code, label, kind] kind: rel8 / rel32 / iat:<va>
sub emit { $code .= shift }
sub here { length $code }
# DeviceIoControl(hDev, code, inBuf, inLen, outBuf, outLen, pRet, pOv)  -- stdcall
emit("\x8B\x44\x24\x08");                       # mov eax, [esp+8]        ; dwIoControlCode
emit("\x3D" . pack("V", 0x220004));             # cmp eax, 0x220004       ; write frame
emit("\x74\x00"); push @fix, [here() - 1, 'write', 'rel8'];
emit("\x3D" . pack("V", 0x22000C));             # cmp eax, 0x22000C       ; stop -> 0-byte write
emit("\x74\x00"); push @fix, [here() - 1, 'write', 'rel8'];
# read: ReadFile(hDev, outBuf, outLen, pRet, pOv)
emit("\xFF\x74\x24\x20");                       # push [esp+0x20]  pOv
emit("\xFF\x74\x24\x20");                       # push [esp+0x20]  pRet
emit("\xFF\x74\x24\x20");                       # push [esp+0x20]  outLen
emit("\xFF\x74\x24\x20");                       # push [esp+0x20]  outBuf
emit("\xFF\x74\x24\x14");                       # push [esp+0x14]  hDev
emit("\xE8\0\0\0\0"); push @fix, [here() - 4, 'getpc', 'rel32'];
my $pcR = here();
emit("\x8B\x80\0\0\0\0"); push @fix, [here() - 4, $pcR, "iat:$IAT_READ"];   # mov eax, [eax+disp] -> ReadFile
emit("\xFF\xD0");                               # call eax
emit("\xC2\x20\x00");                           # ret 0x20
# write: WriteFile(hDev, inBuf, inLen, pRet, pOv)
$lbl{write} = here();
emit("\xFF\x74\x24\x20");                       # push [esp+0x20]  pOv
emit("\xFF\x74\x24\x20");                       # push [esp+0x20]  pRet
emit("\xFF\x74\x24\x18");                       # push [esp+0x18]  inLen
emit("\xFF\x74\x24\x18");                       # push [esp+0x18]  inBuf
emit("\xFF\x74\x24\x14");                       # push [esp+0x14]  hDev
emit("\xE8\0\0\0\0"); push @fix, [here() - 4, 'getpc', 'rel32'];
my $pcW = here();
emit("\x8B\x80\0\0\0\0"); push @fix, [here() - 4, $pcW, "iat:$IAT_WRITE"];  # mov eax, [eax+disp] -> WriteFile
emit("\xFF\xD0");                               # call eax
emit("\xC2\x20\x00");                           # ret 0x20
$lbl{getpc} = here();
emit("\x8B\x04\x24");                           # mov eax, [esp]
emit("\xC3");                                   # ret

for my $f (@fix) {
    my ($at, $what, $kind) = @$f;
    if ($kind eq 'rel8') {
        my $rel = $lbl{$what} - ($at + 1);
        die "rel8 out of range\n" if $rel > 127 || $rel < -128;
        substr($code, $at, 1) = pack("c", $rel);
    } elsif ($kind eq 'rel32') {
        substr($code, $at, 4) = pack("l<", $lbl{$what} - ($at + 4));
    } elsif ($kind =~ /^iat:(\d+)$/) {
        # disp = IAT slot VA - VA of the instruction that getpc returned (= $what)
        substr($code, $at, 4) = pack("l<", $1 - ($STUB + $what));
    }
}
die "stub too large\n" if $STUB + length($code) > $base + $text->{va} + $text->{rsize};
put($STUB, $code);
# make the stub officially part of .text
substr($d, $text->{hdr} + 8, 4) = pack("V", $text->{rsize});

# ---- 4. Redirect the five DeviceIoControl call sites to the stub ----------------
for my $s (@sites) {
    put($s, "\xE8" . pack("l<", $STUB - ($s + 5)) . "\x90");
}

# ---- 5. Neutralise the HIGHLOW relocations that pointed into those call operands
my ($rrva, $rsz) = unpack("V V", substr($d, $opt + 96 + 5 * 8, 8));
my %kill = map { ($_ + 2 - $base) => 1 } @sites;
my $o = va2off($base + $rrva);
my $end = $o + $rsz;
my $killed = 0;
while ($o < $end) {
    my ($page, $bsz) = unpack("V V", substr($d, $o, 8));
    last unless $bsz;
    for (my $k = 8; $k < $bsz; $k += 2) {
        my $e = unpack("v", substr($d, $o + $k, 2));
        next unless ($e >> 12) == 3;
        if ($kill{$page + ($e & 0xFFF)}) { substr($d, $o + $k, 2) = "\0\0"; $killed++; }
    }
    $o += $bsz;
}
die "expected to neutralise 5 relocations, did $killed\n" unless $killed == 5;

# ---- 6. PE checksum ------------------------------------------------------------
my $ckoff = $opt + 64;
substr($d, $ckoff, 4) = "\0\0\0\0";
my $sum = 0;
my $len = length $d;
my $padded = $d . ($len % 2 ? "\0" : "");
for my $w (unpack("v*", $padded)) {
    $sum += $w;
    $sum = ($sum & 0xFFFF) + ($sum >> 16);
}
$sum = ($sum & 0xFFFF) + ($sum >> 16);
$sum += $len;
substr($d, $ckoff, 4) = pack("V", $sum & 0xFFFFFFFF);

open my $oh, '>:raw', $out or die "$out: $!";
print $oh $d;
close $oh;
printf "Patched %s -> %s (%d bytes, stub %d bytes at 0x%X, checksum 0x%08X)\n", $in, $out, length $d, length $code, $STUB, $sum;
