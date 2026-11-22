#!/usr/bin/perl
# Extract the first icon group of a PE file into a .ico file.
# Usage: perl extract_icon.pl file.exe out.ico
use strict;
use warnings;

my ($in, $out) = @ARGV;
die "usage: $0 file.exe out.ico\n" unless $in && $out;
open my $fh, '<:raw', $in or die "$in: $!";
my $d = do { local $/; <$fh> };
close $fh;

my $pe = unpack("V", substr($d, 0x3C, 4));
my $nsec = unpack("v", substr($d, $pe + 6, 2));
my $optsz = unpack("v", substr($d, $pe + 20, 2));
my $opt = $pe + 24;
my $magic = unpack("v", substr($d, $opt, 2));
my $dd = $opt + ($magic == 0x20b ? 112 : 96);
my ($rsrcRva) = unpack("V", substr($d, $dd + 2 * 8, 4));
die "no resources\n" unless $rsrcRva;
my @secs;
for my $i (0 .. $nsec - 1) {
    my ($n, $vs, $va, $rs, $rp) = unpack("a8 V V V V", substr($d, $opt + $optsz + 40 * $i, 40));
    push @secs, [$va, ($vs > $rs ? $vs : $rs), $rp];
}
sub r2o { my $r = shift; for (@secs) { my ($va, $sz, $rp) = @$_; return $rp + $r - $va if $r >= $va && $r < $va + $sz; } die sprintf("rva 0x%X?\n", $r) }
my $base = r2o($rsrcRva);

# returns list of [id_or_name, offset(with high bit = subdir)]
sub entries {
    my $off = shift;
    my ($named, $ids) = unpack("v v", substr($d, $base + $off + 12, 4));
    my @e;
    for my $i (0 .. $named + $ids - 1) {
        my ($name, $to) = unpack("V V", substr($d, $base + $off + 16 + 8 * $i, 8));
        push @e, [$name, $to];
    }
    return @e;
}
sub leaf_data {    # follow first entry down to a data entry
    my $to = shift;
    while ($to & 0x80000000) { my @e = entries($to & 0x7FFFFFFF); $to = $e[0][1]; }
    my ($rva, $size) = unpack("V V", substr($d, $base + $to, 8));
    return substr($d, r2o($rva), $size);
}
my %types = map { $_->[0] => $_->[1] } entries(0);
die "no RT_GROUP_ICON\n" unless exists $types{14};
die "no RT_ICON\n" unless exists $types{3};
my @groups = entries($types{14} & 0x7FFFFFFF);
my $grp = leaf_data($groups[0][1]);
my %icons = map { $_->[0] => $_->[1] } entries($types{3} & 0x7FFFFFFF);

my ($res, $type, $count) = unpack("v v v", substr($grp, 0, 6));
my (@dir, @imgs);
for my $i (0 .. $count - 1) {
    my ($w, $h, $cc, $r, $planes, $bpp, $bytes, $id) = unpack("C C C C v v V v", substr($grp, 6 + 14 * $i, 14));
    die "icon id $id missing\n" unless exists $icons{$id};
    my $img = leaf_data($icons{$id});
    push @dir, [$w, $h, $cc, $planes, $bpp, length $img];
    push @imgs, $img;
}
my $ico = pack("v v v", 0, 1, scalar @dir);
my $offset = 6 + 16 * @dir;
for my $i (0 .. $#dir) {
    my ($w, $h, $cc, $planes, $bpp, $len) = @{ $dir[$i] };
    $ico .= pack("C C C C v v V V", $w, $h, $cc, 0, $planes, $bpp, $len, $offset);
    $offset += $len;
}
$ico .= join('', @imgs);
open my $o, '>:raw', $out or die "$out: $!";
print $o $ico;
close $o;
printf "%s: %d image(s): %s\n", $out, scalar @dir, join(", ", map { ($_->[0] || 256) . "x" . ($_->[1] || 256) . "x" . $_->[4] } @dir);
