# PairVPN 1.9.16 on Windows on ARM (ARM64)

**`PairVPN1916-ARM64-Setup.exe`** is a single, self-contained installer. Double-click it, approve the
admin prompt, and it does everything:

1. Checks for the Microsoft Visual C++ Runtime that PairVPN's route helper needs. If it's missing,
   it offers to download it from Microsoft, checks Microsoft's signature, and installs it.
2. Installs OpenVPN's Microsoft-signed **TAP-Windows6 9.27.0 ARM64** driver and creates the
   network adapter **"PairVPN"**.
3. Installs into `C:\Program Files\PairVPN`:
   - **PairVPN.exe**, patched to use that adapter;
   - PairVPN's own route service, **pvservice.exe**;
   - the **PairVPN ARM64 Bridge** service.
4. Starts both services. Adds a Start menu shortcut and a Settings → Apps entry,
   *PairVPN (ARM64 compatibility install)*.
5. Self-tests the whole path. It opens the bridge the way PairVPN does, checks that Windows' DHCP
   traffic arrives, and checks that a frame sent toward Windows gets Windows' ARP reply.

Run it again to repair or update the install.

## Why the official installer can't work on ARM64

PairVPN's own network driver, `pveth.sys`, exists only for x86 and x64, and Windows on ARM can't
load x64 kernel drivers. Installing OpenVPN's TAP driver alone, the usual web advice, doesn't help
either, because PairVPN never looks for TAP adapters.

This install changes only what's needed:

- **PairVPN.exe** opens `\\.\pipe\pveth` instead of `\\.\PVETH`, looks for adapter id `tap0901`
  instead of `pveth`, and uses `ReadFile`/`WriteFile` in place of pveth's four IOCTLs. Pairing,
  encryption, DHCP, ARP and routing are unchanged.
- **The bridge service** relays Ethernet frames between that pipe and the TAP adapter, in exactly
  pveth's data format.

## Command line

| | |
|---|---|
| `PairVPN1916-ARM64-Setup.exe` | install or repair, with a progress window |
| `... /quiet` | silent install (`/launch` starts PairVPN afterwards) |
| `... /uninstall` | uninstall (`/uninstall /quiet` for silent) |
| `... /noselftest` | skip the self-test |

Logs:
- `C:\ProgramData\PairVPN-ARM64\setup.log`: install
- `%TEMP%\PairVPN-ARM64-uninstall.log`: uninstall
- `C:\ProgramData\PairVPN-ARM64\bridge.log`: bridge; each connection shows *PairVPN opened the
  adapter* and then *TAP adapter link up*

To test the bridge without the phone, close PairVPN and run:
`"C:\Program Files\PairVPN\PairVPN-ARM64-Bridge.exe" probe 15 sendtest`

## Caveats

- **Don't let PairVPN update itself.** The official installer would replace the patched app and fail
  at its driver step. The patch is for 1.9.16 only.
- **Unsigned files.** The setup, the patched PairVPN.exe and the bridge are unsigned:
  - Windows shows "Unknown publisher" at the admin prompt.
  - On another PC, SmartScreen may warn about a downloaded copy.
  - If Smart App Control is switched fully on, Windows blocks these files. It's in evaluation
    mode on this PC.
- **No inbound firewall rule.** The official installer adds one; Windows will ask instead if
  PairVPN ever needs to accept incoming connections.
- **Pairing settings.** Uninstalling keeps them, in `HKCU\Software\PairVPN`.

## Rebuilding (`build.ps1`)

`build.ps1` uses only the .NET Framework 4.8.1 compiler that ships with Windows 11 on ARM. If
`payload\PairVPN.exe` is missing, it re-creates it with Git for Windows' Perl.

| Path | Contents |
|---|---|
| `src\PairVpnArm64Setup.cs` | the installer |
| `src\PairVpnArm64Bridge.cs` | the bridge service |
| `src\setup.manifest`, `src\pairvpn.ico` | installer manifest and icon |
| `tools\patch_pairvpn.pl` | the PairVPN.exe patch: `perl tools\patch_pairvpn.pl original\PairVPN.exe payload\PairVPN.exe` |
| `tools\extract_icon.pl` | icon extraction |
| `original\PairVPN.exe` | the unmodified, vendor-signed 1.9.16 executable |
| `payload\` | the files embedded in the setup |
| `tap-windows6-arm64\` | the driver package and `devcon.exe`, from https://github.com/OpenVPN/tap-windows6/releases/tag/9.27.0 (`dist.win10.zip`) |
