<#
  Builds PairVPN1916-ARM64-Setup.exe: one self-contained installer for Windows on ARM.
  Needs only what ships with Windows 11 on ARM (.NET Framework 4.8.1 csc.exe), plus Git for
  Windows' perl if payload\PairVPN.exe has to be re-created from original\PairVPN.exe.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$csc = Join-Path $env:WINDIR 'Microsoft.NET\FrameworkArm64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe' }

Write-Host '== bridge service'
& $csc /nologo /optimize+ /target:exe /platform:anycpu /r:System.ServiceProcess.dll `
    "/out:$root\payload\PairVPN-ARM64-Bridge.exe" "$root\src\PairVpnArm64Bridge.cs"
if ($LASTEXITCODE) { throw 'bridge build failed' }

if (-not (Test-Path "$root\payload\PairVPN.exe")) {
    Write-Host '== patching PairVPN.exe'
    $perl = (Get-Command perl -ErrorAction SilentlyContinue).Source
    if (-not $perl) { $perl = 'C:\Program Files\Git\usr\bin\perl.exe' }
    & $perl "$root\tools\patch_pairvpn.pl" "$root\original\PairVPN.exe" "$root\payload\PairVPN.exe"
    if ($LASTEXITCODE) { throw 'patch failed' }
}

Write-Host '== setup'
$resources = [ordered]@{
    'PairVPN.exe'              = 'payload\PairVPN.exe'
    'pvservice.exe'            = 'payload\pvservice.exe'
    'PairVPN-ARM64-Bridge.exe' = 'payload\PairVPN-ARM64-Bridge.exe'
    'tap.OemVista.inf'         = 'tap-windows6-arm64\OemVista.inf'
    'tap.tap0901.sys'          = 'tap-windows6-arm64\tap0901.sys'
    'tap.tap0901.cat'          = 'tap-windows6-arm64\tap0901.cat'
    'tap.devcon.exe'           = 'tap-windows6-arm64\devcon.exe'
}
$resArgs = foreach ($name in $resources.Keys) { '/resource:' + (Join-Path $root $resources[$name]) + ',' + $name }
$out = Join-Path $root 'PairVPN1916-ARM64-Setup.exe'
& $csc /nologo /optimize+ /target:winexe /platform:anycpu `
    "/win32manifest:$root\src\setup.manifest" "/win32icon:$root\src\pairvpn.ico" `
    /r:System.dll /r:System.Core.dll /r:Microsoft.CSharp.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.ServiceProcess.dll `
    $resArgs "/out:$out" "$root\src\PairVpnArm64Setup.cs"
if ($LASTEXITCODE) { throw 'setup build failed' }
Get-Item $out | Format-Table Name, Length, LastWriteTime -AutoSize
