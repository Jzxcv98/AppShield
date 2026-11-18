# SPDX-License-Identifier: GPL-3.0-only
# Builds an unsigned x64 minifilter using Microsoft's project-local WDK package.
[CmdletBinding()]
param(
    [ValidatePattern('^8[0-9]{4}(\.[0-9]+)?$')]
    [string]$AssignedAltitude
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$version = '10.0.26100.6584'
$sdkVersion = '10.0.26100.0'
$id = 'microsoft.windows.wdk.x64'
$catalogHash = 'jhddaBnhMDqt3GVr32RVTtaR0KHmZDjY0JCTMn10OQpk4+AShXCK9QA09vBazp8ni1Mju84qM5SGXfIfnyOJ+g=='
$cache = Join-Path $root '.local\packages'
$package = Join-Path $cache "$id.$version.nupkg"
$expanded = Join-Path $cache "wdk.$version"
$programFiles32 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
$kits = Join-Path $programFiles32 'Windows Kits\10'
$source = Join-Path $root 'driver\AppShieldFilter'
$output = Join-Path $root 'build\driver'

function Confirm-Package([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA512]::Create()
    try { $hash = [Convert]::ToBase64String($sha.ComputeHash($stream)) }
    finally { $sha.Dispose(); $stream.Dispose() }
    if ($hash -cne $catalogHash) { throw 'WDK package failed the pinned NuGet catalog SHA-512 check.' }
}

[void][IO.Directory]::CreateDirectory($cache)
if (-not [IO.File]::Exists($package)) {
    $partial = "$package.$([Guid]::NewGuid().ToString('N')).download"
    $uri = "https://api.nuget.org/v3-flatcontainer/$id/$version/$id.$version.nupkg"
    try {
        Invoke-WebRequest -Uri $uri -OutFile $partial -TimeoutSec 300 -UseBasicParsing
        Confirm-Package $partial
        if (-not [IO.File]::Exists($package)) { [IO.File]::Move($partial, $package) }
    } finally { if ([IO.File]::Exists($partial)) { [IO.File]::Delete($partial) } }
}
Confirm-Package $package
if (-not [IO.Directory]::Exists($expanded)) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $staging = Join-Path $cache ("extract-" + [Guid]::NewGuid().ToString('N'))
    [IO.Compression.ZipFile]::ExtractToDirectory($package, $staging)
    if (-not [IO.Directory]::Exists($expanded)) { [IO.Directory]::Move($staging, $expanded) }
}

$vswhere = Join-Path $programFiles32 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio C++ x64 build tools.' }
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Install Visual Studio C++ x64 build tools.' }
$shared = Join-Path $kits "Include\$sdkVersion\shared"
if (-not (Test-Path -LiteralPath (Join-Path $shared 'ntdef.h'))) { throw "Install Windows SDK $sdkVersion." }
& (Join-Path $vs 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null

$km = Join-Path $expanded "c\Include\$sdkVersion\km"
$lib = Join-Path $expanded "c\Lib\$sdkVersion\km\x64"
$infverif = Join-Path $expanded "c\tools\$sdkVersion\x64\infverif.exe"
$objects = Join-Path $root '.local\driver-build\obj'
[void][IO.Directory]::CreateDirectory($objects)
$compile = @('/nologo', '/kernel', '/GS', '/guard:cf', '/W4', '/WX', '/O2', '/Zl', '/Gy', '/Zp8',
    '/D_AMD64_', '/DAMD64', '/D_WIN32_WINNT=0x0A00', '/DWINVER=0x0A00', '/DNTDDI_VERSION=NTDDI_WIN11_GE',
    "/external:I$km", "/external:I$shared", '/external:anglebrackets', '/external:W0')
$sources = @(Get-ChildItem -LiteralPath $source -File -Filter '*.c' | Sort-Object Name)
if ($sources.Count -eq 0) { throw 'No minifilter sources found.' }
$objFiles = @(foreach ($file in $sources) {
    $obj = Join-Path $objects ($file.BaseName + '.obj')
    & cl.exe @compile /c $file.FullName "/Fo$obj" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Driver compilation failed for $($file.Name)." }
    $obj
})

$image = Join-Path $objects 'AppShieldFilter.sys'
$link = @('/nologo', '/driver', '/nodefaultlib', '/subsystem:native,10.00', '/machine:x64', '/entry:GsDriverEntry',
    '/integritycheck', '/dynamicbase', '/nxcompat', '/guard:cf', '/release', '/Brepro', "/libpath:$lib")
& link.exe @link @objFiles ntoskrnl.lib fltMgr.lib BufferOverflowFastFailK.lib hal.lib "/out:$image"
if ($LASTEXITCODE -ne 0) { throw 'Driver linking failed.' }

$bytes = [IO.File]::ReadAllBytes($image)
$pe = [BitConverter]::ToInt32($bytes, 60)
$opt = $pe + 24
$dllFlags = [BitConverter]::ToUInt16($bytes, $opt + 70)
if ([BitConverter]::ToUInt32($bytes, $pe) -ne 0x4550 -or
    [BitConverter]::ToUInt16($bytes, $pe + 4) -ne 0x8664 -or
    [BitConverter]::ToUInt16($bytes, $opt) -ne 0x20b -or
    [BitConverter]::ToUInt16($bytes, $opt + 68) -ne 1 -or ($dllFlags -band 0x1c0) -ne 0x1c0) {
    throw 'Unexpected driver PE architecture, subsystem, or protection flags.'
}
$imports = (& dumpbin.exe /nologo /imports $image) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0 -or $imports -notmatch '(?im)^\s*FLTMGR\.SYS\s*$' -or
    $imports -notmatch '(?im)^\s*ntoskrnl\.exe\s*$' -or
    $imports -match '(?im)^\s*(kernel32|user32|advapi32|ntdll)\.dll\s*$') {
    throw 'Unexpected driver imports.'
}

$infTemplate = [IO.File]::ReadAllText((Join-Path $source 'AppShieldFilter.inf'))
if (-not $infTemplate.Contains('@APPSHIELD_ALTITUDE@')) { throw 'Missing altitude template value.' }
# The synthetic value goes only into the offline verification directory.
$altitude = if ($AssignedAltitude) { $AssignedAltitude } else { '80000.98765' }
$testInf = Join-Path $objects 'AppShieldFilter.inf'
[IO.File]::WriteAllText($testInf, $infTemplate.Replace('@APPSHIELD_ALTITUDE@', $altitude), [Text.Encoding]::Unicode)
& $infverif /w $testInf
if ($LASTEXITCODE -ne 0) { throw 'Microsoft InfVerif /w rejected the package metadata.' }

[void][IO.Directory]::CreateDirectory($output)
[IO.File]::Copy($image, (Join-Path $output 'AppShieldFilter.sys'), $true)
$controller = Join-Path $source 'lab\FilterLab.cpp'
$sdkLib = Join-Path $kits "Lib\$sdkVersion\um\x64"
& cl.exe /nologo /std:c++17 /MT /EHsc /W4 /WX /O2 /DUNICODE /D_UNICODE $controller "/Fo$objects\FilterLab.obj" "/Fe$output\FilterLab.exe" /link /Brepro "/libpath:$sdkLib"
if ($LASTEXITCODE -ne 0) { throw 'User-mode filter lab controller compilation failed.' }
if ($AssignedAltitude) {
    $unsignedPackage = Join-Path $output ("package-" + $AssignedAltitude)
    [void][IO.Directory]::CreateDirectory($unsignedPackage)
    [IO.File]::Copy($image, (Join-Path $unsignedPackage 'AppShieldFilter.sys'), $true)
    [IO.File]::Copy($testInf, (Join-Path $unsignedPackage 'AppShieldFilter.inf'), $true)
}
Write-Output 'Built build/driver/AppShieldFilter.sys (unsigned x64 Native PE) and FilterLab.exe. WDK InfVerif /w passed.'
