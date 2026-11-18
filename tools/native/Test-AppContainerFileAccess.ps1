# SPDX-License-Identifier: GPL-3.0-only
#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Grant-FixtureAccess {
    param([string]$Path, [System.Security.Principal.SecurityIdentifier]$Sid,
          [System.Security.AccessControl.FileSystemRights]$Rights, [switch]$Private)

    $acl = Get-Acl -LiteralPath $Path
    if ($Private) {
        $acl.SetAccessRuleProtection($true, $false)
    }
    # The rule applies only to this exact fixture object.
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($Sid, $Rights, 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $finder = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $finder -PathType Leaf)) {
        throw 'Run from an MSVC developer shell with the C++ tools and Windows SDK installed.'
    }
    $vs = & $finder -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'MSVC x64 build tools are required.' }
    $shell = Join-Path $vs 'Common7\Tools\Launch-VsDevShell.ps1'
    & $shell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
}

$source = Join-Path $PSScriptRoot 'file-probe.cpp'
$runId = [Guid]::NewGuid().ToString('N')
$packageName = "AppShield.FileProbe.$runId"
$fixture = Join-Path ([IO.Path]::GetTempPath()) "AppShield.FileProbe.$runId"
$exe = Join-Path $fixture 'file-probe.exe'
$object = Join-Path $fixture 'file-probe.obj'
$private = Join-Path $fixture 'private.txt'
$shared = Join-Path $fixture 'shared.txt'

New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    Push-Location -LiteralPath $fixture
    try {
        & cl.exe /nologo /std:c++17 /O1 /EHsc /MT /W4 /WX "/Fe$exe" "/Fo$object" $source /link /INCREMENTAL:NO
        if ($LASTEXITCODE -ne 0) { throw 'Native probe build failed.' }
    } finally {
        Pop-Location
    }

    $sidString = & $exe --sid $packageName
    if ($LASTEXITCODE -ne 0) { throw 'AppContainer SID derivation failed.' }
    $package = [System.Security.Principal.SecurityIdentifier]::new($sidString)
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    [IO.File]::WriteAllText($private, 'APPSHIELD_PRIVATE', [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText($shared, 'APPSHIELD_SHARED', [Text.Encoding]::ASCII)

    Grant-FixtureAccess $private $user FullControl -Private
    Grant-FixtureAccess $shared $user FullControl -Private
    Grant-FixtureAccess $fixture $package ReadAndExecute
    Grant-FixtureAccess $exe $package ReadAndExecute
    # The native controller owns the temporary profile through both launches.
    # It grants read access only to shared.txt after the pre-grant check.
    & $exe --run $packageName $fixture
    if ($LASTEXITCODE -ne 0) { throw 'AppContainer verification failed.' }
} finally {
    foreach ($path in @($private, $shared, $object, $exe)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
    # This requires the unique temporary directory to be empty.
    [IO.Directory]::Delete($fixture)
}
