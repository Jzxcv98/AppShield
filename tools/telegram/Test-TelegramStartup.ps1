# SPDX-License-Identifier: GPL-3.0-only
#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Client')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Client')][string]$Executable,
    [Parameter(ParameterSetName = 'Client')][switch]$InstalledImage,
    [Parameter(ParameterSetName = 'Client')][Parameter(ParameterSetName = 'Control')][switch]$InternetClient,
    [Parameter(Mandatory, ParameterSetName = 'Control')][switch]$SelfTest,
    [Parameter(Mandatory, ParameterSetName = 'Build')][switch]$BuildOnly
)
$ErrorActionPreference = 'Stop'
if ($Executable) {
    $item = Get-Item -LiteralPath $Executable -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer -or $item.Name -ne 'Telegram.exe') {
        throw 'Supply the installed Telegram.exe.'
    }
    $Executable = $item.FullName
    if ($InstalledImage -and $Executable -notmatch '\\WindowsApps\\[^\\]+\\') {
        throw 'The in-place test is for the read-only installed Store package. Use the default copy mode for portable installations.'
    }
}
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $finder = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = & $finder -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'MSVC x64 build tools and Windows SDK are required.' }
    & (Join-Path $vs 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
}
$run = [Guid]::NewGuid().ToString('N')
$testTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$build = Join-Path $testTemp "AppShield.TgBuild.$run"
New-Item -ItemType Directory -Path $build | Out-Null
try {
    Push-Location -LiteralPath $build
    try {
        & cl.exe /nologo /std:c++17 /EHsc /MT /O1 /W4 /WX /Fetg-probe.exe /Fotg-probe.obj (Join-Path $PSScriptRoot 'startup.cpp') /link /INCREMENTAL:NO
        if ($LASTEXITCODE -ne 0) { throw 'Startup probe compilation failed.' }
    } finally { Pop-Location }
    if ($BuildOnly) { return }
    $probe = Join-Path $build 'tg-probe.exe'
    $mode = if ($SelfTest) { '--controls' } elseif ($InstalledImage) { '--installed' } else { '--copy' }
    $image = if ($SelfTest) { $probe } else { $Executable }
    $capability = if ($InternetClient) { 'internet-client' } else { 'none' }
    & $probe $mode $run $image $capability
    if ($LASTEXITCODE -ne 0) { throw 'Startup checks did not pass. See the stage and numeric status above.' }
} finally {
    foreach ($file in @('tg-probe.obj','tg-probe.exe')) {
        $artifact = Join-Path $build $file
        if (Test-Path -LiteralPath $artifact -PathType Leaf) { Remove-Item -LiteralPath $artifact -Force }
    }
    [IO.Directory]::Delete($build)
}
