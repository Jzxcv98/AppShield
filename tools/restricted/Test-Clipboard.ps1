# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([switch]$BuildOnly, [switch]$ClipboardStationUac, [switch]$WeChatClipboardJob)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $finder = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = & $finder -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'MSVC x64 build tools and Windows SDK are required.' }
    & (Join-Path $vs 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
$output = Join-Path $repo 'build/restricted'
[void][IO.Directory]::CreateDirectory($output)
$exe = Join-Path $output 'AppShield-clipboard-check.exe'
$obj = Join-Path $output 'clipboard.obj'
& cl.exe /nologo /std:c++17 /EHsc /W4 /WX /O1 /MT "/Fe$exe" "/Fo$obj" (Join-Path $PSScriptRoot 'clipboard.cpp') /link /INCREMENTAL:NO
if ($LASTEXITCODE -ne 0) { throw 'Clipboard fixture build failed.' }
if ($BuildOnly) { return }

if ($WeChatClipboardJob) {
    $managed = Join-Path $repo 'build\checks\DesktopChecks.exe'
    if (!(Test-Path -LiteralPath $managed -PathType Leaf)) {throw 'Build the desktop checks with Build-AppShield.ps1 -Test first.'}
    & $exe --managed-job-test-uac $managed
} elseif ($ClipboardStationUac) {
    & $exe --self-test-uac
} else {
    & $exe --self-test
}
if ($LASTEXITCODE -ne 0) { throw 'Clipboard data-plane check failed.' }
