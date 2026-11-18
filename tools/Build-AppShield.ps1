# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([switch]$Test,[switch]$LiveTest,[switch]$PublicNetworkTest,[switch]$WeChatPreloginTest)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$lookup = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$buildTool = if (Test-Path -LiteralPath $lookup) {
    & $lookup -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\Current\Bin\MSBuild.exe' | Select-Object -First 1
}
if (-not $buildTool) { throw 'Visual Studio MSBuild and the .NET Framework 4.8.1 targeting pack are required.' }
if ($WeChatPreloginTest -and ($LiveTest -or $PublicNetworkTest)) { throw 'Run the WeChat pre-login check separately from other live checks.' }
$checks = $Test -or $LiveTest -or $PublicNetworkTest -or $WeChatPreloginTest
$project = if ($checks) { 'tests\desktop\DesktopChecks.csproj' } else { 'src\AppShield\AppShield.csproj' }
& $buildTool (Join-Path $root $project) /nologo /v:minimal /p:Configuration=Release /p:UseSharedCompilation=false /nr:false
if ($LASTEXITCODE -ne 0) { throw 'AppShield build failed.' }
if ($checks) {
    $testOptions = @()
    if ($LiveTest -or $PublicNetworkTest) {
        $vs = & $lookup -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if(-not $vs){throw 'MSVC x64 and Windows SDK are required for the live fixture.'}
        & (Join-Path $vs 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
        $out = Join-Path $root 'build\checks'
        $fixture = Join-Path $out 'AppShieldFixture.exe'
        & cl.exe /nologo /std:c++17 /EHsc /MT /O1 /W4 /WX "/Fe$fixture" "/Fo$out\fixture.obj" (Join-Path $root 'tests\desktop\fixture\client.cpp') /link user32.lib /SUBSYSTEM:WINDOWS /INCREMENTAL:NO
        if($LASTEXITCODE -ne 0){throw 'Native fixture build failed.'}
        $mode = if ($PublicNetworkTest) { '--public-network' } else { '--live' }
        $testOptions = @($mode,$fixture)
    }
    if ($WeChatPreloginTest) { $testOptions = @('--wechat-prelogin') }
    & (Join-Path $root 'build\checks\DesktopChecks.exe') @testOptions
    if ($LASTEXITCODE -eq 77) { Write-Output 'The requested live comparison was not run.'; exit 77 }
    if ($LASTEXITCODE -ne 0) { throw 'Desktop checks failed.' }
}
