# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TrialSid, [Parameter(Mandatory)][int]$Session,
    [Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Client)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne $TrialSid -or ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -ne $Session) {exit 2}
function Wait-Phase([string]$Phase) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while (![IO.File]::Exists((Join-Path $Root ('control\'+$Phase)))) {
        if ($clock.Elapsed.TotalSeconds -gt 100) {throw 'Control timeout.'}
        Start-Sleep -Milliseconds 150
    }
}
function Confirm-Stage([string]$Phase) {
    $dest=Join-Path $Root ('shared\'+$Phase)
    [IO.File]::WriteAllText($dest+'.new',[string]$PID)
    [IO.File]::Move($dest+'.new',$dest)
}
function Test-Denied([string]$Path) {
    try { [void][IO.File]::ReadAllText($Path); return $false }
    catch { return (5 -eq ($_.Exception.GetBaseException().HResult -band 65535)) }
}
try {
    if (!(Test-Denied (Join-Path $Root 'private\marker')) -or
        [IO.File]::ReadAllText((Join-Path $Root 'shared\marker')) -ne 'shared' -or
        [IO.File]::ReadAllText((Join-Path $Root 'live\marker')) -ne 'live') {exit 3}
    Confirm-Stage 'baseline'
    Wait-Phase 'client'
    $clientPid=[int][IO.File]::ReadAllText((Join-Path $Root 'control\client'))
    $process=[Diagnostics.Process]::GetProcessById($clientPid)
    if ($process.SessionId -ne $Session -or $process.MainModule.FileName -ine $Client) {exit 7}
    Add-Type -Path (Join-Path $Root 'control\HostAccount-AccessCheck.cs')
    function TokenAllowsRead([string]$Name) {
        $sd=[IO.File]::ReadAllBytes((Join-Path $Root ('control\'+$Name+'.sd')))
        return [AppShield.Trials.HostAccountAccessCheck]::CanReadData($process,$TrialSid,$Session,$Client,$sd)
    }
    if ((TokenAllowsRead 'private') -or !(TokenAllowsRead 'baseline')) {exit 16}
    Confirm-Stage 'tokenready'
    Wait-Phase 'deny'
    if (!(Test-Denied (Join-Path $Root 'live\marker')) -or (TokenAllowsRead 'denied')) {exit 4}
    Confirm-Stage 'denied'
    Wait-Phase 'revoke'
    if ([IO.File]::ReadAllText((Join-Path $Root 'live\marker')) -ne 'live' -or !(TokenAllowsRead 'restored')) {exit 5}
    Confirm-Stage 'revoked'
    Wait-Phase 'observe'
    Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
    $a=[Windows.Automation.AutomationElement]
    $owned=[Windows.Automation.PropertyCondition]::new($a::ProcessIdProperty,$clientPid)
    $visible=[Windows.Automation.PropertyCondition]::new($a::IsOffscreenProperty,$false)
    $ownedVisible=[Windows.Automation.AndCondition]::new($owned,$visible)
    $labels=foreach ($text in @('Scan to log in','Scan QR code to log in','扫码登录','掃碼登入','扫描二维码登录','掃描二維碼登入','请使用手机微信扫码登录','請使用手機微信掃碼登入','请使用手机微信扫描二维码登录','請使用手機微信掃描二維碼登入')) {
        [Windows.Automation.PropertyCondition]::new($a::NameProperty,$text,[Windows.Automation.PropertyConditionFlags]::IgnoreCase)
    }
    $scan=[Windows.Automation.AndCondition]::new($ownedVisible,[Windows.Automation.OrCondition]::new([Windows.Automation.Condition[]]$labels))
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $candidate=0
    $since=0
    do {
        if ($process.HasExited) {exit 9}
        $match=0
        foreach ($w in $a::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$ownedVisible)) {
            try {
                if ($w.Current.ClassName -eq '#32770' -and $w.Current.Name.Replace([char]0xa0,[char]0x20) -in 'Launch Error','启动错误','啟動錯誤') {exit 10}
                if ($w.FindFirst([Windows.Automation.TreeScope]::Descendants,$scan)) {$match=$w.Current.NativeWindowHandle}
            } catch [Windows.Automation.ElementNotAvailableException] {}
        }
        if ($match -eq 0 -or $match -ne $candidate) {$candidate=$match;$since=$timer.ElapsedMilliseconds}
        elseif ($timer.ElapsedMilliseconds-$since -ge 3000) {Confirm-Stage 'scan';exit 0}
        Start-Sleep -Milliseconds 250
    } while ($timer.Elapsed.TotalSeconds -lt 45)
    exit 11
} catch {
    $e=$_.Exception.GetBaseException()
    [IO.File]::WriteAllText((Join-Path $Root 'shared\probe-error'),($e.GetType().FullName+' HRESULT='+$e.HResult+' line='+$_.InvocationInfo.ScriptLineNumber+' '+$e.Message))
    exit 99
}
