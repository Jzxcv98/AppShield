# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([string]$ProductAssembly)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) {throw 'Use 64-bit Windows PowerShell 5.1.'}
$user = [Security.Principal.WindowsIdentity]::GetCurrent()
if (!([Security.Principal.WindowsPrincipal]::new($user)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'Requesting elevation for the temporary synthetic rules and scheduled tasks.'
    $arguments = '-NoProfile -NonInteractive -File "'+$PSCommandPath+'"'
    if ($ProductAssembly) { $arguments += ' -ProductAssembly "'+(Resolve-Path -LiteralPath $ProductAssembly).Path+'"' }
    $child = Start-Process (Join-Path $PSHOME 'powershell.exe') -ErrorAction Stop -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -PassThru -Wait
    exit $child.ExitCode
}
$repo = Split-Path (Split-Path $PSScriptRoot)
if (!$ProductAssembly) {$ProductAssembly = Join-Path $repo 'build\AppShield\AppShield.exe'}
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $ProductAssembly).Path)
$backend = $assembly.GetType('AppShield.Native.WeChatAccountNetwork',$true)
$addr = [Net.Dns]::GetHostAddresses('www.microsoft.com') | Where-Object {
    $b = $_.GetAddressBytes()
    $_.AddressFamily -eq 'InterNetwork' -and $b[0] -notin 0,10,127 -and $b[0] -lt 224 -and
       !($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -and !($b[0] -eq 192 -and $b[1] -eq 168) -and
       !($b[0] -eq 169 -and $b[1] -eq 254) -and !($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)
} | Select-Object -First 1
if (!$addr) {throw 'No external IPv4 control was available.'}
$id = [guid]::NewGuid()
$tag = 'AppShield.WeChatNetwork.'+$id.ToString('N')
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $tag
$probe = Join-Path $root 'NetworkA.exe'
$control = Join-Path $root 'NetworkB.exe'
$source = Join-Path $PSScriptRoot 'NetworkConnectProbe.cs'
$service = [Security.Principal.SecurityIdentifier]'S-1-5-19'
$system = [Security.Principal.SecurityIdentifier]'S-1-5-18'
$admins = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
foreach ($s in $admins,$system,$user.User,$service) {
    $rights = if ($s -eq $admins -or $s -eq $system) {'FullControl'} else {'ReadAndExecute'}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,$rights,'ContainerInherit,ObjectInherit','None','Allow'))
}
$owned = @()
$tried = $false
if ([IO.Directory]::Exists($root)) {throw 'Trial collision.'}
[void][IO.Directory]::CreateDirectory($root,$acl)

function Invoke-Backend([string]$Mode) {
    if ($Mode -eq 'RecordedAccounts') {
        return $backend.GetMethod($Mode,[Reflection.BindingFlags]'Static,NonPublic').Invoke($null,
            [object[]]@($id.PSObject.BaseObject,$probe.PSObject.BaseObject))
    }
    $backend.GetMethod($Mode,[Reflection.BindingFlags]'Static,NonPublic').Invoke($null,
        [object[]]@($id.PSObject.BaseObject,$probe.PSObject.BaseObject,$user.User.PSObject.BaseObject))
}
function New-ProbeTask([string]$Label,[string]$Program,$Sid,[string]$Logon) {
    $nt = $Sid.Translate([Security.Principal.NTAccount]).Value
    $principal = New-ScheduledTaskPrincipal -UserId $nt -LogonType $Logon -RunLevel Limited
    $action = New-ScheduledTaskAction -Execute $Program -Argument ($addr.IPAddressToString+' '+$Sid.Value) -WorkingDirectory $root
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 20) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName ($tag+'.'+$Label) -Action $action -Settings $settings -Principal $principal | Out-Null
    return $tag+'.'+$Label
}
function Invoke-ProbeTask([string]$Name) {
    $previous=(Get-ScheduledTaskInfo -TaskName $Name).LastRunTime
    if ([math]::Abs(([datetime]::Now-$previous).TotalSeconds) -lt 1.2) {Start-Sleep -Milliseconds 1300}
    Start-ScheduledTask -TaskName $Name
    $until=[datetime]::UtcNow.AddSeconds(25)
    do {
        Start-Sleep -Milliseconds 180
        $info=Get-ScheduledTaskInfo -TaskName $Name
        $state=(Get-ScheduledTask -TaskName $Name).State
        if($info.LastRunTime -gt $previous -and $state -eq 'Ready') {return [int]$info.LastTaskResult}
    } while ([datetime]::UtcNow -lt $until)
    throw 'Synthetic probe did not complete.'
}
function Check-Phase([string]$Label,[int[]]$Expected) {
    $actual = @(foreach ($name in $owned) {Invoke-ProbeTask $name})
    Write-Output ("{0}: selected user/image, other image, other user = {1}" -f $Label,($actual -join ','))
    if (($actual -join ',') -ne ($Expected -join ',')) {throw "Unexpected TCP result for $Label."}
}
try {
    & (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe') /nologo /optimize+ /target:exe ("/out:"+$probe) $source
    if($LASTEXITCODE) {throw 'Could not compile synthetic probe.'}
    [IO.File]::Copy($probe,$control)
    $owned += New-ProbeTask 'selected' $probe $user.User 'Interactive'
    $owned += New-ProbeTask 'other-image' $control $user.User 'Interactive'
    $owned += New-ProbeTask 'other-user' $probe $service 'ServiceAccount'
    if (Invoke-Backend 'IsApplied') {throw 'Unexpected existing rule.'}
    Check-Phase 'Baseline' @(0,0,0)
    $tried=$true
    Invoke-Backend 'Apply'
    if (!(Invoke-Backend 'IsApplied')) {throw 'The product did not confirm its rule.'}
    $listed = @(Invoke-Backend 'RecordedAccounts')
    if ($listed.Count -ne 1 -or $listed[0].Value -ne $user.User.Value) {throw 'Stored rule could not be resolved to the exact account.'}
    Check-Phase 'Blocked' @(41,0,0)
    Invoke-Backend 'Revoke'
    if ((Invoke-Backend 'IsApplied') -or @(Invoke-Backend 'RecordedAccounts').Count) {throw 'The rule still exists.'}
    $tried=$false
    Check-Phase 'Restored' @(0,0,0)
    Write-Output 'PASS: one fresh external TCP connection was denied only for the selected user and executable.'
} finally {
    try {if($tried) {Invoke-Backend 'Revoke'}}
    finally {
        foreach ($name in $owned) {Unregister-ScheduledTask -TaskName $name -Confirm:$false}
        foreach ($path in $probe,$control) {if([IO.File]::Exists($path)) {[IO.File]::Delete($path)}}
        [IO.Directory]::Delete($root)
    }
}
