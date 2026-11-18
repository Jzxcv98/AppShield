# SPDX-License-Identifier: GPL-3.0-only
# Runs only in the temporary Windows Sandbox prepared by the clipboard test.
[CmdletBinding()]
param([Parameter(Mandatory)][guid]$RunId,[Parameter(Mandatory)][string]$ExpectedSha256)
$ErrorActionPreference='Stop'
if ([Environment]::UserName -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\AppShieldInput') {
    throw 'Fresh Windows Sandbox required.'
}
$receipt=Join-Path $env:LOCALAPPDATA 'AppShieldWeChatTest\result.json'
$trial=Join-Path $env:LOCALAPPDATA 'AppShieldClipboardResult.json'
$status='BASELINE'
$code=1
try {
    & "$PSHOME\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\Guest-Prelogin.ps1" -RunId $RunId -ExpectedSha256 $ExpectedSha256 -Networking Default
    $r=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $r.RunId -ne $RunId.ToString() -or $r.Status -ne 'PASS_SCAN_PROMPT' -or
        $r.SharedInput.WriteResult -ne 'DENIED') {throw 'Baseline or read-only mapping failed.'}
    $status='STOP_BASELINE'
    $installDir=(Resolve-Path (Join-Path $env:ProgramFiles 'Tencent\Weixin')).Path
    foreach ($name in 'Weixin','WeixinExt','crashpad_handler') {
        foreach ($p in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            try {
                if (!$p.HasExited -and $p.MainModule.FileName.StartsWith($installDir+'\',[StringComparison]::OrdinalIgnoreCase)) {
                    $p.Kill(); if (!$p.WaitForExit(8000)) {throw 'Baseline process did not stop.'}
                }
            } catch [InvalidOperationException] {if (!$p.HasExited){throw}}
            finally {$p.Dispose()}
        }
    }
    $status='PREPARE_STANDARD_USER'
    $name='ASClipboardTrial'
    if(Get-LocalUser -Name $name -ErrorAction SilentlyContinue){throw 'Expected a fresh guest test identity.'}
    $secret=ConvertTo-SecureString ('Az7!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $user=New-LocalUser -Name $name -Password $secret -Description 'Disposable Windows Sandbox clipboard test'
    $users=Get-LocalGroup -SID 'S-1-5-32-545'
    if(!(Get-LocalGroupMember -Group $users | Where-Object SID -eq $user.SID)){Add-LocalGroupMember -Group $users -Member $user}
    $dir=Join-Path $env:ProgramFiles 'AppShieldClipboardTrial'
    [void][IO.Directory]::CreateDirectory($dir)
    foreach ($file in 'DesktopChecks.exe','AppShield.exe') {Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $dir}
    $status='START_STANDARD_USER'
    # Retain the native process handle. Windows PowerShell Start-Process -Credential -PassThru
    # can yield a completed process with an empty ExitCode even when it ran successfully.
    $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $dir 'DesktopChecks.exe'),'--wechat-clipboard-test guest-client')
    $start.UseShellExecute=$false
    $start.WorkingDirectory=$dir
    $start.CreateNoWindow=$true
    $start.UserName=$name
    $start.Domain=[Environment]::MachineName
    $start.Password=$secret
    $start.LoadUserProfile=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $child=[Diagnostics.Process]::Start($start)
    try {
        $stdout=$child.StandardOutput.ReadToEndAsync()
        $stderr=$child.StandardError.ReadToEndAsync()
        if(!$child.WaitForExit(80000)){throw 'Guest clipboard launch timed out.'}
        $status='GUEST_CHECK_'+$child.ExitCode
        if($child.ExitCode -eq 0){$status='PASS_ROOT_WINDOW_AND_JOB_CHILD';$code=0}
        elseif($child.ExitCode -eq 20){$status='PASS_ROOT_WINDOW';$code=0}
        [IO.File]::WriteAllText((Join-Path $env:LOCALAPPDATA 'AppShieldClipboardDiagnostic.txt'),$stdout.Result+$stderr.Result)
    } finally {$child.Dispose();$secret.Dispose()}
} catch {Write-Host ('Guest clipboard stage '+$status+': '+$_.Exception.Message)}
finally {
    [IO.File]::WriteAllText($trial,([ordered]@{RunId=$RunId.ToString();Status=$status;ExitCode=$code} | ConvertTo-Json))
}
exit $code
