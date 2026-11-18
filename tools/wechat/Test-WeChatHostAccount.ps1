# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([guid]$Recover, [guid]$Execute, [switch]$SelfTest)
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell 5.1.' }
$windowsPS=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$lifetime=Join-Path $PSScriptRoot 'HostAccount-Lifetime.ps1'
$user=[Security.Principal.WindowsIdentity]::GetCurrent()
$admin=[Security.Principal.WindowsPrincipal]::new($user).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function Remove-TrialDirectory([guid]$Id) {
    $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    $leaf='AppShield.WeChatHost.'+$Id.ToString('N')
    $path=[IO.Path]::GetFullPath((Join-Path $parent $leaf))
    if (!(Test-Path -LiteralPath $path)) {return}
    if ([IO.Path]::GetDirectoryName($path) -ine $parent -or [IO.Path]::GetFileName($path) -cne $leaf) {throw 'Unexpected cleanup path.'}
    $dirs=[Collections.Generic.Stack[IO.DirectoryInfo]]::new()
    $dirs.Push([IO.DirectoryInfo]::new($path))
    while ($dirs.Count) {
        $dir=$dirs.Pop()
        if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Unexpected reparse point in trial.'}
        foreach ($entry in $dir.EnumerateFileSystemInfos()) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Unexpected reparse point in trial.'}
            if ($entry -is [IO.DirectoryInfo]) {$dirs.Push($entry)}
        }
    }
    [IO.Directory]::Delete($path,$true)
}
if ($Recover) {
    $p=Start-Process $windowsPS -ArgumentList ('-NoProfile -File "'+$lifetime+'" -Recover -Run '+$Recover) -WorkingDirectory $env:SystemRoot -Verb RunAs -WindowStyle Hidden -PassThru -Wait
    if ($p.ExitCode) {throw "Owned trial cleanup failed (stage/exit $($p.ExitCode))."}
    Remove-TrialDirectory $Recover
    return
}
if ($admin) {throw 'Start this check from a non-elevated interactive Windows session.'}
if ($SelfTest) {
    foreach ($file in @($lifetime,(Join-Path $PSScriptRoot 'HostAccount-Probe.ps1'))) {
        $tokens=$null;$errors=$null
        $null=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
        if ($errors) {throw $errors[0]}
    }
    Write-Output 'PASS host account acceptance script syntax'
    return
}
if (!$Execute) {
    $id=[guid]::NewGuid()
    if (Test-Path -LiteralPath (Join-Path ([IO.Path]::GetTempPath()) ('AppShield.WeChatHost.'+$id.ToString('N')))) {throw 'Trial directory exists.'}
    try {& $windowsPS -NoProfile -NonInteractive -File $PSCommandPath -Execute $id; $code=$LASTEXITCODE}
    finally {
        $account='ASW'+$id.ToString('N').Substring(0,12)
        if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) {throw "A test account remains. Recover with -Recover $id"}
        Remove-TrialDirectory $id
    }
    exit $code
}
$repo=Split-Path (Split-Path $PSScriptRoot)
$build=Join-Path $repo 'build\AppShield\AppShield.exe'
$run=$Execute
$name='ASW'+$run.ToString('N').Substring(0,12)
$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$root=Join-Path $temp ('AppShield.WeChatHost.'+$run.ToString('N'))
$safeRoot=[Security.AccessControl.DirectorySecurity]::new()
$safeRoot.SetAccessRuleProtection($true,$false)
foreach ($s in $user.User,([Security.Principal.SecurityIdentifier]'S-1-5-18'),([Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
    $safeRoot.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
if (Test-Path -LiteralPath $root) {throw 'Trial directory collision.'}
[void][IO.Directory]::CreateDirectory($root,$safeRoot)
Write-Output ('Trial ID '+$run.ToString('D')+'; local account '+$name)
$server=$helper=$password=$probe=$app=$profile=$trialSid=$null
$guarded=$false

function Grant-Trial([string]$Dir,[string]$Rights,[string]$Inheritance) {
    $acl=[IO.Directory]::GetAccessControl($Dir,[Security.AccessControl.AccessControlSections]::Access)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($trialSid,$Rights,$Inheritance,'None','Allow'))
    [IO.Directory]::SetAccessControl($Dir,$acl)
}
function Wait-Probe([string]$Stage,[int]$Seconds=20) {
    $gate=Join-Path $root ('shared\'+$Stage)
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do {
        if ([IO.File]::Exists($gate) -and [IO.File]::ReadAllText($gate) -eq [string]$probe.Id) {return}
        if ($probe.HasExited) {
            $details=Join-Path $root 'shared\probe-error'
            if ([IO.File]::Exists($details)) {
                # The child may use this file to report its stage. Do not print child-controlled content.
                $info=[IO.File]::ReadAllText($details)
                if ($info -match '^([\w.]+) HRESULT=(-?\d+) line=(\d+) ') {Write-Warning ("Probe error type "+$Matches[1]+", HRESULT "+$Matches[2]+", line "+$Matches[3])}
            }
            throw "Probe exited during $Stage (exit $($probe.ExitCode))."
        }
        Start-Sleep -Milliseconds 150
    } while ($watch.Elapsed.TotalSeconds -lt $Seconds)
    throw "Timed out at $Stage."
}
function Signal-Probe([string]$Stage,[string]$Value='ready') {
    $dest=Join-Path $root ('control\'+$Stage)
    [IO.File]::WriteAllText($dest+'.new',$Value)
    [IO.File]::Move($dest+'.new',$dest)
}
function Save-FileDescriptor([string]$Name,[string]$File) {
    $which=[Security.AccessControl.AccessControlSections]'Access,Owner,Group'
    $sd=[IO.File]::GetAccessControl($File,$which).GetSecurityDescriptorBinaryForm()
    [IO.File]::WriteAllBytes((Join-Path $root ('control\'+$Name+'.sd')),$sd)
}

try {
    foreach($sub in 'control','private','live','shared','store','bin'){[void][IO.Directory]::CreateDirectory((Join-Path $root $sub))}
    foreach($sub in 'private','live','shared'){[IO.File]::WriteAllText((Join-Path $root ($sub+'\marker')),$sub)}
    $worker=Join-Path $root 'control\probe.ps1'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'HostAccount-Probe.ps1') -Destination $worker
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'HostAccount-AccessCheck.cs') -Destination (Join-Path $root 'control\HostAccount-AccessCheck.cs')
    $copy=Join-Path $root 'bin\AppShield.exe'
    Copy-Item -LiteralPath $build -Destination $copy
    [void][Reflection.Assembly]::LoadFrom($copy)
    $app=[AppShield.AppService]::new((Join-Path $root 'store'))
    $profile=$app.ImportWeChat()
    if (!$profile.IsWeChat -or !$app.PSObject.Methods['LaunchWeChatAsAccount'] -or !$app.PSObject.Methods['ProtectWeChatFolder']) {throw 'Build the host-account launcher and folder guard first.'}
    if (Get-Process -Name Weixin,WeChat -ErrorAction SilentlyContinue) {throw 'An existing host WeChat instance is present; trial skipped.'}
    $security=[IO.Pipes.PipeSecurity]::new()
    $security.SetAccessRuleProtection($true,$false)
    $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new($user.User,'FullControl','Allow'))
    $server=[IO.Pipes.NamedPipeServerStream]::new(('AppShield.WeChatHost.'+$run.ToString('N')),'InOut',1,'Byte','Asynchronous',4096,4096,$security)
    $argsList='-NoProfile -NonInteractive -File "'+$lifetime+'" -Run '+$run+' -ControllerPid '+$PID
    $helper=Start-Process $windowsPS -ArgumentList $argsList -WorkingDirectory $env:SystemRoot -Verb RunAs -WindowStyle Hidden -PassThru
    $wait=$server.WaitForConnectionAsync()
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while (!$wait.IsCompleted -and !$helper.HasExited -and $watch.Elapsed.TotalSeconds -lt 25) {Start-Sleep -Milliseconds 100}
    if (!$wait.IsCompleted -or !$server.IsConnected) {throw 'Elevated account helper did not connect.'}
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class ASWTrialPipe {
    [DllImport("kernel32.dll",SetLastError=true)]
    public static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint id);
}
'@
    [uint32]$remote=0
    if (![ASWTrialPipe]::GetNamedPipeClientProcessId($server.SafePipeHandle,[ref]$remote) -or $remote -ne $helper.Id) {throw 'Unexpected helper process.'}
    $reader=[IO.BinaryReader]::new($server,[Text.Encoding]::UTF8,$true)
    $announcement=$reader.ReadString()
    if ($announcement.StartsWith('ERROR ')) {Write-Warning $announcement;throw 'Temporary account provisioning failed.'}
    $trialSid=[Security.Principal.SecurityIdentifier]::new($announcement)
    $seed=$reader.ReadBytes(32)
    if($seed.Length -ne 32){throw 'Incomplete credentials.'}
    try {$password=ConvertTo-SecureString ('Az9!'+[Convert]::ToBase64String($seed)) -AsPlainText -Force}
    finally {[Array]::Clear($seed,0,$seed.Length)}
    if ($trialSid.Translate([Security.Principal.NTAccount]).Value -ine ([Environment]::MachineName+'\'+$name)) {throw 'Unexpected trial identity.'}
    Grant-Trial $root 'ReadAndExecute' 'None'
    Grant-Trial (Join-Path $root 'control') 'ReadAndExecute' 'ContainerInherit,ObjectInherit'
    # A conventional group-readable baseline lets the guard own just its new,
    # account-specific deny ACE. The temporary directory contains synthetic data only.
    $liveAcl=[IO.Directory]::GetAccessControl((Join-Path $root 'live'),[Security.AccessControl.AccessControlSections]::Access)
    $liveAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(([Security.Principal.SecurityIdentifier]'S-1-5-32-545'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    [IO.Directory]::SetAccessControl((Join-Path $root 'live'),$liveAcl)
    Grant-Trial (Join-Path $root 'shared') 'Modify' 'ContainerInherit,ObjectInherit'
    $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    $start=[Diagnostics.ProcessStartInfo]::new($windowsPS)
    $start.UserName=$name;$start.Domain=[Environment]::MachineName;$start.Password=$password;$start.LoadUserProfile=$true
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WorkingDirectory=$env:SystemRoot
    $start.Arguments='-NoProfile -NonInteractive -MTA -ExecutionPolicy Bypass -File "'+$worker+'" -TrialSid '+$trialSid.Value+' -Session '+$session+' -Root "'+$root+'" -Client "'+$profile.ExecutablePath+'"'
    $probe=[Diagnostics.Process]::Start($start)
    Wait-Probe 'baseline'
    Write-Output 'PASS ordinary-account probe denied private marker, read shared markers and created a receipt'
    $clientPid=$app.LaunchWeChatAsAccount($profile,$name,$password)
    Write-Output ('Launched verified WeChat '+$profile.ProductVersion+'; PID '+$clientPid)
    $live=Join-Path $root 'live'
    Save-FileDescriptor 'baseline' (Join-Path $live 'marker')
    Save-FileDescriptor 'private' (Join-Path $root 'private\marker')
    Signal-Probe 'client' ([string]$clientPid)
    Wait-Probe 'tokenready'
    Write-Output 'PASS Windows Authz checked the actual WeChat token: protected baseline private file denied, selected readable file allowed'
    $before=(Get-Acl -LiteralPath $live).Sddl
    $app.ProtectWeChatFolder($profile,$live,$name,$password)
    $guarded=$true
    Save-FileDescriptor 'denied' (Join-Path $live 'marker')
    Signal-Probe 'deny'
    Wait-Probe 'denied'
    if ([IO.File]::ReadAllText((Join-Path $live 'marker')) -ne 'live') {throw 'Host lost access to the original.'}
    $app.UnprotectWeChatFolder($profile,$live)
    $guarded=$false
    Save-FileDescriptor 'restored' (Join-Path $live 'marker')
    Signal-Probe 'revoke'
    Wait-Probe 'revoked'
    if ((Get-Acl -LiteralPath $live).Sddl -cne $before -or $app.WeChatFolderProtections($profile).Length -ne 0) {throw 'Folder ACL or journal not restored.'}
    Write-Output 'PASS same running probe denied after protection and read again after revocation; matching real WeChat token Authz verdicts; host contents and ACL restored'
    Signal-Probe 'observe' ([string]$clientPid)
    Wait-Probe 'scan' 65
    if (!$probe.WaitForExit(5000) -or $probe.ExitCode -ne 0) {throw 'Window observation did not finish.'}
    Write-Output ('PASS signed WeChat '+$profile.ProductVersion+' showed a fixed scan prompt for 3 seconds under the trial SID on the host session')
} catch {
    Write-Warning ("Trial error: "+$_.Exception.GetBaseException().Message+' (line '+$_.InvocationInfo.ScriptLineNumber+')')
    Write-Warning ([string]$_.Exception.GetBaseException().StackTrace)
    throw
} finally {
    try {
        if ($guarded) {$app.UnprotectWeChatFolder($profile,(Join-Path $root 'live'))}
    } finally {
        if ($password){$password.Dispose()}
        if ($server) {
            try {if($server.IsConnected){$server.WriteByte(1);$server.Flush()}} catch [IO.IOException] {}
            finally {$server.Dispose()}
        }
        if ($helper) {
            if (!$helper.WaitForExit(80000) -or $helper.ExitCode -ne 0) {throw "Elevated account helper ended at stage/exit $($helper.ExitCode). Verify and recover with -Recover $run"}
        }
        if ($probe){$probe.Dispose()}
        if ($trialSid -and (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {throw 'Trial account remains.'}
        Write-Output 'Account/profile cleanup completed or no account was created.'
    }
}
