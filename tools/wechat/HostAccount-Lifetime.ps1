# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([Parameter(Mandatory)][guid]$Run, [int]$ControllerPid, [switch]$Recover)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$phase=80
trap {exit $phase}
if (!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevation required.' }
$name='ASW'+$Run.ToString('N').Substring(0,12)
$description='ASW trial '+$Run.ToString('N')
$parent=[Environment]::ExpandEnvironmentVariables((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').ProfilesDirectory)
$expectedPath=[IO.Path]::GetFullPath((Join-Path $parent $name))
$sid=$null

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class ASWTrialOwner {
    [DllImport("advapi32.dll",SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint id);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
    static extern bool DeleteProfileW(string sid, string path, string computer);
    public static int DeleteLocalProfile(string sid,string path) {
        return DeleteProfileW(sid,path,null) ? 0 : Marshal.GetLastWin32Error();
    }
    public static bool Owns(Process process,string sid) {
        IntPtr token;
        if (!OpenProcessToken(process.Handle,8,out token)) throw new Win32Exception();
        try { using(var user=new WindowsIdentity(token)) return user.User.Value==sid; }
        finally { CloseHandle(token); }
    }
}
'@

function Remove-Trial {
    if (!$sid) { return }
    $script:phase=85
    $u=Get-LocalUser -SID $sid -ErrorAction SilentlyContinue
    if (!$u -or $u.Name -cne $name -or $u.Description -cne $description) {throw 'Trial account identity changed.'}
    Disable-LocalUser -SID $sid
    $lastDelete=0
    $until=[datetime]::UtcNow.AddSeconds(45)
    do {
        $left=@(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {$_.UserName -ieq ([Environment]::MachineName+'\'+$name)})
        foreach ($p in $left) {
            try {
                if (!$p.HasExited -and [ASWTrialOwner]::Owns($p,$sid.Value)) { $p.Kill(); [void]$p.WaitForExit(1500) }
            } catch [InvalidOperationException] { if (!$p.HasExited) {throw} }
            finally {$p.Dispose()}
        }
        $prof=Get-CimInstance Win32_UserProfile -Filter ("SID='"+$sid.Value+"'")
        if ($prof) {
            if ($prof.Special -or [IO.Path]::GetFullPath($prof.LocalPath) -ine $expectedPath) {throw 'Unexpected profile path; retained for inspection.'}
            if (!$prof.Loaded) {
                $lastDelete=[ASWTrialOwner]::DeleteLocalProfile($sid.Value,$expectedPath)
                if (!$lastDelete) {$prof=$null}
            }
        }
        if (!$prof -and !$left.Count) {break}
        Start-Sleep -Milliseconds 500
    } while ([datetime]::UtcNow -lt $until)
    if ((Get-CimInstance Win32_UserProfile -Filter ("SID='"+$sid.Value+"'")) -or [IO.Directory]::Exists($expectedPath)) {
        $script:phase=1000+$lastDelete
        throw 'Trial profile could not be removed. The trial account is disabled.'
    }
    Remove-LocalUser -SID $sid
    if (Get-LocalUser -SID $sid -ErrorAction SilentlyContinue) {throw 'Trial account still exists.'}
}

if ($Recover) {
    $u=Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if (!$u) {if ([IO.Directory]::Exists($expectedPath)) {throw 'A profile remains without a matching trial account.'};return}
    if ($u.Description -cne $description) {throw 'Account does not belong to this trial.'}
    $sid=$u.SID
    Remove-Trial
    return
}
$pipe=[IO.Pipes.NamedPipeClientStream]::new('.','AppShield.WeChatHost.'+$Run.ToString('N'),[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous,[Security.Principal.TokenImpersonationLevel]::Identification)
$password=$null
$seed=[byte[]]::new(32)
try {
    $phase=81
    $pipe.Connect(15000)
    [uint32]$server=0
    if (![ASWTrialOwner]::GetNamedPipeServerProcessId($pipe.SafePipeHandle,[ref]$server) -or $server -ne $ControllerPid) { throw 'Unexpected controller.' }
    $phase=82
    $read=[IO.BinaryReader]::new($pipe,[Text.Encoding]::UTF8,$true)
    $write=[IO.BinaryWriter]::new($pipe,[Text.Encoding]::UTF8,$true)
    if ((Get-LocalUser -Name $name -ErrorAction SilentlyContinue) -or [IO.Directory]::Exists($expectedPath)) {throw 'Trial name already exists.'}
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try {$rng.GetBytes($seed)} finally {$rng.Dispose()}
    $password=ConvertTo-SecureString ('Az9!'+[Convert]::ToBase64String($seed)) -AsPlainText -Force
    $u=New-LocalUser -Name $name -Password $password -Description $description -AccountExpires ([datetime]::Now.AddHours(2))
    $sid=$u.SID
    $phase=83
    $users=Get-LocalGroup -SID 'S-1-5-32-545'
    if (!(Get-LocalGroupMember -Group $users | Where-Object {$_.SID -eq $sid})) {Add-LocalGroupMember -Group $users -Member $u}
    if (Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object {$_.SID -eq $sid}) {throw 'Unexpected administrator membership.'}
    $write.Write($sid.Value)
    $write.Write($seed)
    $write.Flush()
    $phase=84
    [Array]::Clear($seed,0,$seed.Length)
    $password.Dispose();$password=$null
    # A broken pipe, expiration or an explicit completion all trigger rollback.
    $buf=[byte[]]::new(1)
    $pending=$pipe.ReadAsync($buf,0,1)
    if (!$pending.Wait(300000)) {throw 'Trial controller timed out.'}
} catch {
    if ($write -and $phase -in 82,83) {
        try {
            $write.Write(('ERROR {0} line {1} {2} {3}' -f $phase,$_.InvocationInfo.ScriptLineNumber,$_.Exception.GetType().Name,$_.FullyQualifiedErrorId))
            $write.Flush()
        } catch {}
    }
    throw
} finally {
    [Array]::Clear($seed,0,$seed.Length)
    if ($password){$password.Dispose()}
    try { Remove-Trial } finally {$pipe.Dispose()}
}
