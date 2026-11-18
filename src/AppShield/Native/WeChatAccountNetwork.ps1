# SPDX-License-Identifier: GPL-3.0-only
# Trusted embedded source; only a base64-encoded path, validated SID, GUID and internal operation enter the script.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PSModulePath = [IO.Path]::Combine($PSHOME,'Modules')
$sid = '__SID__'
$prefix = 'AppShield.WeChat.Out.__ID__.'
$name = $prefix + $sid
$image = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__IMAGE64__'))
$operation = '__OP__'
$group = 'AppShield.WeChat.Account'
$descriptionPrefix = 'AppShield outbound __ID__ ' + $sid + ' '

function Get-Rule([string]$Store,[string]$Pattern) {
    try {return Get-NetFirewallRule -Name $Pattern -PolicyStore $Store -ErrorAction Stop}
    catch {
        if ($_.FullyQualifiedErrorId -in 'CmdletizationQuery_NotFound_Name,Get-NetFirewallRule','CmdletizationQuery_NotFound_InstanceID,Get-NetFirewallRule') { return }
        throw
    }
}

function Get-ExactRule([string]$Store) {
    $rules = @(Get-Rule $Store $name)
    if ($rules.Count -gt 1) { exit 22 }
    if (!$rules.Count) { return }
    $r = $rules[0]
    $a = $r | Get-NetFirewallApplicationFilter
    $s = $r | Get-NetFirewallSecurityFilter
    if ($r.Name -cne $name -or $r.Group -cne $group -or $r.Description -cnotmatch ('^'+[regex]::Escape($descriptionPrefix)+'[0-9a-f]{32}$') -or
        [string]$r.PolicyStoreSourceType -ne 'Local' -or [string]$r.Direction -ne 'Outbound' -or
        [string]$r.Action -ne 'Block' -or [Environment]::ExpandEnvironmentVariables($a.Program) -ine $image -or
        [string]$a.Package -notin @('','Any') -or !$s.LocalUser -or [string]$s.LocalUser -eq 'Any') { exit 22 }
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($s.LocalUser)
    $dacl = $descriptor.DiscretionaryAcl
    if ($null -eq $dacl -or $dacl.Count -ne 1 -or $dacl[0].AceType -ne 'AccessAllowed' -or
        $dacl[0].AceFlags -ne 'None' -or $dacl[0].AccessMask -ne 1 -or $dacl[0].SecurityIdentifier.Value -ne $sid) {exit 22}
    return $r
}

function Check-Effective($r) {
    if (!$r) {exit 24}
    $addr = $r | Get-NetFirewallAddressFilter
    $port = $r | Get-NetFirewallPortFilter
    $sec = $r | Get-NetFirewallSecurityFilter
    $interface = $r | Get-NetFirewallInterfaceFilter
    $type = $r | Get-NetFirewallInterfaceTypeFilter
    $service = $r | Get-NetFirewallServiceFilter
    if ([string]$r.Enabled -ne 'True' -or [string]$r.Profile -ne 'Any' -or [string]$r.PrimaryStatus -ne 'OK' -or
        @($r.Platform | Where-Object {$_}).Count -ne 0 -or @($r.RemoteDynamicKeywordAddresses | Where-Object {$_}).Count -ne 0 -or
        [string]$addr.RemoteAddress -ne 'Any' -or [string]$addr.LocalAddress -ne 'Any' -or
        [string]$port.Protocol -ne 'Any' -or [string]$port.LocalPort -ne 'Any' -or [string]$port.RemotePort -ne 'Any' -or
        [string]$port.IcmpType -ne 'Any' -or [string]$service.Service -ne 'Any' -or
        [string]$sec.RemoteUser -ne 'Any' -or [string]$sec.RemoteMachine -ne 'Any' -or
        [string]$sec.Authentication -ne 'NotRequired' -or [string]$sec.Encryption -ne 'NotRequired' -or
        [string]$interface.InterfaceAlias -ne 'Any' -or [string]$type.InterfaceType -ne 'Any') {exit 24}
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3 -or (Get-Service MpsSvc).Status -ne 'Running' -or (Get-Service BFE).Status -ne 'Running') {exit 20}
    foreach ($p in $profiles) {
        if ([string]$p.Enabled -ne 'True' -or [string]$p.AllowLocalFirewallRules -eq 'False' -or
            @($p.DisabledInterfaceAliases | Where-Object {$_ -and $_ -ne 'NotConfigured'}).Count -ne 0) {exit 20}
    }
}

$mutex = $null
$held = $false
$createdDescription = $null
try {
    Import-Module NetSecurity -ErrorAction Stop
    if ($operation -eq 'list') {
        $names = @(@(Get-Rule 'PersistentStore' ($prefix+'*')) + @(Get-Rule 'ActiveStore' ($prefix+'*')) |
            ForEach-Object Name | Sort-Object -Unique)
        foreach ($name in $names) {
            $sid=$name.Substring($prefix.Length)
            if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {exit 22}
            $descriptionPrefix='AppShield outbound __ID__ '+$sid+' '
            if (!(Get-ExactRule 'PersistentStore')) {exit 22}
            Write-Output $sid
        }
        exit 0
    }
    if ($operation -in 'apply','remove') {
        $mutex = [Threading.Mutex]::new($false,('Global\'+$name))
        try {$held = $mutex.WaitOne(20000)} catch [Threading.AbandonedMutexException] {$held=$true}
        if (!$held) {exit 23}
    }
    $local = Get-ExactRule 'PersistentStore'
    $active = Get-ExactRule 'ActiveStore'
    if ($active -and !$local) {exit 22}
    if ($operation -eq 'remove') {
        if ($local) {Remove-NetFirewallRule -Name $name -PolicyStore PersistentStore}
        if ((Get-ExactRule 'PersistentStore') -or (Get-ExactRule 'ActiveStore')) {exit 24}
        exit 0
    }
    if ($operation -eq 'can-remove') {if ($local) {exit 0}; exit 21}
    if (!$local -and $operation -eq 'inspect') {exit 21}
    if (!$local -and $operation -eq 'apply') {
        $marker = $descriptionPrefix + [guid]::NewGuid().ToString('N')
        # Verify both conditions before enabling. Never activate a program-wide fallback.
        $null = New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group $group -Description $marker -Direction Outbound -Action Block -Enabled False -Profile Any -Program $image -LocalUser ('D:(A;;CC;;;'+$sid+')')
        $createdDescription = $marker
        if (!(Get-ExactRule 'PersistentStore')) {exit 24}
        Enable-NetFirewallRule -Name $name -PolicyStore PersistentStore
        $active = Get-ExactRule 'ActiveStore'
    }
    Check-Effective $active
    $createdDescription=$null
    exit 0
} catch {exit 23}
finally {
    if ($createdDescription) {
        # Per-creation nonce keeps rollback from claiming a concurrent replacement.
        try {
            $ours = @(Get-Rule 'PersistentStore' $name)
            if ($ours.Count -eq 1 -and $ours[0].Group -ceq $group -and $ours[0].Description -ceq $createdDescription) {
                Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name
                if (Get-Rule 'PersistentStore' $name) {exit 25}
            } elseif ($ours.Count -ne 0) {exit 22}
        } catch {exit 25}
    }
    if ($held) {$mutex.ReleaseMutex()}
    if ($mutex) {$mutex.Dispose()}
}
