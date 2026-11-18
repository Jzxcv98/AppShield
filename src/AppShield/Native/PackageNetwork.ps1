# SPDX-License-Identifier: GPL-3.0-only
# Embedded in AppShield. All substitutions are a derived SID, a GUID or internal enum literals.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
$sid = '__SID__'
$scope = '__SCOPE__'
$apply = __APPLY__
$prefix = 'AppShield.Native.__ID__.'
$group = 'AppShield.Native'
$description = 'AppShield package __ID__'

function CanonicalAddress([string]$text) {
    if ($text -match '^[a-z][a-z0-9]*$') { return $text.ToLowerInvariant() }
    $bounds = $text.Split('-')
    if ($bounds.Count -eq 2) {
        return [IPAddress]::Parse($bounds[0]).ToString() + '-' + [IPAddress]::Parse($bounds[1]).ToString()
    }
    $parts = $text.Split('/')
    $ip = [IPAddress]::Parse($parts[0])
    if ($parts.Count -eq 1) { return $ip.ToString() + '-' + $ip.ToString() }
    $first = $ip.GetAddressBytes()
    $last = $ip.GetAddressBytes()
    if ($parts[1] -match '^\d+$') {
        $bits = [int]$parts[1]
        if ($bits -gt 8 * $first.Length) { throw 'Invalid prefix length' }
        $mask = foreach ($i in 0..($first.Length-1)) {
            $width = [Math]::Min(8, [Math]::Max(0, $bits - 8 * $i))
            (255 -shl (8 - $width)) -band 255
        }
    } else { $mask = [IPAddress]::Parse($parts[1]).GetAddressBytes() }
    if ($mask.Count -ne $first.Length) { throw 'Invalid address mask' }
    for ($i = 0; $i -lt $first.Length; $i++) {
        $first[$i] = $first[$i] -band $mask[$i]
        $last[$i] = $first[$i] -bor (255 -bxor $mask[$i])
    }
    return [IPAddress]::new($first).ToString() + '-' + [IPAddress]::new($last).ToString()
}

function SameSet($a, $b) {
    $left = @($a | ForEach-Object { CanonicalAddress $_ } | Sort-Object -Unique)
    $right = @($b | ForEach-Object { CanonicalAddress $_ } | Sort-Object -Unique)
    return (($left -join '|') -ceq ($right -join '|'))
}

function Rules([string]$store) {
    # One enumerated prefix also finds stale guards from an interrupted write.
    $all = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop | Where-Object Name -Like ($prefix + '*'))
    foreach ($r in $all) {
        $kind = $r.Name.Substring($prefix.Length)
        $a = $r | Get-NetFirewallApplicationFilter
        if ($r.Group -cne $group -or $r.Description -cne $description -or $a.Package -ine $sid -or
            $kind -notin @('Inbound','Outbound','Hold.Inbound','Hold.Outbound')) { exit 22 }
    }
    return $all
}

function Correct($rule, [string]$direction, $remote, [switch]$Staging) {
    if (-not $rule -or [string]$rule.Enabled -ne 'True' -or [string]$rule.Profile -ne 'Any' -or
        [string]$rule.Action -ne 'Block' -or [string]$rule.Direction -ne $direction -or
        @($rule.Platform | Where-Object { $_ }).Count -ne 0 -or
        @($rule.RemoteDynamicKeywordAddresses | Where-Object { $_ }).Count -ne 0) { return $false }
    # Windows can optimize out a duplicate while a temporary all-traffic block covers it.
    # In the staging phase inspect the definition. After both holds are gone, require OK.
    if (-not $Staging -and [string]$rule.PrimaryStatus -ne 'OK') { return $false }
    $app = $rule | Get-NetFirewallApplicationFilter
    $addresses = $rule | Get-NetFirewallAddressFilter
    $port = $rule | Get-NetFirewallPortFilter
    $interface = $rule | Get-NetFirewallInterfaceFilter
    $interfaceType = $rule | Get-NetFirewallInterfaceTypeFilter
    $service = $rule | Get-NetFirewallServiceFilter
    $security = $rule | Get-NetFirewallSecurityFilter
    return ($app.Program -eq 'Any' -and $app.Package -eq $sid -and [string]$port.Protocol -eq 'Any' -and
        [string]$port.LocalPort -eq 'Any' -and [string]$port.RemotePort -eq 'Any' -and [string]$port.IcmpType -eq 'Any' -and
        [string]$addresses.LocalAddress -eq 'Any' -and [string]$interface.InterfaceAlias -eq 'Any' -and
        [string]$interfaceType.InterfaceType -eq 'Any' -and [string]$service.Service -eq 'Any' -and
        [string]$security.Authentication -eq 'NotRequired' -and [string]$security.Encryption -eq 'NotRequired' -and
        [string]$security.LocalUser -eq 'Any' -and [string]$security.RemoteUser -eq 'Any' -and
        [string]$security.RemoteMachine -eq 'Any' -and (SameSet $addresses.RemoteAddress $remote))
}

function SelectRule($rules, [string]$name) {
    $matches = @($rules | Where-Object Name -EQ ($prefix + $name))
    if ($matches.Count -gt 1) { exit 22 }
    if ($matches.Count -eq 1) { return $matches[0] }
}

function SetRule($rules, [string]$name, [string]$direction, $remote) {
    $prior = SelectRule $rules $name
    if (Correct $prior $direction $remote) { return }
    if ($prior) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $prior.Name }
    $null = New-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + $name) -DisplayName ($prefix + $name) -Group $group -Description $description -Package $sid -Profile Any -Direction $direction -Action Block -Enabled True -RemoteAddress $remote
}

try {
    Import-Module NetSecurity -ErrorAction Stop
    if ($scope -eq 'remove') {
        $rules = @(Rules 'PersistentStore')
        if ($rules.Count -gt 0 -and -not $apply) { exit 21 }
        foreach ($r in $rules) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name }
        if (@(Rules 'ActiveStore').Count -gt 0) { exit 21 }
        exit 0
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3 -or (Get-Service MpsSvc).Status -ne 'Running' -or (Get-Service BFE).Status -ne 'Running') { exit 20 }
    foreach ($profile in $profiles) {
        if ([string]$profile.Enabled -ne 'True' -or [string]$profile.AllowLocalFirewallRules -eq 'False' -or
            @($profile.DisabledInterfaceAliases | Where-Object { $_ -and $_ -ne 'NotConfigured' }).Count -ne 0) { exit 20 }
    }
    $directions = @('Inbound', 'Outbound')
    if ($scope -eq 'offline') { $remote = @('Any') }
    else {
        # The Windows firewall rejects ::1 as a remote-address literal. IPv6 and IPv4
        # loopback additionally require the verified AppContainer token and no exemption.
        $remote = @('127.0.0.0/8')
        if ($scope -eq 'public') {
            # LocalSubnet is maintained by Windows as adapters and routes change.
            $remote += @('LocalSubnet','0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','169.254.0.0/16','172.16.0.0/12',
                '192.168.0.0/16','224.0.0.0/4','255.255.255.255','fc00::/7','fe80::/10','ff00::/8')
        }
    }
    if ($apply) {
        $local = @(Rules 'PersistentStore')
        foreach ($d in $directions) { SetRule $local ('Hold.' + $d) $d @('Any') }
        $active = @(Rules 'ActiveStore')
        foreach ($d in $directions) { if (-not (Correct (SelectRule $active ('Hold.' + $d)) $d @('Any') -Staging)) { exit 21 } }
        foreach ($d in $directions) { SetRule $local $d $d $remote }
        $active = @(Rules 'ActiveStore')
        foreach ($d in $directions) { if (-not (Correct (SelectRule $active $d) $d $remote -Staging)) { exit 21 } }
        foreach ($d in $directions) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + 'Hold.' + $d) }
    }
    $active = @(Rules 'ActiveStore')
    if ($active.Count -ne 2) { exit 21 }
    foreach ($d in $directions) { if (-not (Correct (SelectRule $active $d) $d $remote)) { exit 21 } }
    exit 0
} catch { exit 23 }
