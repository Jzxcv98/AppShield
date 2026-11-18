# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding(DefaultParameterSetName='Test')]
param(
    [Parameter(Mandatory, ParameterSetName='Test')][string]$Installer,
    [Parameter(ParameterSetName='Test')][ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedSha256 = 'A463110FED2DAD8F27A313A1E5118CFBBE8B9DE2B9296DB8015A496E07191052',
    [Parameter(ParameterSetName='Test')][switch]$AllowNetwork,
    [Parameter(ParameterSetName='Test')][switch]$ClipboardJob,
    [Parameter(ParameterSetName='Test')][switch]$PrepareOnly,
    [Parameter(ParameterSetName='Test')][string]$OutputDirectory,
    [Parameter(Mandatory, ParameterSetName='SelfTest')][switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$guestInput = 'C:\AppShieldInput'

function Invoke-BoundedCommand([string]$Executable, [string[]]$Arguments, [int]$TimeoutMs) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    # Windows PowerShell 5.1 lacks ProcessStartInfo.ArgumentList. Preserve each
    # argument, including XML and whitespace, under the Windows argv rules.
    $quoted = foreach ($argument in $Arguments) {
        '"' + (($argument -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
    }
    $info.Arguments = $quoted -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $out = $process.StandardOutput.ReadToEndAsync()
        $err = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit($TimeoutMs)) {
            try { $process.Kill() } catch [InvalidOperationException] {}
            throw [TimeoutException]::new("Timed out waiting for $($Arguments[0]) after $TimeoutMs ms.")
        }
        $remaining = [Math]::Max(1, $TimeoutMs - [int]$watch.ElapsedMilliseconds)
        if (!([Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($out,$err), $remaining))) {
            throw [TimeoutException]::new("Timed out reading the result for $($Arguments[0]).")
        }
        [pscustomobject]@{Code=$process.ExitCode; Output=$out.Result.Trim(); ErrorText=$err.Result.Trim()}
    } finally { $process.Dispose() }
}

function Read-GuestExit($Reply) {
    # Some clients relay the guest code as their exit status, others print it
    # after successful command transport. Never extract a trailing number
    # from an arbitrary diagnostic or override a failed transport.
    if ($Reply.Code -ne 0) {return $Reply.Code}
    $s = $Reply.Output
    if ($s -match '^\s*(\d{1,3})\s*$' -or $s -match '(?i)^Process exited with code:\s*(\d{1,3})\.?$') {
        return [int]$Matches[1]
    }
    if ($s.StartsWith('{')) {
        try {
            $json = $s | ConvertFrom-Json -ErrorAction Stop
            foreach ($key in 'ExitCode','ProcessExitCode') {
                if ($json.PSObject.Properties[$key] -and [string]$json.$key -match '^\d{1,3}$') {return [int]$json.$key}
            }
        } catch {}
    }
    return 0
}

function Read-StartedSandboxId([string]$Response) {
    $guid = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    $text = $Response.Trim()
    if ($text.StartsWith('{') -or $text.StartsWith('"')) {
        try {
            $value = ConvertFrom-Json -InputObject $text -ErrorAction Stop
            $text = if ($value -is [string]) {$value} else {[string]$value.Id}
        } catch {return}
    }
    if ($text -match "^($guid)$" -or $text -match "^Sandbox ID:\s*($guid)\.?$") {
        if ([guid]$Matches[1] -ne [guid]::Empty) {return $Matches[1]}
    }
}

function Find-SandboxCli {
    foreach ($path in @((Join-Path ([Environment]::SystemDirectory) 'wsb.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wsb.exe'))) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {return $path}
    }
    # A registered Microsoft Store client may have its execution alias disabled.
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            $packages = Get-AppxPackage -Name '*WindowsSandbox' -ErrorAction Stop |
                Where-Object { $_.Name -in 'WindowsSandbox','MicrosoftWindows.WindowsSandbox' }
            foreach ($package in $packages) {
                if ($package.PublisherId -notin 'cw5n1h2txyewy','8wekyb3d8bbwe' -or !$package.InstallLocation) {continue}
                $path = Join-Path $package.InstallLocation 'wsb.exe'
                if (Test-Path -LiteralPath $path -PathType Leaf) {return $path}
            }
        } catch { Write-Verbose "Store client lookup unavailable: $_" }
    }
}

# The same pure check is embedded in the guest query and exercised by SelfTest.
function Resolve-TrialReceipt {
    param($Receipt,[string]$ExpectedRun,[int]$PassCode)
    if ([string]$Receipt.RunId -cne $ExpectedRun) {return 194}
    if ($Receipt.ExitCode -eq 0 -and $Receipt.Status -ceq 'PASS_SCAN_PROMPT' -and
        $Receipt.SharedInput.ReadVerified -is [bool] -and $Receipt.SharedInput.ReadVerified -and
        $Receipt.SharedInput.WriteResult -ceq 'DENIED') {return $PassCode}
    switch ([string]$Receipt.Status) {
        'FRESH_SANDBOX_REQUIRED' { return 201 }
        'INSTALLER_HASH_MISMATCH' { return 202 }
        'INSTALL_FAILED' { return 203 }
        'INSTALL_TIMEOUT' { return 204 }
        'CLIENT_NOT_INSTALLED' { return 205 }
        'SIGNATURE_UNVERIFIED' { return 206 }
        'UNEXPECTED_CLIENT_IDENTITY' { return 207 }
        'LAUNCH_FAILED' { return 208 }
        'CLIENT_LAUNCH_ERROR' { return 209 }
        'NO_VERIFIED_PROCESS' { return 210 }
        'NO_VISIBLE_WINDOW' { return 211 }
        'SCAN_PROMPT_UNVERIFIED' { return 212 }
        'OBSERVER_TIMEOUT' { return 213 }
        'OBSERVER_FAILED' { return 214 }
        'SHARED_INPUT_WRITABLE' { return 215 }
        'SHARED_INPUT_WRITE_UNVERIFIED' { return 216 }
        'SHARED_INPUT_PROBE_CLEANUP_FAILED' { return 217 }
    }
    return 192
}

function New-TrialConfig([string]$Share, [guid]$Run, [string]$Hash, [bool]$Network) {
    [xml]$config = @'
<Configuration>
  <VGpu>Disable</VGpu><Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection><PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><ProtectedClient>Enable</ProtectedClient>
  <MappedFolders><MappedFolder><HostFolder/><SandboxFolder/><ReadOnly>true</ReadOnly></MappedFolder></MappedFolders>
  <LogonCommand><Command/></LogonCommand>
</Configuration>
'@
    $folder = $config.Configuration.MappedFolders.MappedFolder
    $folder.HostFolder = $Share
    $folder.SandboxFolder = $guestInput
    $mode = 'Off'
    if ($Network) { $config.Configuration.Networking = 'Enable'; $mode = 'Default' }
    $config.Configuration.LogonCommand.Command = "cmd.exe /d /k powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File $guestInput\Guest-Prelogin.ps1 -RunId $Run -ExpectedSha256 $Hash -Networking $mode"
    return $config
}

if ($SelfTest) {
    $id = [guid]::NewGuid()
    if ((Read-StartedSandboxId ('{"Id":"'+$id+'"}')) -ne $id.ToString() -or
        (Read-StartedSandboxId ('"'+$id+'"')) -ne $id.ToString() -or
        (Read-StartedSandboxId "Sandbox ID: $id") -ne $id.ToString() -or
        (Read-StartedSandboxId ('{"Error":"'+$id+'"}')) -or
        (Read-StartedSandboxId ([guid]::Empty.ToString()))) {throw 'Incorrect session ID parsing.'}
    $sample = @{RunId=$id.ToString(); ExitCode=0; Status='PASS_SCAN_PROMPT'; SharedInput=@{ReadVerified=$true;WriteResult='DENIED'}}
    if ((Resolve-TrialReceipt $sample $id 197) -ne 197 -or
        (Resolve-TrialReceipt $sample ([guid]::Empty) 191) -ne 194) {throw 'Incorrect receipt identity.'}
    $sample.SharedInput.ReadVerified = 'true'
    if ((Resolve-TrialReceipt $sample $id 191) -ne 192) {throw 'Invalid read proof accepted.'}
    $sample.SharedInput.ReadVerified = $true
    $sample.SharedInput.WriteResult = 'WRITABLE'
    if ((Resolve-TrialReceipt $sample $id 191) -ne 192) {throw 'Invalid write proof accepted.'}
    $sample.Status = 'SHARED_INPUT_PROBE_CLEANUP_FAILED'
    if ((Resolve-TrialReceipt $sample $id 191) -ne 217) {throw 'Shared-folder failure not relayed.'}
    # Exercise both result encodings and ensure an unrelated CLI error cannot pass.
    if ((Read-GuestExit ([pscustomobject]@{Code=0;Output='Process exited with code: 191'})) -ne 191 -or
        (Read-GuestExit ([pscustomobject]@{Code=0;Output='{"ExitCode":194}'})) -ne 194 -or
        (Read-GuestExit ([pscustomobject]@{Code=0;Output='Unexpected error 191'})) -ne 0 -or
        (Read-GuestExit ([pscustomobject]@{Code=1;Output='191'})) -ne 1) {throw 'Incorrect guest exit parsing.'}
    $testExe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $bounded = Invoke-BoundedCommand $testExe @('-NoProfile','-NonInteractive','-Command','exit 19') 10000
    if ($bounded.Code -ne 19) {throw 'Native exit status lost.'}
    try {
        $null = Invoke-BoundedCommand $testExe @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') 200
        throw 'Unbounded CLI call.'
    } catch [TimeoutException] {}
    foreach ($network in @($false,$true)) {
        $share = 'C:\sandbox config & data\input'
        $config = New-TrialConfig $share $id ('A' * 64) $network
        [xml]$read = $config.OuterXml
        $entry = $read.SelectNodes('/Configuration/MappedFolders/MappedFolder')
        if ($entry.Count -ne 1 -or $entry[0].HostFolder -cne $share -or
            $entry[0].SandboxFolder -cne $guestInput -or $entry[0].ReadOnly -cne 'true') { throw 'Invalid input mapping.' }
        foreach ($setting in @('AudioInput','VideoInput','VGpu','ClipboardRedirection','PrinterRedirection')) {
            if ($read.Configuration.$setting -cne 'Disable') { throw "Sharing enabled: $setting" }
        }
        $expectedNetwork = if ($network) { 'Enable' } else { 'Disable' }
        if ($read.Configuration.Networking -cne $expectedNetwork -or $read.Configuration.ProtectedClient -cne 'Enable' -or
            !$read.Configuration.LogonCommand.Command.Contains($id.ToString())) { throw 'Invalid launch configuration.' }
    }
    Write-Output 'PASS: sandbox configurations, read-only mapping, receipt parsing, bounded CLI status and timeout.'
    return
}

$source = Get-Item -LiteralPath $Installer
if ($ClipboardJob -and (!$AllowNetwork -or $PrepareOnly)) {throw 'Use -ClipboardJob with -AllowNetwork for a fresh guest compatibility test.'}
if ($source.PSIsContainer -or $source.Extension -ine '.exe') { throw 'Supply the official Windows installer executable.' }
$guestScript = Join-Path $PSScriptRoot 'Guest-Prelogin.ps1'
$id = [guid]::NewGuid()
$parent = [IO.Path]::GetTempPath()
if ($OutputDirectory) {
    if (!$PrepareOnly) { throw 'OutputDirectory is available with PrepareOnly.' }
    $parent = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    [void][IO.Directory]::CreateDirectory($parent)
}
$trialRoot = Join-Path $parent ('AppShield.WeChatSandbox.' + $id.ToString('N'))
$inputDir = Join-Path $trialRoot 'input'
$configPath = Join-Path $trialRoot 'WeChat.wsb'
if (Test-Path -LiteralPath $trialRoot) { throw 'Unexpected pre-existing trial directory.' }
$null = New-Item -Path $inputDir -ItemType Directory -Force
$payload = Join-Path $inputDir 'WeChatSetup.exe'
$keep = $false
$sandboxId = $null
$extraInputs = @()
try {
    Copy-Item -LiteralPath $source.FullName -Destination $payload
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Installer SHA-256 mismatch.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $payload
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
        $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -ine 'Tencent Technology (Shenzhen) Company Limited') {
        throw 'Installer does not have a trusted Tencent Authenticode signature.'
    }
    Copy-Item -LiteralPath $guestScript -Destination $inputDir
    if ($PrepareOnly) {
        $offline = New-TrialConfig $inputDir $id $ExpectedSha256 $false
        $online = New-TrialConfig $inputDir ([guid]::NewGuid()) $ExpectedSha256 $true
        $offline.Save($configPath)
        $onlinePath = Join-Path $trialRoot 'WeChat-NetworkEnabled.wsb'
        $online.Save($onlinePath)
        $keep = $true
        Write-Output "PREPARED offline: $configPath"
        Write-Output "PREPARED optional default network (LAN may be reachable): $onlinePath"
        return
    }
    $config = New-TrialConfig $inputDir $id $ExpectedSha256 $AllowNetwork.IsPresent
    if ($ClipboardJob) {
        $checks = Join-Path $PSScriptRoot '..\..\build\checks'
        foreach ($file in @((Join-Path $PSScriptRoot 'ClipboardGuest.ps1'),(Join-Path $checks 'DesktopChecks.exe'),(Join-Path $checks 'AppShield.exe'))) {
            $copy = Join-Path $inputDir ([IO.Path]::GetFileName($file))
            $extraInputs += $copy
            Copy-Item -LiteralPath $file -Destination $copy
        }
        $config.Configuration.LogonCommand.Command = "cmd.exe /d /k powershell.exe -NoProfile -ExecutionPolicy Bypass -File $guestInput\ClipboardGuest.ps1 -RunId $id -ExpectedSha256 $ExpectedSha256"
    }
    $config.Save($configPath)
    if ($AllowNetwork) { Write-Host 'Guest networking uses the Windows Sandbox default switch, which may reach the LAN.' }
    $cli = Find-SandboxCli
    if (!$cli) {
        $legacy = Join-Path ([Environment]::SystemDirectory) 'WindowsSandbox.exe'
        $association = [Microsoft.Win32.Registry]::GetValue('HKEY_CLASSES_ROOT\.wsb','','')
        $openCommand = if ($association) {
            [Microsoft.Win32.Registry]::GetValue("HKEY_CLASSES_ROOT\$association\shell\open\command",'','')
        }
        if (!(Test-Path -LiteralPath $legacy -PathType Leaf) -and !$openCommand) {
            throw 'Windows Sandbox has no registered launcher. Enable the feature and complete any required restart.'
        }
        if (Get-Process WindowsSandbox,WindowsSandboxClient -ErrorAction SilentlyContinue) {
            throw 'An existing Sandbox desktop was detected. Close it before starting a new trial.'
        }
        if (Test-Path -LiteralPath $legacy -PathType Leaf) {
            Start-Process -FilePath $legacy -ArgumentList ('"{0}"' -f $configPath)
        } else { Start-Process -FilePath $configPath }
        $keep = $true
        Write-Output "LAUNCHED (guest verdict pending): read the result inside Windows Sandbox. Configuration: $configPath"
        return
    }
    # Only an ID returned by this start operation is eligible for later inspection and stop.
    $inventory = Invoke-BoundedCommand $cli @('list','--raw') 15000
    if ($inventory.Code -ne 0) { throw "Could not inspect sandbox sessions: $($inventory.ErrorText) $($inventory.Output)" }
    $list = ConvertFrom-Json -InputObject $inventory.Output -ErrorAction Stop
    if ($list.WindowsSandboxEnvironments -isnot [array]) {throw 'Unknown Sandbox session inventory format.'}
    if ($list.WindowsSandboxEnvironments.Count) {throw 'An existing Sandbox session was found. Close it before starting a new trial.'}
    # On timeout we cannot prove ownership of any newly started VM, and must
    # retain its read-only input until the operator can identify the session.
    try { $started = Invoke-BoundedCommand $cli @('start','--config',$config.OuterXml,'--raw') 120000 }
    catch [TimeoutException] { $keep = $true; throw "Sandbox start timed out; trial retained at $trialRoot." }
    if ($started.Code -ne 0) { throw "Sandbox start failed: $($started.ErrorText) $($started.Output)" }
    $sandboxId = Read-StartedSandboxId $started.Output
    if (!$sandboxId) {
        $keep = $true
        throw "Could not identify the new sandbox. Trial retained at $trialRoot. Start response: $($started.Output)"
    }
    Start-Process -FilePath $cli -ArgumentList @('connect','--id',$sandboxId) -WindowStyle Hidden

    # wsb exec exposes the guest exit code. Distinctive codes avoid treating CLI success as a test pass.
    $query = @'
$file = Join-Path $env:LOCALAPPDATA 'AppShieldWeChatTest\result.json'
if (!(Test-Path -LiteralPath $file)) { exit 194 }
try { $r = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json } catch { exit 194 }
exit (& { __RESOLVE__ } $r '__RUN__' __PASS__)
'@
    $statuses = @('FRESH_SANDBOX_REQUIRED','INSTALLER_HASH_MISMATCH','INSTALL_FAILED','INSTALL_TIMEOUT',
        'CLIENT_NOT_INSTALLED','SIGNATURE_UNVERIFIED','UNEXPECTED_CLIENT_IDENTITY','LAUNCH_FAILED',
        'CLIENT_LAUNCH_ERROR','NO_VERIFIED_PROCESS','NO_VISIBLE_WINDOW','SCAN_PROMPT_UNVERIFIED','OBSERVER_TIMEOUT','OBSERVER_FAILED',
        'SHARED_INPUT_WRITABLE','SHARED_INPUT_WRITE_UNVERIFIED','SHARED_INPUT_PROBE_CLEANUP_FAILED')
    $passCode = 191
    $query = $query.Replace('__RESOLVE__',${function:Resolve-TrialReceipt}.ToString()).Replace('__RUN__',$id.ToString())
    if ($ClipboardJob) {
        $query = @'
$file = Join-Path $env:LOCALAPPDATA 'AppShieldClipboardResult.json'
if (!(Test-Path -LiteralPath $file)) {exit 194}
try {$r=Get-Content -Raw -LiteralPath $file | ConvertFrom-Json} catch {exit 194}
if ($r.RunId -ne '__RUN__') {exit 194}
if ($r.ExitCode -eq 0 -and $r.Status -eq 'PASS_ROOT_WINDOW_AND_JOB_CHILD') {exit __PASS__}
if ($r.ExitCode -eq 0 -and $r.Status -eq 'PASS_ROOT_WINDOW') {exit 218}
exit 192
'@
        $query=$query.Replace('__RUN__',$id.ToString())
    }
    $deadline = [datetime]::UtcNow.AddMinutes(6)
    do {
        Start-Sleep -Seconds 3
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($query.Replace('__PASS__',[string]$passCode)))
        $command = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
        try {
            $reply = Invoke-BoundedCommand $cli @('exec','--id',$sandboxId,'--run-as','ExistingLogin','--command',$command,'--raw') 12000
        } catch [TimeoutException] { continue }
        $code = Read-GuestExit $reply
        if ($code -eq $passCode) {
            if ($passCode -eq 191) { $passCode = 197; continue }
            $probeName = 'AppShield.WriteProbe.'+$id.ToString('N')+'.tmp'
            if (Test-Path -LiteralPath (Join-Path $inputDir $probeName)) {throw 'Guest probe left a file in the host input.'}
            if ($ClipboardJob) {Write-Output 'PASS: clipboard-limited guest client showed the login prompt and a verified Job descendant.'}
            else {Write-Output 'PASS_SCAN_PROMPT: stable signed guest client prompt; read verified and write denied on shared input.'}
            return
        }
        if ($ClipboardJob -and $code -eq 218) {
            Write-Warning 'Guest login prompt and root Job verified; no additional Job member observed.'
            exit 77
        }
        if ($code -eq 192) { throw 'FAIL: guest pre-login check did not pass.' }
        if ($code -ge 201 -and $code -le 217) {
            $status = $statuses[$code - 201]
            if ($code -in 204,206,211,212,213,214,216) { Write-Warning "UNVERIFIED: $status"; exit 77 }
            throw "Guest pre-login check failed: $status"
        }
    } while ([datetime]::UtcNow -lt $deadline)
    Write-Warning 'UNVERIFIED: the host did not receive a matching guest verdict before timeout.'
    exit 77
} finally {
    if ($sandboxId) {
        try { $stopped = Invoke-BoundedCommand $cli @('stop','--id',$sandboxId) 30000 }
        catch { $keep = $true; throw "Sandbox stop was not confirmed. Session $sandboxId; trial files $trialRoot. $_" }
        if ($stopped.Code -ne 0) { $keep = $true; throw "Sandbox stop failed. Session $sandboxId; trial files $trialRoot" }
    }
    if (Test-Path -LiteralPath (Join-Path $inputDir ('AppShield.WriteProbe.'+$id.ToString('N')+'.tmp'))) {
        throw "A guest write probe remains on the host. Trial retained at $trialRoot."
    }
    if (!$keep) {
        # Only files created by this invocation are eligible for removal.
        foreach ($file in @($payload,(Join-Path $inputDir 'Guest-Prelogin.ps1'),$configPath,(Join-Path $trialRoot 'WeChat-NetworkEnabled.wsb')) + $extraInputs) {
            if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file -Force }
        }
        [IO.Directory]::Delete($inputDir)
        [IO.Directory]::Delete($trialRoot)
    }
}
