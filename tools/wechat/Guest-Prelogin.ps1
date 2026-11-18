# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding(DefaultParameterSetName='Install')]
param(
    [Parameter(Mandatory, ParameterSetName='Install')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory, ParameterSetName='Install')][guid]$RunId,
    [Parameter(ParameterSetName='Install')][ValidateSet('Off','Default')][string]$Networking='Off',
    [Parameter(Mandatory, ParameterSetName='Observe')][switch]$Observe
)
$ErrorActionPreference='Stop'
# Do not install anything or write a result when this script is opened on the host.
$guestUser=[Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
if ($guestUser -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\AppShieldInput') {
    throw 'Run inside Windows Sandbox through the host launcher.'
}
$client=Join-Path $env:ProgramFiles 'Tencent\Weixin\Weixin.exe'

function Find-ScanPrompt {
    Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
    $element=[System.Windows.Automation.AutomationElement]
    $names=@('Scan to log in','Scan QR code to log in','扫码登录','掃碼登入','扫描二维码登录','掃描二維碼登入',
        '请使用手机微信扫码登录','請使用手機微信掃碼登入','请使用手机微信扫描二维码登录','請使用手機微信掃描二維碼登入','掃描 QR Code 登入')
    $labels=foreach ($name in $names) {
        [System.Windows.Automation.PropertyCondition]::new($element::NameProperty,$name,
            [System.Windows.Automation.PropertyConditionFlags]::IgnoreCase)
    }
    $scan=[System.Windows.Automation.OrCondition]::new([System.Windows.Automation.Condition[]]$labels)
    $visible=[System.Windows.Automation.PropertyCondition]::new($element::IsOffscreenProperty,$false)
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $candidate=''
    $since=0
    $sawClient=$false
    $sawWindow=$false
    while ($watch.Elapsed.TotalSeconds -lt 45) {
        $match=''
        foreach ($p in @(Get-Process -Name 'Weixin' -ErrorAction SilentlyContinue)) {
            try {
                if ($p.HasExited -or $p.MainModule.FileName -ine $client) {continue}
                $sawClient=$true
                $pidCondition=[System.Windows.Automation.PropertyCondition]::new($element::ProcessIdProperty,$p.Id)
                $owned=[System.Windows.Automation.AndCondition]::new($pidCondition,$visible)
                $windowList=$element::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children,$owned)
                foreach ($window in $windowList) {
                    $sawWindow=$true
                    $handle=$window.Current.NativeWindowHandle
                    if (!$handle) {continue}
                    if ($window.Current.ClassName -eq '#32770') {
                        $title=$window.Current.Name.Replace([char]0xa0,[char]0x20)
                        if ($title -in 'Launch Error','启动错误','啟動錯誤') {return 11}
                    }
                    $prompt=$window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
                        [System.Windows.Automation.AndCondition]::new($owned,$scan))
                    if ($prompt -and !$p.HasExited) { $match="$($p.Id)/$($p.StartTime.Ticks)/$handle" }
                }
            }
            catch [System.Windows.Automation.ElementNotAvailableException] { }
            catch [System.InvalidOperationException] { }
            finally { $p.Dispose() }
        }
        if (!$match -or $candidate -ne $match) {
            $candidate=$match
            $since=$watch.ElapsedMilliseconds
        } elseif ($watch.ElapsedMilliseconds - $since -ge 3000) {
            return 0
        }
        Start-Sleep -Milliseconds 250
    }
    if (!$sawClient) {return 12}
    if (!$sawWindow) {return 13}
    return 14
}
if ($Observe) {
    try { exit (Find-ScanPrompt) } catch { exit 15 }
}

function Test-InputWrite([string]$Directory, [guid]$Run) {
    $marker=Join-Path $Directory ('AppShield.WriteProbe.'+$Run.ToString('N')+'.tmp')
    try {
        $stream=[IO.File]::Open($marker,'CreateNew','Write','None')
    } catch {
        $errorCode=$_.Exception.GetBaseException().HResult
        # ERROR_ACCESS_DENIED and ERROR_WRITE_PROTECT establish a rejected write.
        # Missing mappings, sharing violations and existing files are inconclusive.
        $result=if ($errorCode -in -2147024891,-2147024877) {'DENIED'} else {'UNVERIFIED'}
        return [pscustomobject]@{Result=$result;HResult=('0x{0:X8}' -f $errorCode)}
    }
    try {
        $stream.Dispose()
        [IO.File]::Delete($marker)
    } catch {
        return [pscustomobject]@{Result='CLEANUP_FAILED';HResult=('0x{0:X8}' -f $_.Exception.GetBaseException().HResult)}
    }
    return [pscustomobject]@{Result='WRITABLE';HResult=$null}
}

$resultDir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AppShieldWeChatTest'
[void][IO.Directory]::CreateDirectory($resultDir)
$resultPath=Join-Path $resultDir 'result.json'
$stage='PREFLIGHT'
$status='UNEXPECTED_ERROR'
$version=$null
$code=1
$sharedInput=[ordered]@{ReadVerified=$false;WriteResult='NOT_TESTED';WriteHResult=$null}

try {
    if ([IO.File]::Exists($resultPath) -or (Test-Path -LiteralPath $client) -or
        (Get-Process -Name Weixin,WeChat -ErrorAction SilentlyContinue)) {
        $status='FRESH_SANDBOX_REQUIRED'; throw $status
    }
    $stage='VERIFY_INSTALLER'
    $status='INSTALLER_HASH_MISMATCH'
    $inputFile=Join-Path $PSScriptRoot 'WeChatSetup.exe'
    # Keep the verified file immutable for the duration of the installation.
    $lock=[IO.File]::Open($inputFile,'Open','Read','Read')
    try {
        if ((Get-FileHash -InputStream $lock -Algorithm SHA256).Hash -ine $ExpectedSha256) {throw $status}
        $sharedInput.ReadVerified=$true
        $stage='VERIFY_INPUT_MAPPING'
        $probe=Test-InputWrite $PSScriptRoot $RunId
        $sharedInput.WriteResult=$probe.Result
        $sharedInput.WriteHResult=$probe.HResult
        switch ($probe.Result) {
            'WRITABLE' { $status='SHARED_INPUT_WRITABLE'; throw $status }
            'CLEANUP_FAILED' { $status='SHARED_INPUT_PROBE_CLEANUP_FAILED'; throw $status }
            'DENIED' { }
            default { $status='SHARED_INPUT_WRITE_UNVERIFIED'; $code=77; throw $status }
        }
        $stage='INSTALL'
        $status='INSTALL_FAILED'
        $setup=Start-Process -FilePath $inputFile -ArgumentList '/S' -WindowStyle Hidden -PassThru
        try {
            if (!$setup.WaitForExit(180000)) {$status='INSTALL_TIMEOUT'; $code=77; throw $status}
            if ($setup.ExitCode -ne 0) {throw $status}
        } finally { $setup.Dispose() }
    } finally { $lock.Dispose() }

    $stage='VERIFY_CLIENT'
    $status='CLIENT_NOT_INSTALLED'
    $installClock=[Diagnostics.Stopwatch]::StartNew()
    while (![IO.File]::Exists($client) -and $installClock.Elapsed.TotalSeconds -lt 20) {
        Start-Sleep -Milliseconds 500
    }
    if (![IO.File]::Exists($client)) {throw $status}
    $image=[IO.File]::Open($client,'Open','Read','Read')
    try {
        $status='SIGNATURE_UNVERIFIED'
        $sig=Get-AuthenticodeSignature -LiteralPath $client
        $meta=[Diagnostics.FileVersionInfo]::GetVersionInfo($client)
        if ($sig.Status -ne 'Valid' -or !$sig.SignerCertificate) { $code=77; throw $status }
        $publisher=$sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
        if ($publisher -ne 'Tencent Technology (Shenzhen) Company Limited' -or
            $meta.ProductName -ne 'Weixin' -or $meta.FileDescription -ne 'Weixin') {
            $status='UNEXPECTED_CLIENT_IDENTITY'; throw $status
        }
        $version=$meta.ProductVersion
        $stage='LAUNCH'
        $status='LAUNCH_FAILED'
        # A silent installer can start the installed client itself.
        $running=@(Get-Process -Name Weixin -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $client })
        if (!$running.Count) {
            Start-Process -FilePath $client -WorkingDirectory ([IO.Path]::GetDirectoryName($client))
        }
        foreach ($p in $running) {$p.Dispose()}
        $stage='OBSERVE'
        $status='OBSERVER_FAILED'
        # Some UI Automation providers block. A separate bounded worker cannot stall the receipt.
        $observer=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @(
            '-NoProfile','-NonInteractive','-MTA','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Observe'
        ) -WindowStyle Hidden -PassThru
        try {
            if (!$observer.WaitForExit(55000)) {
                $observer.Kill(); $status='OBSERVER_TIMEOUT'; $code=77; throw $status
            }
            switch ($observer.ExitCode) {
                0  { $status='PASS_SCAN_PROMPT'; $code=0 }
                11 { $status='CLIENT_LAUNCH_ERROR' }
                12 { $status='NO_VERIFIED_PROCESS' }
                13 { $status='NO_VISIBLE_WINDOW'; $code=77 }
                14 { $status='SCAN_PROMPT_UNVERIFIED'; $code=77 }
                default { $status='OBSERVER_FAILED'; $code=77 }
            }
        } finally { $observer.Dispose() }
    } finally { $image.Dispose() }
} catch {
    Write-Host ("Guest check stopped at {0} ({1})." -f $stage,$status)
}
$result=[ordered]@{RunId=$RunId.ToString('D');Stage=$stage;Status=$status;ExitCode=$code;ProductVersion=$version;Networking=$Networking;SharedInput=$sharedInput}
$json=$result | ConvertTo-Json
$tmp=Join-Path $resultDir ([guid]::NewGuid().ToString('N')+'.tmp')
[IO.File]::WriteAllText($tmp,$json)
if ([IO.File]::Exists($resultPath)) { [IO.File]::Replace($tmp,$resultPath,$null) }
else { [IO.File]::Move($tmp,$resultPath) }
Write-Host $json
exit $code
