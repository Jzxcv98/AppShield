# SPDX-License-Identifier: GPL-3.0-only
# Embedded by AppShield as a Windows Sandbox LogonCommand. Only the installer directory is mapped.
$ErrorActionPreference = 'Stop'
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
if ($account -ne 'WDAGUtilityAccount') { exit 1 }
$source = 'C:\AppShieldInput\WeChatSetup.exe'
$exe = Join-Path $env:ProgramFiles 'Tencent\Weixin\Weixin.exe'
$stage = 'verify-installer'
$ok = $false
$failure = $null
try {
    $inputFile = [IO.File]::Open($source,'Open','Read','Read')
    try {
        if ((Get-FileHash -InputStream $inputFile -Algorithm SHA256).Hash -ne '__HASH__') { throw 'Installer hash mismatch.' }
        $stage = 'install'
        $setup = Start-Process -FilePath $source -ArgumentList '/S' -WindowStyle Hidden -PassThru
        try {
            if (!$setup.WaitForExit(180000) -or $setup.ExitCode -ne 0) { throw 'Installer failed.' }
        } finally { $setup.Dispose() }
    } finally { $inputFile.Dispose() }
    $stage = 'verify-client'
    $image = [IO.File]::Open($exe,'Open','Read','Read')
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $exe
        $meta = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
        if ($sig.Status -ne 'Valid' -or !$sig.SignerCertificate -or
            $sig.SignerCertificate.GetNameInfo('SimpleName',$false) -ne 'Tencent Technology (Shenzhen) Company Limited' -or
            $meta.ProductName -ne 'Weixin' -or $meta.ProductVersion -ne '__VERSION__') { throw 'Unexpected WeChat client.' }
        $stage = 'launch'
        $running = @(Get-Process -Name Weixin -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $exe })
        if (!$running.Count) { Start-Process -FilePath $exe -WorkingDirectory ([IO.Path]::GetDirectoryName($exe)) }
        $ok = $true
    } finally { $image.Dispose() }
} catch {
    $failure = "WeChat setup in Windows Sandbox failed ($stage). " + $_.Exception.Message
} finally {
    $state = Join-Path $env:LOCALAPPDATA 'AppShield'
    [void][IO.Directory]::CreateDirectory($state)
    $receipt = @{RunId='__RUN__';Version='__VERSION__';Stage=$stage;LaunchRequested=$ok}
    [IO.File]::WriteAllText((Join-Path $state 'WeChatSandboxStart.json'),($receipt | ConvertTo-Json))
}
if ($failure) {
    Add-Type -AssemblyName System.Windows.Forms
    [void][Windows.Forms.MessageBox]::Show($failure,'AppShield')
}
