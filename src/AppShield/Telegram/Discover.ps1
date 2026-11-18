# SPDX-License-Identifier: GPL-3.0-only
# Run only in the host's Windows PowerShell. Output is a single verified installation.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Use the in-box Windows PowerShell modules even when the parent is PowerShell 7.
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$candidate = $env:APPSHIELD_TELEGRAM_CANDIDATE
$family = 'TelegramMessengerLLP.TelegramDesktop_t4vj0pshhgkwm'
$targets = [Collections.Generic.List[string]]::new()
$storePaths = @{}

function Add-Candidate([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)) { return }
    try { $path = [IO.Path]::GetFullPath($path) } catch { return }
    if ([IO.Path]::GetFileName($path) -ine 'Telegram.exe' -or $path.StartsWith('\\')) { return }
    if ([IO.File]::Exists($path) -and -not $targets.Contains($path)) { $targets.Add($path) }
}

try {
    foreach ($pkg in @(Get-AppxPackage -Name 'TelegramMessengerLLP.TelegramDesktop' -ErrorAction Stop)) {
        if ($pkg.PackageFamilyName -ine $family -or [string]$pkg.SignatureKind -ne 'Store') { continue }
        $manifest = Get-AppxPackageManifest -Package $pkg.PackageFullName
        foreach ($entry in $manifest.Package.Applications.Application) {
            $relative = [string]$entry.Executable
            if (-not $relative -or [IO.Path]::IsPathRooted($relative) -or
                [IO.Path]::GetFileName($relative) -ine 'Telegram.exe') { continue }
            $root = [IO.Path]::GetFullPath($pkg.InstallLocation).TrimEnd('\') + '\'
            $path = [IO.Path]::GetFullPath([IO.Path]::Combine($root, $relative))
            if (-not $path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $storePaths[$path] = $family + '!' + [string]$entry.Id
            if (-not $candidate) { Add-Candidate $path }
        }
    }
} catch {
    # Ordinary desktop and portable distributions can also be identified by signature.
}

if ($candidate) {
    Add-Candidate $candidate
} else {
    foreach ($p in @(Get-Process -Name Telegram -ErrorAction SilentlyContinue)) {
        try { Add-Candidate $p.Path } catch { }
    }
    $program32 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    foreach ($location in @($env:APPDATA, $env:LOCALAPPDATA, $env:ProgramFiles, $program32)) {
        if ($location) { Add-Candidate ([IO.Path]::Combine($location, 'Telegram Desktop', 'Telegram.exe')) }
    }
    foreach ($hive in @([Microsoft.Win32.Registry]::CurrentUser, [Microsoft.Win32.Registry]::LocalMachine)) {
        foreach ($appPaths in @('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Telegram.exe',
                                'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Telegram.exe')) {
            $key = $null
            try {
                $key = $hive.OpenSubKey($appPaths)
                if ($key) { Add-Candidate (([string]$key.GetValue('')).Trim('"')) }
            } catch { } finally { if ($key) { $key.Dispose() } }
        }
    }
}

foreach ($path in $targets) {
    $isStore = $storePaths.ContainsKey($path)
    if ($path -match '\\WindowsApps\\' -and -not $isStore) { continue }
    try {
        $image = Get-Item -LiteralPath $path
        if ($image.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $path
        if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { continue }
        $publisher = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if ($publisher -ine 'Telegram FZ-LLC' -or $image.VersionInfo.ProductName -ine 'Telegram Desktop') { continue }
        $version = [Version]::Parse($image.VersionInfo.ProductVersion)
    } catch { continue }
    [ordered]@{
        ExecutablePath = $image.FullName
        Version = $version.ToString()
        Publisher = $publisher
        PackageFamilyName = $(if ($isStore) { $family } else { '' })
        PackageAppId = $(if ($isStore) { $storePaths[$path] } else { '' })
    } | ConvertTo-Json -Compress
    exit 0
}
exit 3
