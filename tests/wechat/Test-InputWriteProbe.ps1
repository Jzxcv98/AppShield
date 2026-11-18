# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'

# Load the guest's probe alone so this host check never invokes the installer or desktop observer.
$guest=Join-Path $PSScriptRoot '..\..\tools\wechat\Guest-Prelogin.ps1'
$tokens=$null
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $guest).Path,[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw $errors[0].Message}
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-InputWrite'},$false)
if (!$function) {throw 'Guest probe not found.'}
. ([scriptblock]::Create($function.Extent.Text))

$run=[guid]::NewGuid()
$root=Join-Path ([IO.Path]::GetTempPath()) ('AppShield.MappingProbe.'+$run.ToString('N'))
$marker=Join-Path $root ('AppShield.WriteProbe.'+$run.ToString('N')+'.tmp')
if (Test-Path -LiteralPath $root) {throw 'Unexpected test directory.'}
[void][IO.Directory]::CreateDirectory($root)
$originalAcl=$null
try {
    $probe=Test-InputWrite $root $run
    if ($probe.Result -ne 'WRITABLE' -or [IO.File]::Exists($marker)) {throw 'Writable mapping failed detection or cleanup.'}
    [IO.File]::WriteAllText($marker,'existing fixture')
    $probe=Test-InputWrite $root $run
    if ($probe.Result -ne 'UNVERIFIED' -or [IO.File]::ReadAllText($marker) -cne 'existing fixture') {throw 'Pre-existing marker was accepted or changed.'}
    [IO.File]::Delete($marker)
    $probe=Test-InputWrite (Join-Path $root 'missing') $run
    if ($probe.Result -ne 'UNVERIFIED') {throw 'Missing directory was accepted as read-only.'}

    $originalAcl=Get-Acl -LiteralPath $root
    $restricted=Get-Acl -LiteralPath $root
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $deny=[Security.AccessControl.FileSystemAccessRule]::new($user,'CreateFiles','Deny')
    $restricted.AddAccessRule($deny)
    Set-Acl -LiteralPath $root -AclObject $restricted
    $probe=Test-InputWrite $root $run
    if ($probe.Result -ne 'DENIED' -or $probe.HResult -ne '0x80070005' -or [IO.File]::Exists($marker)) {
        throw "Expected create to fail with access denied, observed $($probe.Result) $($probe.HResult)."
    }
    'PASS: denied create, writable mapping cleanup, collision preservation and missing mapping.'
} finally {
    if ($originalAcl) {Set-Acl -LiteralPath $root -AclObject $originalAcl}
    if ([IO.File]::Exists($marker)) {[IO.File]::Delete($marker)}
    [IO.Directory]::Delete($root)
}
