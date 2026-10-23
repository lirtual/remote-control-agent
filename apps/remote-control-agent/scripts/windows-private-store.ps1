# Native Windows foreground preview: create/check *only* the current user's private Agent store.
# PowerShell 5.1 on Windows. No elevation, scheduled task, service or cloud operation.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Init','Check','Seal')][string]$Action,
  [Parameter(Mandatory=$true)][string]$Directory,
  [ValidateSet('v2-identity.pem','v2-identity.pem.device-id','v2-identity.pem.install-mode','v2-identity.pem.activation-pending')][string]$FileName
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows required' }
if (-not $env:LOCALAPPDATA) { throw 'Missing local profile' }
$expected = [IO.Path]::GetFullPath([IO.Path]::Combine($env:LOCALAPPDATA, 'mcp-workers', 'remote-control'))
if (-not [string]::Equals([IO.Path]::GetFullPath($Directory), $expected, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'Unexpected Agent store'
}
if ($expected.StartsWith('\\') -or $expected.StartsWith('//')) { throw 'Network stores are not allowed' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$userSid = $identity.User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$allowed = @($userSid.Value, $systemSid.Value)

function Assert-PrivateAcl([string]$file, [bool]$directory) {
  $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Agent store contains a reparse point' }
  if ($directory -and -not $item.PSIsContainer) { throw 'Expected a private directory' }
  if (-not $directory -and $item.PSIsContainer) { throw 'Expected an identity file' }
  # Native .NET API works when the PowerShell.Security module cannot autoload.
  $acl = if ($directory) { [IO.Directory]::GetAccessControl($file) } else { [IO.File]::GetAccessControl($file) }
  if ($directory -and -not $acl.AreAccessRulesProtected) { throw 'Private directory inherits broad ACL' }
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne $userSid.Value) { throw 'Private path owner is not the current user' }
  $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  $userFullControl = $false
  foreach ($rule in $rules) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $allowed -notcontains $rule.IdentityReference.Value) {
      throw 'Unexpected identity ACL grant'
    }
    if ($rule.IdentityReference.Value -eq $userSid.Value -and
        (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
         [Security.AccessControl.FileSystemRights]::FullControl)) {
      $userFullControl = $true
    }
  }
  if (-not $userFullControl) { throw 'Missing owner-only ACL grant' }
}

function New-PrivateDirectory([string]$file) {
  if ([IO.Directory]::Exists($file) -or [IO.File]::Exists($file)) {
    Assert-PrivateAcl $file $true
    return
  }
  $null = [IO.Directory]::CreateDirectory($file)
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetOwner($userSid)
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  foreach ($sid in @($userSid, $systemSid)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
      $sid, [Security.AccessControl.FileSystemRights]::FullControl,
      $inherit, [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
  }
  [IO.Directory]::SetAccessControl($file, $acl)
  Assert-PrivateAcl $file $true
}

$local = Get-Item -LiteralPath $env:LOCALAPPDATA -Force -ErrorAction Stop
if (-not $local.PSIsContainer -or ($local.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw 'Unsafe local profile directory'
}
$parent = [IO.Path]::Combine($env:LOCALAPPDATA, 'mcp-workers')
if ($Action -eq 'Init') {
  New-PrivateDirectory $parent
  New-PrivateDirectory $expected
} else {
  Assert-PrivateAcl $parent $true
  Assert-PrivateAcl $expected $true
}
if ($Action -eq 'Seal') {
  # Only after a caller proved exclusive create with flag 'wx'. Never seal
  # arbitrary files or rotate/correct an existing identity silently.
  if (-not $FileName) { throw 'A newly created identity filename is required' }
  $file = [IO.Path]::Combine($expected, $FileName)
  $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Identity is not a regular local file'
  }
  $fileAcl = [Security.AccessControl.FileSecurity]::new()
  $fileAcl.SetOwner($userSid)
  $fileAcl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($userSid, $systemSid)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
      $sid, [Security.AccessControl.FileSystemRights]::FullControl,
      [Security.AccessControl.AccessControlType]::Allow)
    $fileAcl.AddAccessRule($rule)
  }
  [IO.File]::SetAccessControl($file, $fileAcl)
  Assert-PrivateAcl $file $false
  return
}
foreach ($name in @('v2-identity.pem', 'v2-identity.pem.device-id', 'v2-identity.pem.install-mode', 'v2-identity.pem.activation-pending')) {
  $file = [IO.Path]::Combine($expected, $name)
  if ([IO.File]::Exists($file) -or [IO.Directory]::Exists($file)) {
    Assert-PrivateAcl $file $false
  }
}
