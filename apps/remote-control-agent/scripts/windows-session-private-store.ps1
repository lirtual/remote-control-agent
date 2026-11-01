# GitHub-hosted Windows Session only: protect the job-scoped RCA identity.
# Does not read or change the ordinary per-user Agent store, task or service.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Init','Check','Seal')][string]$Action,
  [Parameter(Mandatory=$true)][string]$Directory,
  [ValidateSet('identity.json','v2-identity.pem','v2-identity.pem.device-id','receipts','transport-stage')][string]$FileName
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    -not $env:RUNNER_TEMP) { throw 'GitHub-hosted Windows Session required' }
$temp=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
$expected=[IO.Path]::GetFullPath([IO.Path]::Combine($temp,'session-rca'))
if (-not [string]::Equals([IO.Path]::GetFullPath($Directory),$expected,[StringComparison]::OrdinalIgnoreCase) -or
    $temp.StartsWith('\\') -or $temp.StartsWith('//') -or
    $expected.StartsWith('\\') -or $expected.StartsWith('//')) { throw 'Unexpected Session store' }
# Avoid starting a PowerShell FileSystem provider in the OIDC-stripped child.
# .NET attributes check preserves the directory and no-reparse-point contract.
$parentAttributes=[IO.File]::GetAttributes($temp)
if (($parentAttributes -band [IO.FileAttributes]::Directory) -eq 0 -or
    ($parentAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw 'Unsafe Runner Temp'
}
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$allowed=@($user.Value,$system.Value)
function New-PrivateAcl([bool]$isDirectory) {
  $acl=if($isDirectory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
  $acl.SetOwner($user)
  $acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @($user,$system)){
    if($isDirectory){
      $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    }else{
      $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow)
    }
    $acl.AddAccessRule($rule)
  }
  return $acl
}
function Assert-Private([string]$target,[bool]$isDirectory){
  $attributes=[IO.File]::GetAttributes($target)
  $actualDirectory=($attributes -band [IO.FileAttributes]::Directory) -ne 0
  if($actualDirectory -ne $isDirectory -or
     ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
    throw 'Wrong type or reparse point'
  }
  $acl=if($isDirectory){[IO.Directory]::GetAccessControl($target)}else{[IO.File]::GetAccessControl($target)}
  if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value){
    throw 'Session store ownership or ACL inheritance invalid'
  }
  $hasUser=$false
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
       $allowed -notcontains $rule.IdentityReference.Value){throw 'Unexpected Session ACL grant'}
    if($rule.IdentityReference.Value -eq $user.Value -and
       (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
         [Security.AccessControl.FileSystemRights]::FullControl)){$hasUser=$true}
  }
  if(-not $hasUser){throw 'Missing exclusive Runner identity ownership'}
}
if($Action -eq 'Init' -and -not [IO.Directory]::Exists($expected)){
  [void][IO.Directory]::CreateDirectory($expected)
  [IO.Directory]::SetAccessControl($expected,(New-PrivateAcl $true))
}
Assert-Private $expected $true
if($Action -eq 'Seal'){
  if(-not $FileName){throw 'Exact newly-created Session filename required'}
  $file=[IO.Path]::Combine($expected,$FileName)
  $isDirectory=$FileName -eq 'receipts'
  $attributes=[IO.File]::GetAttributes($file)
  $actualDirectory=($attributes -band [IO.FileAttributes]::Directory) -ne 0
  if($actualDirectory -ne $isDirectory -or
     ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
    throw 'Only regular Session-owned resources may be sealed'
  }
  if($isDirectory){[IO.Directory]::SetAccessControl($file,(New-PrivateAcl $true))}
  else{[IO.File]::SetAccessControl($file,(New-PrivateAcl $false))}
  Assert-Private $file $isDirectory
}
foreach($name in @('identity.json','v2-identity.pem','v2-identity.pem.device-id','receipts','transport-stage')){
  $file=[IO.Path]::Combine($expected,$name)
  if([IO.File]::Exists($file) -or [IO.Directory]::Exists($file)){
    Assert-Private $file ($name -eq 'receipts')
  }
}
