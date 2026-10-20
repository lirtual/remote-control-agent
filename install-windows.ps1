# Native Windows x64 bootstrap. Candidate source only: no Release is published here.
# Verify GitHub Release immutability + official SHA256 BEFORE extracting/executing.
[CmdletBinding()]
param(
  [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$')]
  [string]$Version = 'v0.1.9',
  [string]$OfflineArchive,
  [string]$ExpectedSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    -not [Environment]::Is64BitOperatingSystem -or -not $env:LOCALAPPDATA -or
    $env:LOCALAPPDATA -notmatch '^[A-Za-z]:[\\/]') {
  throw 'Native 64-bit Windows with a local user profile required'
}
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$userSid = $me.User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$allowedSids = @($userSid.Value, $systemSid.Value)
$root = [IO.Path]::Combine($env:LOCALAPPDATA, 'mcp-workers', 'remote-control')
$profile = Get-Item -LiteralPath $env:LOCALAPPDATA -Force
if (-not $profile.PSIsContainer -or
    ($profile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw 'Reparse-point profiles are unsupported'
}
function Assert-PrivateFolder([string]$folder) {
  $item = Get-Item -LiteralPath $folder -Force
  if (-not $item.PSIsContainer -or
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Unexpected folder type'
  }
  $acl = [IO.Directory]::GetAccessControl($folder)
  if (-not $acl.AreAccessRulesProtected -or
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $userSid.Value) {
    throw 'Unsafe folder ownership/inheritance'
  }
  $ownerFull = $false
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $allowedSids -notcontains $rule.IdentityReference.Value) {
      throw 'Unexpected folder ACL grant'
    }
    if ($rule.IdentityReference.Value -eq $userSid.Value -and
        (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
          [Security.AccessControl.FileSystemRights]::FullControl)) { $ownerFull = $true }
  }
  if (-not $ownerFull) { throw 'Owner lacks full control' }
}
function Ensure-PrivateFolder([string]$folder) {
  if (Test-Path -LiteralPath $folder) { Assert-PrivateFolder $folder; return }
  $null = [IO.Directory]::CreateDirectory($folder)
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetOwner($userSid)
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  foreach ($sid in @($userSid, $systemSid)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
      $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit,
      [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
  }
  [IO.Directory]::SetAccessControl($folder, $acl)
  Assert-PrivateFolder $folder
}
function Download-ImmutableRelease([string]$tag, [string]$dest) {
  $base = 'https://api.github.com/repos/lirtual/remote-control-agent'
  $headers = @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'rca-windows-pinned-installer' }
  $release = Invoke-RestMethod -Uri "$base/releases/tags/$tag" -Headers $headers -TimeoutSec 30
  if ($release.immutable -ne $true -or $release.draft -ne $false -or $release.tag_name -ne $tag) {
    throw 'Unpublished or mutable GitHub Release'
  }
  $ref = Invoke-RestMethod -Uri "$base/git/ref/tags/$tag" -Headers $headers -TimeoutSec 30
  if ($ref.ref -ne "refs/tags/$tag") { throw 'Unexpected Git tag' }
  $commit = $ref.object
  if ($commit.type -eq 'tag') {
    if ($commit.sha -notmatch '^[a-f0-9]{40}$') { throw 'Invalid annotated tag' }
    $annotated = Invoke-RestMethod -Uri "$base/git/tags/$($commit.sha)" -Headers $headers -TimeoutSec 30
    $commit = $annotated.object
  }
  if ($commit.type -ne 'commit' -or $commit.sha -notmatch '^[a-f0-9]{40}$') {
    throw 'Untrusted Release source commit'
  }
  $name = "remote-control-agent-$tag-windows-x64.zip"
  $assets = @($release.assets | Where-Object { $_.name -ceq $name })
  if ($assets.Count -ne 1) { throw 'Pinned Windows asset is missing' }
  $asset = $assets[0]
  $expectedUri = "https://github.com/lirtual/remote-control-agent/releases/download/$tag/$name"
  if ($asset.state -ne 'uploaded' -or $asset.digest -cnotmatch '^sha256:[a-f0-9]{64}$' -or
      $asset.browser_download_url -cne $expectedUri -or
      $asset.size -lt 100000 -or $asset.size -gt 100000000) {
    throw 'Untrusted GitHub Release asset digest/URL'
  }
  Invoke-WebRequest -Uri $expectedUri -OutFile $dest -MaximumRedirection 5 -TimeoutSec 120 -UseBasicParsing
  return $asset.digest.Substring(7)
}
function Assert-ArchiveDigest([string]$file, [string]$sha) {
  if ($sha -cnotmatch '^[a-f0-9]{64}$') { throw 'SHA256 must be pinned' }
  $item = Get-Item -LiteralPath $file -Force
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $item.Length -lt 100000 -or $item.Length -gt 100000000) {
    throw 'Untrusted ZIP asset file'
  }
  $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -cne $sha) { throw 'Release asset SHA256 mismatch' }
}
function Expand-SafeArchive([string]$file, [string]$folder) {
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($file)
  try {
    $entries = @($zip.Entries)
    if ($entries.Count -lt 8 -or $entries.Count -gt 70) { throw 'Unexpected ZIP member count' }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    [long]$total = 0
    foreach ($entry in $entries) {
      $name = $entry.FullName
      if ($name.Contains('\') -or $name.Contains(':') -or $name.StartsWith('/') -or
          $name.Contains('//') -or $name -match '(^|/)\.{1,2}(/|$)' -or
          $name -match '[^\x20-\x7e]' -or -not $seen.Add($name)) {
        throw 'ZIP traversal, alias or duplicate'
      }
      $allowedDir = $name -cmatch '^(?:bin|apps|apps/remote-control-agent|apps/remote-control-agent/src|apps/remote-control-agent/scripts)/$'
      $allowedFile = $name -cmatch '^(?:bin/node\.exe|rca\.cmd|bundle\.json|apps/remote-control-agent/(?:package\.json|src/[a-z0-9-]+\.js|scripts/(?:(?:windows-private-store|windows-user-task)\.ps1|verify-windows-preview\.mjs)))$'
      if (($name.EndsWith('/') -and -not $allowedDir) -or
          (-not $name.EndsWith('/') -and -not $allowedFile)) {
        if ($env:GITHUB_ACTIONS -eq 'true') {
          throw ('Unreviewed CI ZIP member: ' + $name)
        }
        throw 'Unreviewed ZIP member'
      }
      $unixKind = (($entry.ExternalAttributes -shr 16) -band 0xF000)
      if ($unixKind -eq 0xA000 -or $unixKind -eq 0x6000) { throw 'ZIP links forbidden' }
      if (-not $name.EndsWith('/')) {
        if ($entry.Length -lt 0 -or $entry.Length -gt 130000000) { throw 'Oversized ZIP entry' }
        $total += $entry.Length
        if ($total -gt 150000000) { throw 'ZIP expansion limit' }
      }
    }
    foreach ($entry in $entries) {
      $relative = $entry.FullName.TrimEnd('/').Replace('/', [IO.Path]::DirectorySeparatorChar)
      $dest = [IO.Path]::Combine($folder, $relative)
      $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest))
      if ($entry.FullName.EndsWith('/')) { $null = [IO.Directory]::CreateDirectory($dest); continue }
      $inputStream = $entry.Open()
      try {
        $output = [IO.File]::Open($dest, [IO.FileMode]::CreateNew,
                                 [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $inputStream.CopyTo($output); $output.Flush($true) }
        finally { $output.Dispose() }
      } finally { $inputStream.Dispose() }
    }
  } finally { $zip.Dispose() }
}
$temp = $null
$stage = $null
$promoted = $false
try {
  Ensure-PrivateFolder ([IO.Path]::Combine($env:LOCALAPPDATA, 'mcp-workers'))
  Ensure-PrivateFolder $root
  $programs = [IO.Path]::Combine($root, 'programs')
  Ensure-PrivateFolder $programs
  $target = [IO.Path]::Combine($programs, "$Version-windows-x64")
  if (Test-Path -LiteralPath $target) { throw 'Version already installed; no overwrite/implicit upgrade' }
  $temp = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('rca-' + [guid]::NewGuid().ToString('N') + '.zip'))
  if ($OfflineArchive) {
    if ($env:GITHUB_ACTIONS -ne 'true' -or -not $ExpectedSha256) {
      throw 'Offline input is allowed only by explicit CI fixture'
    }
    [IO.File]::Copy([IO.Path]::GetFullPath($OfflineArchive), $temp, $false)
    $expected = $ExpectedSha256
  } else {
    if ($ExpectedSha256) { throw 'Live checksum must come from immutable GitHub Release' }
    $expected = Download-ImmutableRelease $Version $temp
  }
  Assert-ArchiveDigest $temp $expected
  $stage = [IO.Path]::Combine($programs, ('.stage-' + [guid]::NewGuid().ToString('N')))
  Ensure-PrivateFolder $stage
  Expand-SafeArchive $temp $stage
  $node = [IO.Path]::Combine($stage, 'bin', 'node.exe')
  $verifier = [IO.Path]::Combine($stage, 'apps', 'remote-control-agent',
                                'scripts', 'verify-windows-preview.mjs')
  & $node $verifier $stage
  if ($LASTEXITCODE -ne 0) { throw 'Bundle file manifest failed verification' }
  $manifest = Get-Content -LiteralPath ([IO.Path]::Combine($stage, 'bundle.json')) -Raw | ConvertFrom-Json
  if ($manifest.version -cne $Version) { throw 'Manifest version mismatch' }
  [IO.Directory]::Move($stage, $target)
  $promoted = $true
  Write-Output "Native Windows Agent installed (not paired): $target"
  Write-Output 'Use the bundled rca.cmd with pair/run/status; no system Node is required.'
} finally {
  if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Force }
  if (-not $promoted -and $stage -and (Test-Path -LiteralPath $stage)) {
    Remove-Item -LiteralPath $stage -Recurse -Force
  }
}
