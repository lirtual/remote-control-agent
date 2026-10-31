# Native Windows x64 bootstrap. Refuses a Release unless published and immutable.
# Verify GitHub Release immutability + official SHA256 BEFORE extracting/executing.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$')][string]$Version,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$PinnedCommit,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PinnedReleaseSha256,
  [string]$OfflineArchive,
  [string]$ExpectedSha256,
  [switch]$StageOnly
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
function Download-ApprovedAsset([string]$firstUri, [string]$dest) {
  # Do not let an HTTP redirect select a new release source or an internal URL.
  Add-Type -AssemblyName System.Net.Http
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [TimeSpan]::FromSeconds(120)
  $uri = [Uri]::new($firstUri)
  try {
    for ($redirects = 0; $redirects -le 5; $redirects++) {
      if ($uri.Scheme -cne 'https' -or $uri.Port -ne 443 -or
          $uri.UserInfo -or $uri.Fragment -or
          (($redirects -eq 0 -and
            ($uri.AbsoluteUri -cne $firstUri -or $uri.Host -cne 'github.com' -or
             $uri.AbsolutePath -cnotlike '/lirtual/remote-control-agent/releases/download/*')) -or
           ($redirects -gt 0 -and $uri.Host -cnotin @(
              'release-assets.githubusercontent.com', 'objects.githubusercontent.com')))) {
        throw 'Unexpected GitHub Release asset redirect'
      }
      $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
      try {
        $status = [int]$response.StatusCode
        if ($status -in @(301,302,303,307,308)) {
          if (-not $response.Headers.Location -or $redirects -eq 5) {
            throw 'GitHub Release asset redirect limit exceeded'
          }
          $uri = [Uri]::new($uri, $response.Headers.Location)
          continue
        }
        if ($status -ne 200 -or
            ($response.Content.Headers.ContentLength -ne $null -and
             $response.Content.Headers.ContentLength -gt 100000000)) {
          throw 'Untrusted GitHub Release asset response'
        }
        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = [IO.File]::Open($dest, [IO.FileMode]::CreateNew,
                                     [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
          $buffer = [byte[]]::new(65536)
          [long]$total = 0
          while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $count
            if ($total -gt 100000000) { throw 'Oversized GitHub Release asset' }
            $outputStream.Write($buffer, 0, $count)
          }
          $outputStream.Flush($true)
        } finally {
          $outputStream.Dispose()
          $inputStream.Dispose()
        }
        return
      } finally { $response.Dispose() }
    }
    throw 'GitHub Release asset redirect limit exceeded'
  } finally {
    $client.Dispose()
    $handler.Dispose()
  }
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
  if ($commit.type -ne 'commit' -or $commit.sha -cne $PinnedCommit) {
    throw 'Untrusted Release source commit'
  }
  $name = "remote-control-agent-$tag-windows-x64.zip"
  $assets = @($release.assets | Where-Object { $_.name -ceq $name })
  if ($assets.Count -ne 1) { throw 'Pinned Windows asset is missing' }
  $asset = $assets[0]
  $expectedUri = "https://github.com/lirtual/remote-control-agent/releases/download/$tag/$name"
  if ($asset.state -ne 'uploaded' -or $asset.digest -cne ('sha256:' + $PinnedReleaseSha256) -or
      $asset.browser_download_url -cne $expectedUri -or
      $asset.size -lt 100000 -or $asset.size -gt 100000000) {
    throw 'Untrusted GitHub Release asset digest/URL'
  }
  Download-ApprovedAsset $expectedUri $dest
  return $asset.digest.Substring(7)
}
function Assert-ArchiveDigest([string]$file, [string]$sha) {
  if ($sha -cnotmatch '^[a-f0-9]{64}$') { throw 'SHA256 must be pinned' }
  $item = Get-Item -LiteralPath $file -Force
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $item.Length -lt 100000 -or $item.Length -gt 100000000) {
    throw 'Untrusted ZIP asset file'
  }
  # Use the built-in .NET hash implementation rather than depending on
  # automatic PowerShell module discovery in a fresh restricted user profile.
  $hash = [Security.Cryptography.SHA256]::Create()
  try {
    $stream = [IO.File]::Open($file, [IO.FileMode]::Open,
      [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $digest = $hash.ComputeHash($stream) }
    finally { $stream.Dispose() }
    $actual = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
  } finally { $hash.Dispose() }
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
      $allowedFile = $name -cmatch '^(?:bin/(?:node\.exe|rca-background\.exe)|rca\.cmd|bundle\.json|apps/remote-control-agent/(?:package\.json|src/[a-z0-9-]+\.js|scripts/(?:(?:windows-private-store|windows-session-private-store|windows-user-task|windows-stage-install|windows-upgrade-once)\.ps1|verify-windows-preview\.mjs)))$'
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
# Inspect the task target without launching it. The packaged CLI performs
# the complete owner/ACL/task signature validation again before switching.
function Get-ExistingAgentVersion([string]$programs, [string]$taskExe) {
  if (-not $taskExe) { throw 'Existing Agent task has no executable' }
  $base = [IO.Path]::GetFullPath($programs).TrimEnd('\') + '\'
  $exe = [IO.Path]::GetFullPath($taskExe)
  if (-not $exe.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Existing Agent task is outside its private program folder'
  }
  $relative = $exe.Substring($base.Length)
  $matched = [regex]::Match($relative,
    '^(v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?)-windows-x64\\bin\\(?:node\.exe|rca-background\.exe)$',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if (-not $matched.Success) { throw 'Unrecognized existing Agent task executable' }
  return $matched.Groups[1].Value
}
function Complete-ApprovedOnboarding([string]$launcher) {
  # The local installer is interactive. Missing grants require one remote MCP
  # owner approval; do not treat a task-start response as proof of WSS online.
  & $launcher onboard --endpoint 'https://rca.lirtual.dpdns.org/'
  if ($LASTEXITCODE -ne 0) {
    throw 'Authorization incomplete. Identity kept.'
  }
}
# Read a console key directly: PromptForChoice renders system-localized
# help/default text even when its title and choices are English.
# Read-Host can consume piped script input from "irm ... | iex".
function Confirm-Upgrade([object]$ui) {
  Write-Host -NoNewline 'Upgrade? [y/N] '
  try {
    $key = $ui.RawUI.ReadKey('NoEcho,IncludeKeyDown')
  } catch {
    Write-Host ''
    throw 'Interactive approval unavailable. No changes.'
  }
  Write-Host ''
  return [bool]($key.KeyDown -and
    ($key.Character -ceq 'y' -or $key.Character -ceq 'Y'))
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
  $identityFile = [IO.Path]::Combine($root, 'v2-identity.pem')
  $idFile = $identityFile + '.device-id'
  $alreadyPaired = Test-Path -LiteralPath $idFile
  $userTaskName = 'RCA-Remote-Control-v2-' + $userSid.Value.Replace('-', '_')
  $task = Get-ScheduledTask -TaskName $userTaskName -ErrorAction SilentlyContinue
  $upgradeExisting = $false
  if ($alreadyPaired) {
    if (-not (Test-Path -LiteralPath $identityFile -PathType Leaf)) {
      throw 'Existing device ID has no private key; refusing upgrade'
    }
    if (-not $task -or $task.Actions.Count -ne 1) {
      throw 'Existing device has no user-logon task; use explicit device management'
    }
    $oldVersion = Get-ExistingAgentVersion $programs ([string]$task.Actions[0].Execute)
    if ($oldVersion -cne $Version) {
      $oldNumber = [version](($oldVersion.Substring(1) -split '-')[0])
      $newNumber = [version](($Version.Substring(1) -split '-')[0])
      if ($newNumber -le $oldNumber) { throw 'Automatic downgrade or same-version replacement refused' }
      Write-Output ("Agent: {0} -> {1}" -f $oldVersion, $Version)
      Write-Output 'Finish active operations before upgrading.'
      Write-Output ("Task: {0} (state preserved)" -f $task.State)
      # Console key comes from RawUI, not redirected pipeline stdin.
      # Any key other than Y (including Enter) is a safe cancellation.
      if (-not $StageOnly -and -not (Confirm-Upgrade $Host.UI)) {
        Write-Output 'Cancelled. No changes.'
        return
      }
      $upgradeExisting = $true
    }
  } elseif ($task) {
    throw 'Existing user-logon task without an approved local identity; refusing new pairing'
  }
  if ($StageOnly -and -not $upgradeExisting) {
    throw 'Staging requires an existing paired device with a strictly newer target version'
  }
  if (Test-Path -LiteralPath $target) {
    Assert-PrivateFolder $target
    $nodeExisting = [IO.Path]::Combine($target,'bin','node.exe')
    $verifyExisting = [IO.Path]::Combine($target,'apps','remote-control-agent','scripts','verify-windows-preview.mjs')
    & $nodeExisting $verifyExisting $target | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Existing program manifest failed verification' }
    if ($StageOnly) {
      Write-Output ('Verified staging already exists: ' + $Version)
      return
    }
    if ($upgradeExisting) {
      & ([IO.Path]::Combine($target,'rca.cmd')) upgrade --version $Version | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'Upgrade failed. Task kept or restored.' }
      Write-Output 'Upgraded. Checking authorization...'
      Complete-ApprovedOnboarding ([IO.Path]::Combine($target,'rca.cmd'))
      return
    }
    if ($alreadyPaired) {
      $storedId = (Get-Content -LiteralPath $idFile -Raw).Trim()
      if ($storedId -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$') { throw 'Untrusted stored device ID' }
      Write-Output ('Device ID: ' + $storedId)
      Complete-ApprovedOnboarding ([IO.Path]::Combine($target,'rca.cmd'))
      return
    }
    Complete-ApprovedOnboarding ([IO.Path]::Combine($target,'rca.cmd'))
    return
  }
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
  & $node $verifier $stage | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Bundle file manifest failed verification' }
  $manifest = Get-Content -LiteralPath ([IO.Path]::Combine($stage, 'bundle.json')) -Raw | ConvertFrom-Json
  if ($manifest.version -cne $Version) { throw 'Manifest version mismatch' }
  [IO.Directory]::Move($stage, $target)
  $promoted = $true
  Write-Output "Installed: $Version"
  if ($StageOnly) {
    Write-Output ('Verified staging complete; running Agent task unchanged: ' + $Version)
    return
  }
  if ($upgradeExisting) {
    & ([IO.Path]::Combine($target,'rca.cmd')) upgrade --version $Version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Upgrade failed. Task kept or restored.' }
    Write-Output 'Upgraded. Checking authorization...'
    Complete-ApprovedOnboarding ([IO.Path]::Combine($target,'rca.cmd'))
    return
  }
  Complete-ApprovedOnboarding ([IO.Path]::Combine($target,'rca.cmd'))
} finally {
  if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Force }
  if (-not $promoted -and $stage -and (Test-Path -LiteralPath $stage)) {
    Remove-Item -LiteralPath $stage -Recurse -Force
  }
}
