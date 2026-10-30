# Spec #505: fixed, noninteractive Windows screenshot helper (primary display).
# No remote command, path, process, or arbitrary script input is accepted.
$ErrorActionPreference = 'Stop'
try {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class DesktopGate505 {
 [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint desiredAccess);
 [DllImport("user32.dll", SetLastError=true)] public static extern bool GetUserObjectInformation(IntPtr handle, int index, StringBuilder info, int length, out int needed);
 [DllImport("user32.dll", SetLastError=true)] public static extern bool CloseDesktop(IntPtr handle);
}
'@
  $desktop = [DesktopGate505]::OpenInputDesktop(0,$false,1)
  if ($desktop -eq [IntPtr]::Zero) { exit 10 }
  try {
    $name = New-Object System.Text.StringBuilder 128
    $needed = 0
    if (-not [DesktopGate505]::GetUserObjectInformation($desktop,2,$name,$name.Capacity,[ref]$needed)) { exit 10 }
    if ($name.ToString() -cne 'Default') { exit 10 }
  } finally { [void][DesktopGate505]::CloseDesktop($desktop) }
  $screen = [System.Windows.Forms.Screen]::PrimaryScreen
  if ($null -eq $screen) { exit 11 }
  $bounds = $screen.Bounds
  if ($bounds.Width -le 0 -or $bounds.Height -le 0 -or $bounds.Width -gt 16384 -or $bounds.Height -gt 16384) { exit 11 }
  $factor = [Math]::Min(1.0,[Math]::Min(1600.0 / $bounds.Width,1600.0 / $bounds.Height))
  $width = [Math]::Max(1,[int][Math]::Round($bounds.Width*$factor))
  $height = [Math]::Max(1,[int][Math]::Round($bounds.Height*$factor))
  $original = New-Object System.Drawing.Bitmap($bounds.Width,$bounds.Height)
  try {
    $graphics = [System.Drawing.Graphics]::FromImage($original)
    try { $graphics.CopyFromScreen($bounds.X,$bounds.Y,0,0,$bounds.Size) }
    finally { $graphics.Dispose() }
    $scaled = New-Object System.Drawing.Bitmap($width,$height)
    try {
      $draw = [System.Drawing.Graphics]::FromImage($scaled)
      try {
        $draw.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $draw.DrawImage($original,0,0,$width,$height)
      } finally { $draw.Dispose() }
      $stream = New-Object System.IO.MemoryStream
      try {
        $scaled.Save($stream,[System.Drawing.Imaging.ImageFormat]::Jpeg)
        $bytes = $stream.ToArray()
        if ($bytes.Length -lt 8 -or $bytes.Length -gt 524288) { exit 12 }
        [pscustomobject]@{
          data = [Convert]::ToBase64String($bytes)
          width = $width
          height = $height
          native_width = $bounds.Width
          native_height = $bounds.Height
          origin_x = $bounds.X
          origin_y = $bounds.Y
          session_id = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        } | ConvertTo-Json -Compress -Depth 2
      } finally { $stream.Dispose() }
    } finally { $scaled.Dispose() }
  } finally { $original.Dispose() }
} catch { exit 15 }
