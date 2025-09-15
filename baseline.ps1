<#
  ============================================================================
   WIB Project – Windows Integrity Baseline
   File: scripts/baseline.ps1
   Version: 0.1
   License: MIT



<# 
  Make-Baseline.ps1
  Day-one Windows 11 baseline capture for consumers.
  - Captures: cert stores, installed programs, drivers, services, autoruns, scheduled tasks,
              Secure Boot/TPM/BitLocker status, users/groups, processes, network & DNS,
              event-log counts, core file hashes.
  - Emits: baseline.json + manifest.json (hashes) + raw text helpers.
  - Packages: baseline-<hostname>-<timestamp>.zip
  - Optional upload: provide -UploadUrl (supports PUT to presigned URL or POST to API).
#>

[CmdletBinding()]
param(
  [string]$OutDir = "$env:ProgramData\Baseline",
  [string]$UploadUrl,
  [ValidateSet('PUT','POST')]
  [string]$UploadMethod = 'PUT',
  [string]$ApiKeyHeader = 'x-api-key',
  [string]$ApiKey
)

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Run PowerShell as Administrator for full baseline. Continuing with best effort."
  }
}

function New-OutputFolder {
  $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
  $hostn = $env:COMPUTERNAME
  $path = Join-Path $OutDir "$hostn-$stamp"
  New-Item -ItemType Directory -Path $path -Force | Out-Null
  return $path
}

function Get-CoreFileHashes {
  $paths = @(
    "$env:WinDir\System32\ntoskrnl.exe",
    "$env:WinDir\System32\winload.efi",
    "$env:WinDir\System32\winresume.efi"
  ) | Where-Object { Test-Path $_ }
  $paths | ForEach-Object {
    try { Get-FileHash -Algorithm SHA256 -Path $_ } catch { }
  }
}

function Get-InstalledPrograms {
  $roots = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )
  $items = foreach ($r in $roots) {
    try {
      Get-ItemProperty $r -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString
    } catch {}
  }
  $items | Where-Object { $_.DisplayName } | Sort-Object DisplayName -Unique
}

function Get-CertStoreSnapshot {
  $stores = @(
    "Cert:\LocalMachine\Root",
    "Cert:\LocalMachine\CA",
    "Cert:\LocalMachine\TrustedPublisher",
    "Cert:\CurrentUser\Root",
    "Cert:\CurrentUser\CA",
    "Cert:\CurrentUser\TrustedPublisher"
  )
  $out = @{}
  foreach ($s in $stores) {
    try {
      $out[$s] = (Get-ChildItem -Recurse $s -ErrorAction SilentlyContinue | Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter)
    } catch {
      $out[$s] = @()
    }
  }
  $out
}

function Get-Drivers {
  try {
    Get-CimInstance Win32_PnPSignedDriver |
      Select-Object DeviceName, DriverVersion, Manufacturer, DriverDate, IsSigned, DriverName, InfName, DriverProviderName, FriendlyName, ClassGuid
  } catch { @() }
}

function Get-Services {
  try {
    Get-CimInstance Win32_Service |
      Select-Object Name, DisplayName, State, StartMode, StartName, PathName
  } catch { @() }
}

function Get-Autoruns {
  $keys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  )
  $data = foreach ($k in $keys) {
    try {
      (Get-ItemProperty $k -ErrorAction SilentlyContinue).PSObject.Properties |
        Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") } |
        ForEach-Object { [PSCustomObject]@{Key=$k; Name=$_.Name; Value=$_.Value} }
    } catch {}
  }
  # Startup folders
  $startup = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
  ) | Where-Object { Test-Path $_ }
  $startupEntries = foreach ($p in $startup) {
    Get-ChildItem $p -Force -ErrorAction SilentlyContinue | Select-Object FullName,Name,Length,CreationTime
  }
  [PSCustomObject]@{ Registry=$data; StartupFolders=$startupEntries }
}

function Get-ScheduledTasks {
  try {
    Get-ScheduledTask | ForEach-Object {
      $def = $_ | Get-ScheduledTaskInfo
      [PSCustomObject]@{
        TaskName=$_.TaskName
        Path=$_.TaskPath
        State=$def.State
        LastRunTime=$def.LastRunTime
        NextRunTime=$def.NextRunTime
        NumberOfMissedRuns=$def.NumberOfMissedRuns
        Actions=($_.Actions | Select-Object Execute,Arguments,WorkingDirectory)
        Triggers=($_.Triggers | Select-Object StartBoundary,ScheduleBy)
      }
    }
  } catch { @() }
}

function Get-BootTrust {
  $o = [ordered]@{}
  try { $o.SecureBootEnabled = Confirm-SecureBootUEFI } catch { $o.SecureBootEnabled = $null }
  try { $o.TpmInfoText = (tpmtool.exe getdeviceinformation) -join "`n" } catch { $o.TpmInfoText = $null }
  try { $o.BitLocker = (manage-bde -status) -join "`n" } catch { $o.BitLocker = $null }
  return $o
}

function Get-UsersAndGroups {
  $o = [ordered]@{}
  try { $o.LocalUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon } catch { $o.LocalUsers=@() }
  try { $o.Administrators = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass) } catch { $o.Administrators=@() }
  return $o
}

function Get-NetworkSnapshot {
  $o = [ordered]@{}
  try {
    $o.IPConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,IPv4Address,IPv6Address,IPv4DefaultGateway,DnsServer
  } catch { $o.IPConfig=@() }
  try { $o.DnsServers = Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses } catch { $o.DnsServers=@() }
  try { $o.Routes = Get-NetRoute -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric } catch { $o.Routes=@() }
  try { $o.WinHttpProxy = (netsh winhttp show proxy) -join "`n" } catch { $o.WinHttpProxy=$null }
  return $o
}

function Get-ProcessesLite {
  try { Get-Process | Select-Object Name, Id, Path, StartTime -ErrorAction SilentlyContinue } catch { @() }
}

function Get-EventLogCounts {
  try {
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
      Select-Object LogName, RecordCount, FileSize
  } catch { @() }
}

function Write-Json {
  param($Obj,$Path)
  $json = $Obj | ConvertTo-Json -Depth 6
  [IO.File]::WriteAllText($Path, $json, [Text.Encoding]::UTF8)
}

function Get-SHA256 {
  param($Path)
  (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
}

# MAIN
Assert-Admin
$base = New-OutputFolder
Write-Host "Writing baseline to: $base"

# Collect
$baseline = [ordered]@{
  Hostname       = $env:COMPUTERNAME
  TimestampUtc   = (Get-Date).ToUniversalTime().ToString("o")
  OS             = (Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture)
  CoreFileHashes = Get-CoreFileHashes
  InstalledPrograms = Get-InstalledPrograms
  Certificates   = Get-CertStoreSnapshot
  Drivers        = Get-Drivers
  Services       = Get-Services
  Autoruns       = Get-Autoruns
  ScheduledTasks = Get-ScheduledTasks
  BootTrust      = Get-BootTrust
  UsersAndGroups = Get-UsersAndGroups
  Network        = Get-NetworkSnapshot
  Processes      = Get-ProcessesLite
  EventLogCounts = Get-EventLogCounts
}

# Emit JSON
$baselineJson = Join-Path $base "baseline.json"
Write-Json -Obj $baseline -Path $baselineJson
$baselineHash = Get-SHA256 $baselineJson

# Manifest (simple tamper-evidence)
$manifest = [ordered]@{
  BaselineFile = (Split-Path $baselineJson -Leaf)
  BaselineSHA256 = $baselineHash
  CreatedUtc = (Get-Date).ToUniversalTime().ToString("o")
  Computer = $env:COMPUTERNAME
}
$manifestJson = Join-Path $base "manifest.json"
Write-Json -Obj $manifest -Path $manifestJson

# Extra raw captures for transparency
try { $baseline.BootTrust.TpmInfoText | Out-File (Join-Path $base "tpmtool.txt") -Encoding utf8 } catch {}
try { $baseline.BootTrust.BitLocker    | Out-File (Join-Path $base "bitlocker.txt") -Encoding utf8 } catch {}
try { $baseline.Network.WinHttpProxy   | Out-File (Join-Path $base "proxy.txt") -Encoding utf8 } catch {}

# Package
$zipPath = Join-Path $OutDir ("baseline-{0}-{1}.zip" -f $env:COMPUTERNAME, (Get-Date).ToString("yyyyMMdd-HHmmss"))
Compress-Archive -Path (Join-Path $base "*") -DestinationPath $zipPath -Force
$zipHash = Get-SHA256 $zipPath
$zipHash | Out-File (Join-Path $base "archive.sha256") -Encoding ascii

Write-Host "Created archive: $zipPath"
Write-Host "Archive SHA256: $zipHash"

# Optional upload
if ($UploadUrl) {
  try {
    Write-Host "Uploading archive to $UploadUrl using $UploadMethod ..."
    if ($UploadMethod -eq 'PUT') {
      Invoke-WebRequest -Uri $UploadUrl -Method Put -InFile $zipPath -UseBasicParsing | Out-Null
    } else {
      $headers = @{}
      if ($ApiKey) { $headers[$ApiKeyHeader] = $ApiKey }
      Invoke-RestMethod -Uri $UploadUrl -Method Post -Headers $headers -InFile $zipPath -ContentType "application/zip" | Out-Null
    }
    Write-Host "Upload complete."
  } catch {
    Write-Warning "Upload failed: $($_.Exception.Message)"
  }
}

Write-Host "Done. Keep the archive + .sha256 as your day-one baseline."