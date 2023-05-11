#Requires -runasadministrator
<#
  _makefs.ps1

  create standardized file-server with
  - Fileservice
  - SyncShareService
  - Print-Service
  - DHCP
  - RSAT-Tools for roles and Active Directory
  - Sync Folders from old system to new
  - Print Server Migration
  - DHCP Server Migration
  - Computer certificate request for work folder service
#>

# Read JSON file
$JsonFilePath = "parameters.json"
$Parameters = Get-Content -Path $JsonFilePath | ConvertFrom-Json

# Assign parameters from JSON object
$oldserver = $Parameters.oldserver
$Serverlog = $Parameters.Serverlog
$serverlogheader = $Parameters.serverlogheader
$FileService = $Parameters.FileService
$sharelist = $Parameters.sharelist
$newpath = $Parameters.newpath
$createshare = $Parameters.createshare
$InstallWindowsFeatures = $Parameters.InstallWindowsFeatures
$UninstallWindowsFeatures = $Parameters.UninstallWindowsFeatures
$PrintService = $Parameters.PrintService
$DHCPService = $Parameters.DHCPService
$Certificate = $Parameters.Certificate
$FQDN = $Parameters.FQDN
$Mail = $Parameters.Mail
$Organization = $Parameters.Organization
$OrganizationalUnit = $Parameters.OrganizationalUnit
$City = $Parameters.City
$State = $Parameters.State
$Country = $Parameters.Country
$All = $Parameters.All
$logfolder = $Parameterslogfolder
$LogFile = $logfolder + "\" + $($($MyInvocation.MyCommand.Name).Replace('.ps1', '.log'))
$roboparams = $Parametersroboparams
$serverlogfile = $Parametersserverlogfile.Replace("%ProgramData%", $env:ProgramData)
$serverlogheader = $Parametersserverlogheader
$serverlogheadercontent = Get-Content -Path $serverlogheader
# Rest of the script


#########################################
#
# no changes beyond this point
#

#region functions
function Write-Log {
  [CmdletBinding(DefaultParameterSetName = 'Default')]
  param (
      [Parameter(Mandatory = $true)]
      [string]$message,
      [Parameter(ParameterSetName = 'Default')]
      [ValidateSet('INFO', 'WARN', 'ERROR')]
      [string]$level = 'HINT',
      [Parameter()]
      [string]$Log = $LogFile
  )

  switch ($level) {
      'INFO'  { $color = 'Green' }
      'WARN'  { $color = 'Yellow' }
      'ERROR' { $color = 'Red' }
      default { $color = 'White' }
  }

  $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $output = $date + " " + $level + " : " + $message
  Write-Host -Object $output -ForegroundColor $color
  Add-Content -Path $Log -Value $output -Encoding utf8
}
#endregion functions

#region main

# starting script
Clear-Host

# create log folder
if (-not (Test-Path -Path $logfolder)) {
  try {
      $null = New-Item -Path $logfolder -ItemType Directory -Force
      Write-Log -message "Log folder created" -level INFO
  }
  catch {
      Write-Host "ERROR: Unable to create Log and Temp Folder $logfolder"
      Pause
      exit 1
  }
}

Write-Log -message "Starting script execution" -level INFO
Write-Log -message "Log files location is: $logfolder" -level INFO

#region serverlog
if ($Serverlog.IsPresent -or $All.IsPresent) {
  if (-not (Test-Path -Path $serverlogfile -PathType Leaf)) {
      Write-Log -message "Starting serverlog creation and setting file permission" -level INFO
      try {
          $null = New-Item -Path $serverlogfile -ItemType File -Force
          Set-Content -Path $serverlogfile -Value $serverlogheadercontent
          Start-Process -FilePath "$env:windir\System32\icacls.exe" -ArgumentList "`"$serverlogfile`" /grant *S-1-5-32-545:M"
          Write-Log -message "Serverlog created" -level INFO
      }
      catch {
          Write-Log -message "Unable to create $serverlogfile" -level ERROR
      }
  }
  else {
      Write-Log -message "'$serverlogfile' already exists. Setting permissions to User:M" -level INFO
      Start-Process -FilePath "$env:windir\System32\icacls.exe" -ArgumentList "`"$serverlogfile`" /grant *S-1-5-32-545:M"
  }
}
else {
  Write-Log -message "Skipping Serverlog creation" -level INFO
}

#endregion serverlog

#region windowsRaF
if ($InstallWindowsFeatures.IsPresent -and $UninstallWindowsFeatures.IsPresent) {
  Write-Log -message "Currently it is not possible to uninstall and install windows roles and features in the same run. Please restart with just one parameter specified" -level ERROR
  break
}

if ($UninstallWindowsFeatures.IsPresent) {
  # remove unwanted/unsafe features
  $uninstallFeatures = @('PowerShell-v2', 'FS-SMB1-Client', 'FS-SMB1-Server', 'FS-SMB1')
  $uninstallLogPath = "$logfolder\Uninstall-WindowsFeature.log"

  Write-Log -message "Uninstall-WindowsFeature -Name $($uninstallFeatures -join ',') -LogPath `"$uninstallLogPath`"" -level INFO

  $uninstJob = Start-Job -Command {
      param($features, $logPath)
      Uninstall-WindowsFeature -Name $features -LogPath $logPath
  } -ArgumentList $uninstallFeatures, $uninstallLogPath

  Receive-Job -Job $uninstJob -Wait | Select-Object Success, RestartNeeded, exitCode, FeatureResult

  # reboot system
  Write-Log -message "Restarting server to disable roles and features" -level INFO
  $shutdownReason = 0x84020004
  Restart-Computer -Force -Reason 'Uninstall Windows roles and features' -ShutdownEventTrackerReasonCode $shutdownReason
}
else {
  Write-Log -message "Skipping Disabling Windows roles and features" -level INFO
}

if ($InstallWindowsFeatures.IsPresent) {
  # install needed features and restart server afterwards
  $installFeatures = @(
      'FS-Fileserver', 'FS-SyncShareService', 'FS-Resource-Manager', 'DHCP',
      'Print-Server', 'Web-Mgmt-Console', 'Web-Scripting-Tools', 'RSAT-DHCP',
      'RSAT-FSRM-Mgmt', 'RSAT-Print-Services', 'RSAT-ADDS-Tools', 'RSAT-AD-PowerShell',
      'GPMC', 'Remote-Assistance'
  )
  $installLogPath = "$logfolder\Install-WindowsFeature.log"

  Write-Log -message "Install-WindowsFeature -Name $($installFeatures -join ',') -LogPath `"$installLogPath`"" -level INFO

  $instJob = Start-Job -Command {
      param($features, $logPath)
      Install-WindowsFeature -Name $features -LogPath $logPath
  } -ArgumentList $installFeatures, $installLogPath

  Receive-Job -Job $instJob -Wait | Select-Object Success, RestartNeeded, exitCode, FeatureResult

  # reboot system
  Write-Log -message "Restarting server to enable roles and features" -level INFO
  $shutdownReason = 0x84020004
  Restart-Computer -Force -Reason 'Install Windows roles and features' -ShutdownEventTrackerReasonCode $shutdownReason
}
else {
  Write-Log -message "Skipping Enabling Windows roles and features" -level INFO
}

#endregion windowsRaF

#region fileservice
if ($FileService.IsPresent -or $All.IsPresent) {
  # Copy folder structure with permissions
  Write-Log -message "Starting copy process of '$oldserver' to '$newpath'" -level INFO

  if (-not (Test-Path $newpath)) {
      try {
          Write-Log -message "Creating directory '$newpath'" -level INFO
          New-Item -Path $newpath -ItemType Directory -Force | Out-Null
      }
      catch {
          Write-Log "Unable to create path" -level ERROR
          exit 1
      }
  }

  Write-Log -message "Each share has its own log file for copied directories and files" -level INFO

  foreach ($share in $sharelist) {
      # Shared folder on old server
      $old = '\\' + $oldserver + '\' + $share

      # Check if source is available, if not stop working on it
      if (-not (Test-Path -Path $old -PathType Container)) {
          $message = "Unable to access '$old'"
          Write-Log $message -level ERROR
          continue
      }

      # Get share on old server
      $oShare = Get-CimInstance -ComputerName $oldserver -ClassName win32_share -Filter "Name = '$share'"

      # Folder name and description
      $folder = Split-Path -Path $oShare.Path -Leaf
      $description = $oShare.Description

      # If complete disks (administrative Shares [LW]$) are copied
      if ($folder -match '([A-Z]|[a-z])\:\\' ) {
          $folder = $folder.TrimEnd(':\')
          $createshare = $false
      }

      # New local folder with share name
      $new = Join-Path -Path $newpath -ChildPath $folder

      # Date for log file
      $sDate = Get-Date -Format 'yyyy-MM-dd_hh-mm'

      # Log file for each share
      if ($folder.Length -eq 1) {
          $rLogFile = Join-Path -Path $logfolder -ChildPath "$sDate`_disk_$folder.log"
      }
      else {
          $rLogFile = Join-Path -Path $logfolder -ChildPath "$sDate`_$folder.log"
      }

      # Add log file location to robocopy params
      $arguments = $roboparams + "/UNILOG+:$rLogFile"

      # Start copy process
      $message = "Starting copy '$old' -> '$new'"
      Write-Log $message -level INFO
      Write-Log -message "Logfile is: $rLogFile" -level INFO
      Write-Log -message "Robocopy command: Start-Process -NoNewWindow -Wait -FilePath `"$env:windir\System32\Robocopy.exe`" -ArgumentList `"$old`" `"$new`" $arguments" -level INFO
      Start-Process -NoNewWindow -Wait -FilePath "$env:windir\System32\Robocopy.exe" -ArgumentList "`"$old`" `"$new`" $arguments"
      $message = "Finished copy '$old' -> '$new'"
      Write-Log -message $message -level INFO

      # Share new folder
      if ($createshare -eq $false) {
          $message = "Skipping sharing of '$new'"
          Write-Log -message $message -level INFO
      }
      else {
          if (-not (Get-SmbShare -Name $share)) {
            $message = "Creating share '$share' for '$new'"
            Write-Log -message $message -level INFO
            $message = "New-SmbShare -Name $share -Path "$new" -Description "$Description" -FolderEnumerationMode AccessBased -CachingMode None -FullAccess "Everyone""
            Write-Log -message $message -level INFO
            try {
            New-SmbShare -Name $share -Path $new -Description $description -FolderEnumerationMode AccessBased -CachingMode None -FullAccess "Everyone"
            }
            catch {
            $message = "Unable to create share. Error: $_"
            Write-Log -message $message -level ERROR
            }
            }
            else {
            $message = "Creating share '$share' for '$new' failed. Share name already exists."
            Write-Log -message $message -level ERROR
            }
            }
            }
            }
            else {
            Write-Log -message "Skipping File service migration" -level INFO
            }
#endregion fileservice

#region printservice
if (($PrintService.IsPresent -eq $true) -or ($All.IsPresent -eq $true)) {
  # print server migration

  # tool is part of server role, so check if tool is available is necessary before run
  $tool = "C:\windows\system32\spool\tools\PrintBrm.exe"
  if (-not (Test-Path -Path $tool -PathType Leaf)) {
    Write-Log -message "PrintBrm.exe not found. No print server migration" -level WARN
  }
  else {
    $printshare = '\\' + $oldserver + '\print$'
    if (-not (Test-Path -Path $printshare -PathType Container)) {
      Write-Log "`$print share on old server not reachable" -level ERROR
    }
    else {
      $cpath = Get-Location
      Set-Location -Path $(Split-Path -Path $tool -Parent)
      $printbrmbackup = $logfolder + '\' + $oldserver + ".printerExport"
      Write-Log -message "Starting print server migration" -level INFO
      if (Test-Path -Path $printbrmbackup -PathType Leaf) {
        Write-Log -message "Removing existing"
        Remove-Item -Path $printbrmbackup -Force
      }
      $export = & .\$(Split-Path -Path $tool -Leaf) -S "$oldserver" -B -F "$printbrmbackup" -O FORCE
      $exportfile = $logfolder + '\printbrm-export.log'
      Out-File -FilePath $exportfile -InputObject $export -Encoding utf8
      $import = & .\$(Split-Path -Path $tool -Leaf) -R -F "$printbrmbackup" -O FORCE
      $importfile = $logfolder + '\printbrm-import.log'
      Out-File -FilePath $importfile -InputObject $import -Encoding utf8
      Set-Location $cpath.path
    }
  }
}
else {
  Write-Log -message "Skipping print service migration" -level INFO
}
#endregion printservice

#region DHCP
if (($DHCPService.IsPresent -eq $true) -or ($All.IsPresent -eq $true)) {
  $dhcpbackup = $logfolder + '\' + $oldserver + "_DHCP.xml"
  Write-Log -message "Starting migrating DHCP configuration" -level INFO
  try {
    Export-DhcpServer -ComputerName $oldserver -File $dhcpbackup -Force
    try {
      Import-DhcpServer -File $dhcpbackup -BackupPath $env:TEMP
    }
    catch {
      Write-Log -message "Import of DHCP configuration failed"
    }
  }
  catch {
    Write-Log -message "Export of DHCP configuration failed"
  }
  Write-Log -message "End migrating DHCP configuration" -level INFO
}
else {
  Write-Log -message "Skipping DHCP service migration" -level INFO
}
#endregion DHCP

#region certificate
if (($Certificate.IsPresent -eq $true) -or ($All.IsPresent -eq $true)) {
  # generate INF for request with specified variables
  Write-Log -message "Generating certificate request" -level INFO
  $INFFile = $logfolder + '\' + $FQDN + '_' + $((Get-Date).ToString('yyyyMMdd')) + '.INF'
  $REQFile = $logfolder + '\' + $FQDN + '_' + $((Get-Date).ToString('yyyyMMdd')) + '_CSR.REQ'

  $Signature = '$Windows NT$'
  $SANList = @("dns=$CertName")

  $INF = @"
  [Version]
  Signature= "$Signature"

  [NewRequest]
  Exportable = TRUE                                                      ; TRUE = Private key is exportable
  KeyLength = 256                                                        ; Valid key sizes: 256,384,512
  KeySpec = 1                                                            ; Key Exchange – Required for encryption
  MachineKeySet = TRUE                                                   ; The default is false.
  PrivateKeyArchive = FALSE                                              ; The PrivateKeyArchive setting works only if the corresponding RequestType is set to "CMC"
  ProviderName = "Microsoft Software Key Storage Provider"
  ProviderType = 23                                                      ; nistP256
  RequestType = PKCS10                                                   ; Determines the standard that is used to generate and send the certificate request (PKCS10 -- 1)
  SMIME = False                                                          ; Refer to symmetric encryption algorithms that may be used by Secure Multipurpose Internet Mail Extensions (S/MIME)
  Subject = "E=$Mail, CN=$FQDN, OU=$OrganizationalUnit, O=$Organization, L=$City, S=$State, C=$Country"
  UseExistingKeySet = FALSE
  UserProtected = FALSE

  [Extensions]
  ; If your client operating system is Windows Server 2008, Windows Server 2008 R2, Windows Vista, or Windows 7
  ; SANs can be included in the Extensions section by using the following text format. Note 2.5.29.17 is the OID for a SAN extension.
  ; Multiple alternative names must be separated by an ampersand (&).
  2.5.29.17 = "{text}"
"@
  $SANList | ForEach-Object { $INF += "_continue_ = `"$($_)&`"`r`n" }
  $INF += "`r`n; EOF`r`n"

  $INF | Out-File -FilePath $INFFile -Force
  & certreq.exe -New $INFFile $REQFile

  Write-Log -message "Certificate Request has been generated" -level INFO
}
else {
  Write-Log -message "Skipping certificate generation" -level INFO
}
#endregion certificate

Write-Log -message "End script execution" -level INFO
#endregion main
