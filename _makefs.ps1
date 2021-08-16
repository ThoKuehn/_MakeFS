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
#>
[CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)][string]$oldserver,                                                               # Name of the old server
    [Parameter(Mandatory = $true)][string]$shareroot,                                                               # make sure all sub folders are readable to user running script
    [Parameter(Mandatory = $false)][string[]]$folderlist = @("Gruppenablage","usershome","images","usersprofile"),  # DO NOT COPY WORKFOLDERS! LET THE CLIENTS SYNC BACK!!
    [Parameter(Mandatory = $false)][string]$newpath = "E:\fileserv",                                                # location of files on new server
    [Parameter(Mandatory = $false)][string]$serverlogheader = "$PSScriptRoot\serverlog-header.txt"                  # default is a file in script folder
  )

#ab hier finger weg
# #fingerab
$logfolder              = "C:\logs"
$LogFile                = $logfolder + "\" + $($MyInvocation.MyCommand.Name)
$roboparams             = @('/COPYALL', '/MIR', '/MT:128', '/COPY:DATSOU', '/DCOPY:DAT', '/DST', '/R:1', '/W:2', '/NC', '/NP', '/J', '/SEC', '/B')
$serverlogfile          = $env:ProgramData + "\Microsoft\Windows\Start Menu\Programs\StartUp\servlog.txt"
$serverlogheadercontent = Get-Content -Path $serverlogheader

#region functions
function Write-Log
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    $message,
    [Parameter(Mandatory = $false)]
    [ValidateSet('INFO', 'WARN', 'ERROR')]
    [string]
    $level = 'HINT',
    [Parameter(Mandatory = $false)]
    [string]
    $Log = $LogFile
  )
  if ($level -eq 'INFO')
  {
    [System.ConsoleColor]$color = 'Green'
  }
  elseif ($level -eq 'WARN')
  {
    [System.ConsoleColor]$color = 'Yellow'
  }
  elseif ($level -eq 'ERROR')
  {
    [System.ConsoleColor]$color = 'Red'
  }
  else
  {
    [System.ConsoleColor]$color = 'White'
  }
  $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $output = $date + " " + $level + " : " + $message
  Write-Host -Object $output -ForegroundColor $color
  Out-File -InputObject $output -FilePath $LogFile -Encoding utf8
}
#endregion functions

#region main

# starting script
Clear-Host

# create log folder
if (-not (Test-Path "$logfolder"))
{
  try
  {
    New-Item -Path "$logfolder" -ItemType Directory -Force
  }
  catch
  {
    Write-Host "ERROR: Unable to create Log and Temp Folder $logfolder"
    Pause
    exit 1
  }
  Write-Log "Log folder created" -level INFO
}

Write-Log -message "Starting script execution" -level INFO
Write-Log -message "Log files location is: $logfolder" -level INFO

# Create server log
if (-not (Test-Path "$serverlogfile" -PathType Leaf))
{
  Write-Log -message "Starting serverlog creation setting file permission" -level INFO
  try
  {
    New-Item -Path "$serverlogfile" -ItemType File -Force 
    Out-File -InputObject $serverlogheadercontent -FilePath "$serverlogfile"
    Start-Process -FilePath "$env:windir\System32\icacls.exe" -ArgumentList "`"$serverlogfile`" /grant *S-1-5-32-545:M"
    Write-Log -message "Serverlog created" -level INFO
  }
  catch
  {
    Write-Log -message "Unable to create $serverlogfile" -level ERROR
  }
}else{
  Write-Log -message "'$serverlogfile' already exists. Checking permissions" -level INFO
  Start-Process -FilePath "$env:windir\System32\icacls.exe" -ArgumentList "`"$serverlogfile`" /grant *S-1-5-32-545:M"
}

# remove unwanted/unsafe features
Write-Log -message "Uninstall-WindowsFeature -name XPS-Viewer, PowerShell-v2, FS-SMB1-Client, FS-SMB1-Server, FS-SMB1 -LogPath `"$logfolder\Uninstall-WindowsFeature.log`"" -level INFO
Uninstall-WindowsFeature -name XPS-Viewer, PowerShell-v2, FS-SMB1-Client, FS-SMB1-Server, FS-SMB1 -LogPath "$logfolder\Uninstall-WindowsFeature.log"

# install needed features and restart server afterwards
Write-Log -message "Install-WindowsFeature -name FS-Fileserver, FS-SyncShareService, FS-Ressource-Manager, DHCP, Print-Server, Web-Mgmt-Console, Web-Scripting-Tools, RSAT-DHCP, RSAT-FSRM-Mgmt, RSAT-Print-Services, RSAT-ADDS-Tools, RSAT-AD-PowerShell, GPMC, Remote-Assistance -LogPath `"$logfolder\Install-WindowsFeature.log`"" -level INFO
Install-WindowsFeature -name FS-Fileserver, FS-SyncShareService, FS-Ressource-Manager, DHCP, Print-Server, Web-Mgmt-Console, Web-Scripting-Tools, RSAT-DHCP, RSAT-FSRM-Mgmt, RSAT-Print-Services, RSAT-ADDS-Tools, RSAT-AD-PowerShell, GPMC, Remote-Assistance -LogPath "$logfolder\Install-WindowsFeature.log"

# copy folder structure with permissions
Write-Log -message "Starting copy process of old server to new server" -level INFO
if (-not(Test-Path $newpath))
{
  Write-Log -message "New-Item -Path '$newpath' -ItemType Directory -Force" -level INFO
  New-Item -Path "$newpath" -ItemType Directory -Force
}

Write-Log -message "Each folder has its own log file for copied directories and files" -level INFO
foreach ($folder in $folderlist)
{
  # shared folder on on old server
  $old = '\\'+$oldserver +'\\'+ $shareroot + '\' + $folder

  # check if source is available, if not stop working on it
  if (-not(Test-Path -Path $old -PathType Container))
  {
    $message = "Unable to access '" + $old + "'"
    Write-Log $message -level ERROR
  }
  else
  {
    # new local folder with share name
    $new = $newpath + "\" + $folder

    # log file for each share
    $rLogFile = $logfolder + "\" + $folder + ".log"

    # add log file location to robocopy params
    $arguments = $roboparams + "/UNILOG+:$rLogFile"

    # new folder name is the same as old folder name
    $message = "Starting copy '" + $old + "' -> '" + $new + "'"
    Write-Log $message -level INFO
    Write-Log -message "Logfile is: $rLogFile" -level INFO
    Write-Log -message "Start-Process -Wait -FilePath `"$env:windir\System32\Robocopy.exe`" -ArgumentList `"$old $new $arguments`"" -level INFO
    Start-Process -Wait -FilePath "$env:windir\System32\Robocopy.exe" -ArgumentList "$old $new $arguments"
    $message = "Finished copy '" + $old + "' -> '" + $new + "'"
    Write-Log -message $message -level INFO 
  }
}

# print server migration

# tool is part of server role, so check if tool is available is necessary before run

$tool = "C:\windows\system32\spool\tools\PrintBrm.exe"
if (-not (Test-Path -Path $tool -PathType Leaf)){
    Write-Log -message "PrintBrm.exe not found. No print server migration" -level WARN
}else{
    $printshare = '\\'+$oldserver+'\print$'
    if (-not (Test-Path -Path $printshare -PathType Container)){
        Write-Log "`$print share on old server not reachable" -level ERROR
    }else{
        Set-Location -Path $(Split-Path -Path $tool -Parent)
        $printbrmbackup = $logfolder+'\'+$oldserver+".printerExport"
        Write-Log -message "Starting print server migration" -level INFO
        if (Test-Path -Path $printbrmbackup -PathType Leaf){
            Write-Log -message "Removing existing"
            Remove-item -Path $printbrmbackup -Force
        }
        $export = & .\$(Split-Path -Path $tool -Leaf) -S "$oldserver" -B -F "$printbrmbackup" -O FORCE
        $exportfile = $logfolder+'\printbrm-export.log'
        Out-File -FilePath $exportfile -InputObject $export -Encoding utf8
        $import = & .\$(Split-Path -Path $tool -Leaf) -R -F "$printbrmbackup" -O FORCE
        $importfile = $logfolder+'\printbrm-import.log'
        Out-File -FilePath $importfile -InputObject $import -Encoding utf8
    }
}

#endregion main
