# Windows ISO Debloater
# Author: itsNileshHere
# Date: 2023-11-21
# Description: A simple PSscript to modify windows iso file. For more info check README.md

# Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    Exit
}
Clear-Host
$asciiArt = @"
 _       ___           __                      _________ ____     ____       __    __            __           
| |     / (_)___  ____/ /___ _      _______   /  _/ ___// __ \   / __ \___  / /_  / /___  ____ _/ /____  _____
| | /| / / / __ \/ __  / __ \ | /| / / ___/   / / \__ \/ / / /  / / / / _ \/ __ \/ / __ \/ __ `/ __/ _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / |/ |/ (__  )  _/ / ___/ / /_/ /  / /_/ /  __/ /_/ / / /_/ / /_/ / /_/  __/ /    
|__/|__/_/_/ /_/\__,_/\____/|__/|__/____/  /___//____/\____/  /_____/\___/_.___/_/\____/\__,_/\__/\___/_/     
                                                                                        -By itsNileshHere                                                                                                  
"@

Write-Host $asciiArt -ForegroundColor Cyan
Start-Sleep -Milliseconds 1200
Write-Host "Starting Windows ISO Debloater Script..." -ForegroundColor Green
Start-Sleep -Milliseconds 1500
Write-Host "`n*Importent Notes: " -ForegroundColor Yellow
Write-Host "    1. There will be some prompts for the user." -ForegroundColor White
Write-Host "    2. Ensure that you have administrative privileges to run this script." -ForegroundColor White
Write-Host "    3. Review the script before execution to understand its actions." -ForegroundColor White
Write-Host "    4. If you want to whitelist any package, just open the script and comment out the Packagename." -ForegroundColor White
Start-Sleep -Milliseconds 1500

$scriptDirectory = "$PSScriptRoot"
$logFilePath = Join-Path -Path $scriptDirectory -ChildPath 'script_log.txt'

# Log File
function Write-LogMessage {
    param (
        [string]$message
    )
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    Add-Content -Path "$logFilePath" -Value $logEntry
}

# Cleanup Function
function Remove-TempFiles {
    Remove-Item -Path $destinationPath -Recurse -Force > $null 2>&1
    Remove-Item -Path $installMountDir -Recurse -Force > $null 2>&1
    Remove-Item -Path "$env:SystemDrive\WIDTemp" -Recurse -Force > $null 2>&1
}

# Force Remove Function
function Set-OwnAndRemove {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $FullPath = Resolve-Path -Path $Path -ErrorAction Stop
    }
    catch {
        return
    }

    if (Test-Path -Path $FullPath) {
        if ((Get-Item $FullPath).PSIsContainer) {
            takeown /F "$FullPath" /R /D Y > $null 2>&1
            icacls "$FullPath" /grant:R Administrators:F /T /C > $null 2>&1
        }
        else {
            takeown /F "$FullPath" /A > $null 2>&1
            icacls "$FullPath" /grant:R Administrators:F > $null 2>&1
        }
        Remove-Item -Path "$FullPath" -Recurse -Force > $null 2>&1
    }
}

# Image Info Function
function Get-WimInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$MountPath
    )
    $out = dism /Image:$MountPath /Get-Intl | Out-String
    [PSCustomObject]@{
        BuildNumber = if ($out -match "Image Version: \d+\.\d+\.(\d+)\.\d+") { $matches[1] } else { $null }
        Language    = if ($out -match "Default system UI language : ([a-z]{2}-[A-Z]{2})") { $matches[1] } else { $null }
    }
}

# Autounattend.xml Path
$autounattendXmlPath = Join-Path -Path $scriptDirectory -ChildPath "Autounattend.xml"

Write-LogMessage "Script started"
Write-Host

# Mount ISO Dialog
Add-Type -AssemblyName System.Windows.Forms
$openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
$openFileDialog.Filter = "ISO files (*.iso)|*.iso"
$openFileDialog.Title = "Select Windows ISO File"

if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $isoFilePath = $openFileDialog.FileName
    Write-Host "Selected ISO file: $isoFilePath"
    Write-LogMessage "ISO Path: $isoFilePath"
    $mountResult = Mount-DiskImage -ImagePath "$isoFilePath" -PassThru
    if ($mountResult) {
        $sourceDriveLetter = ($mountResult | Get-Volume).DriveLetter
        if ($sourceDriveLetter) {
            Write-LogMessage "Mounted ISO file to drive: $sourceDriveLetter`:"
        }
    }
    else {
        Write-Host "Failed to mount the ISO file." -ForegroundColor Red
        Write-LogMessage "Failed to mount the ISO file."
        Exit
    }
}
else {
    Write-Host "No file selected. Exiting Script" -ForegroundColor Red
    Write-LogMessage "No file selected"
    Exit
}

$sourceDrive = "${sourceDriveLetter}:\" # Source Drive of ISO
$destinationPath = "$env:SystemDrive\WIDTemp\winlite"   # Destination Path
$installMountDir = "$env:SystemDrive\WIDTemp\mountdir\installWIM"   # Mount Directory

# Copy Files
Write-Host "`nCopying files from $sourceDrive to $destinationPath"
Write-LogMessage "Copying files from $sourceDrive to $destinationPath"
$null = New-Item -ItemType Directory -Path $destinationPath
$null = xcopy.exe $sourceDrive $destinationPath /E /I /H /R /Y /J
Dismount-DiskImage -ImagePath "$isoFilePath" > $null 2>&1

# Check files availability
$installWimPath = Join-Path $destinationPath "sources\install.wim"
$installEsdPath = Join-Path $destinationPath "sources\install.esd"
New-Item -ItemType Directory -Path $installMountDir > $null 2>&1

# Handling install.wim and install.esd
if (-not (Test-Path $installWimPath)) {
    Write-Host "`ninstall.wim not found. Searching for install.esd..."
    Start-Sleep -Milliseconds 500
    if (Test-Path $installEsdPath) {
        Write-Host "`ninstall.esd found at $installEsdPath."
        Write-LogMessage "install.esd found. Converting..."
        Start-Sleep -Milliseconds 500
        try {
            dism /Get-WimInfo /wimfile:$installEsdPath
            Write-Host
            $EsdIndex = Read-Host -Prompt "Enter the index to convert and mount"
            Write-LogMessage "Converting and Mounting image: $EsdIndex"
            dism /Export-Image /SourceImageFile:$installEsdPath /SourceIndex:$EsdIndex /DestinationImageFile:$installWimPath /Compress:max /CheckIntegrity
            Remove-Item $installEsdPath -Force
            dism /mount-image /imagefile:$installWimPath /index:1 /mountdir:$installMountDir
        }
        catch {
            Write-LogMessage "Failed to mount image: $_"
            Exit
        }
    }
    else {
        Write-Host "Neither install.wim nor install.esd found. Make sure to mount the correct ISO"  -ForegroundColor Red
        Exit
    }
}
else {
    Write-Host "`nDetails for image: $installWimPath"
    Write-LogMessage "Getting image info"
    $WimInfo = dism /Get-WimInfo /wimfile:$installWimPath 2>$null | Where-Object { $_ -match "^(Index : |Name : )" } | ForEach-Object { $_.Trim() }
    for ($i = 0; $i -lt $WimInfo.Count; $i += 2) {
        $Index = $WimInfo[$i] -replace "Index : "
        $Name = $WimInfo[$i+1] -replace "Name : "
        "$Index. $Name"
    }
    Write-Host
    $WimIndex = Read-Host -Prompt "Enter the index to mount"
    Write-LogMessage "Mounting image: $WimIndex"
    
    try {
        dism /mount-image /imagefile:$installWimPath /index:$WimIndex /mountdir:$installMountDir
    }
    catch {
        Write-LogMessage "Failed to mount image: $_"
        Exit
    }
}

if (-not (Test-Path "$installMountDir\Windows")) {
    Write-Host "Error while mounting image. Try again." -ForegroundColor Red
    Write-LogMessage "Mounted image not found. Exiting"
    Remove-TempFiles
    Exit 
}

# Resolve Image Info
$WimInfo = Get-WimInfo -MountPath $installMountDir
$langCode = $WimInfo.Language
$buildNumber = $WimInfo.BuildNumber

# Comment out the package don't wanna remove
$appxPatternsToRemove = @(
    "Microsoft.Microsoft3DViewer*", # 3DViewer
    "Microsoft.WindowsAlarms*", # Alarms
    "Microsoft.BingNews*", # Bing News
    "Microsoft.BingWeather*", # Bing Weather
    "Clipchamp.Clipchamp*", # Clipchamp
    "Microsoft.549981C3F5F10*", # Cortana
    "Microsoft.Windows.DevHome*", # DevHome
    "MicrosoftCorporationII.MicrosoftFamily*", # Family
    "Microsoft.WindowsFeedbackHub*", # FeedbackHub
    "Microsoft.GetHelp*", # GetHelp
    "Microsoft.Getstarted*", # GetStarted
    "Microsoft.WindowsCommunicationsapps*", # Mail
    "Microsoft.WindowsMaps*", # Maps
    "Microsoft.MixedReality.Portal*", # MixedReality
    "Microsoft.ZuneMusic*", # Music
    "Microsoft.MicrosoftOfficeHub*", # OfficeHub
    "Microsoft.Office.OneNote*", # OneNote
    "Microsoft.OutlookForWindows*", # Outlook
    "Microsoft.MSPaint*", # Paint3D(Windows10)
    "Microsoft.People*", # People
    "Microsoft.YourPhone*", # Phone
    "Microsoft.PowerAutomateDesktop*", # PowerAutomate
    "MicrosoftCorporationII.QuickAssist*", # QuickAssist
    "Microsoft.SkypeApp*", # Skype
    "Microsoft.MicrosoftSolitaireCollection*", # SolitaireCollection
    # "Microsoft.WindowsSoundRecorder*", # SoundRecorder
    "MicrosoftTeams*", # Teams_old
    "MSTeams*", # Teams
    "Microsoft.Todos*", # Todos
    "Microsoft.ZuneVideo*", # Video
    "Microsoft.Wallet*", # Wallet
    "Microsoft.GamingApp*", # Xbox
    "Microsoft.XboxApp*", # Xbox(Win10)
    "Microsoft.XboxGameOverlay*", # XboxGameOverlay
    "Microsoft.XboxGamingOverlay*", # XboxGamingOverlay
    "Microsoft.XboxSpeechToTextOverlay*", # XboxSpeechToTextOverlay
    "Microsoft.Xbox.TCUI*", # XboxTCUI
    # "Microsoft.SecHealthUI*",
    "MicrosoftWindows.CrossDevice*", # CrossDevice
    "Microsoft.BingSearch*" # Bing Search
)

$capabilitiesToRemove = @(
    "Browser.InternetExplorer*",
    "Internet-Explorer*",
    "App.StepsRecorder*",
    "Language.Handwriting~~~$langCode*",
    "Language.OCR~~~$langCode*",
    "Language.Speech~~~$langCode*",
    "Language.TextToSpeech~~~$langCode*",
    "Microsoft.Windows.WordPad*",
    "MathRecognizer*",
    "Media.WindowsMediaPlayer*",
    "Microsoft.Windows.PowerShell.ISE*"
)

$windowsPackagesToRemove = @(
    "Microsoft-Windows-InternetExplorer-Optional-Package*",
    "Microsoft-Windows-LanguageFeatures-Handwriting-$langCode-Package*",
    "Microsoft-Windows-LanguageFeatures-OCR-$langCode-Package*",
    "Microsoft-Windows-LanguageFeatures-Speech-$langCode-Package*",
    "Microsoft-Windows-LanguageFeatures-TextToSpeech-$langCode-Package*",
    "Microsoft-Windows-MediaPlayer-Package*",
    "Microsoft-Windows-TabletPCMath-Package*",
    "Microsoft-Windows-StepsRecorder-Package*"
)

# Remove Packages
Write-LogMessage "Removing provisioned packages"
Write-Host "`nRemoving provisioned Packages..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 1500

# Remove AppX Packages
foreach ($appxPattern in $appxPatternsToRemove) {
    try {
        Write-Host $appxPattern.TrimEnd('*')
        $appxProvisionedPackages = Get-ProvisionedAppxPackage -Path $installMountDir | Where-Object { $_.PackageName -like $appxPattern }
        foreach ($appxPackage in $appxProvisionedPackages) {
            $appxPackageName = $appxPackage.PackageName
            try {
                dism /image:$installMountDir /Remove-ProvisionedAppxPackage /PackageName:$appxPackageName > $null
            }
            catch {
                Write-LogMessage "Removing AppX package $appxPackageName failed: $_"
            }
        }
    }
    catch {
        Write-LogMessage "Failed to remove provisioned AppX package matching '$appxPattern': $_"
    }
}

Write-LogMessage "Removing unnecessary Windows capabilities"
Write-Host "`nRemoving Unnecessary Windows Capabilities..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 1500

# Remove Windows Capabilities
foreach ($capabilityPattern in $capabilitiesToRemove) {
    try {
        Write-Host $capabilityPattern.TrimEnd('*')
        $windowsCapabilities = Get-WindowsCapability -Path $installMountDir | Where-Object { $_.Name -like $capabilityPattern }
        foreach ($capability in $windowsCapabilities) {
            $capabilityName = $capability.Name
            try {
                dism /image:$installMountDir /Remove-Capability /CapabilityName:$capabilityName > $null
            }
            catch {
                Write-LogMessage "Removing capability $capabilityName failed: $_"
            }
        }
    }
    catch {
        Write-LogMessage "Failed to remove capability matching '$capabilityPattern': $_"
    }
}

# Remove Windows Packages
foreach ($windowsPackagePattern in $windowsPackagesToRemove) {
    try {
        Write-Host $windowsPackagePattern.TrimEnd('*')
        $windowsPackages = Get-WindowsPackage -Path $installMountDir | Where-Object { $_.PackageName -like $windowsPackagePattern }
        foreach ($windowsPackage in $windowsPackages) {
            $windowsPackageName = $windowsPackage.PackageName
            try {
                dism /image:$installMountDir /Remove-Package /PackageName:$windowsPackageName > $null
            }
            catch {
                Write-LogMessage "Removing Windows package $windowsPackageName failed: $_"
            }
        }
    }
    catch {
        Write-LogMessage "Failed to remove Windows package matching '$windowsPackagePattern': $_"
    }
}

# # Remove Recall (Have conflict with Explorer)
# Write-LogMessage "Removing Recall"
# Write-Host "`nRemoving Recall..."
# Start-Sleep -Milliseconds 1500
# dism /image:$installMountDir /Disable-Feature /FeatureName:'Recall' /Remove > $null
# Write-Host "Done"

# Remove OutlookPWA
Write-LogMessage "Removing OutlookPWA"
Write-Host "`nRemoving Outlook..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 1500
Get-ChildItem "$installMountDir\Windows\WinSxS\amd64_microsoft-windows-outlookpwa*" -Directory | ForEach-Object { Set-OwnAndRemove -Path $_.FullName } > $null 2>&1
Write-Host "Done" -ForegroundColor Green

# Setting Persmission
function Enable-Privilege {
    param([ValidateSet('SeAssignPrimaryTokenPrivilege', 'SeAuditPrivilege', 'SeBackupPrivilege', 'SeChangeNotifyPrivilege', 'SeCreateGlobalPrivilege', 'SeCreatePagefilePrivilege', 'SeCreatePermanentPrivilege', 'SeCreateSymbolicLinkPrivilege', 'SeCreateTokenPrivilege', 'SeDebugPrivilege', 'SeEnableDelegationPrivilege', 'SeImpersonatePrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeIncreaseQuotaPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeLoadDriverPrivilege', 'SeLockMemoryPrivilege', 'SeMachineAccountPrivilege', 'SeManageVolumePrivilege', 'SeProfileSingleProcessPrivilege', 'SeRelabelPrivilege', 'SeRemoteShutdownPrivilege', 'SeRestorePrivilege', 'SeSecurityPrivilege', 'SeShutdownPrivilege', 'SeSyncAgentPrivilege', 'SeSystemEnvironmentPrivilege', 'SeSystemProfilePrivilege', 'SeSystemtimePrivilege', 'SeTakeOwnershipPrivilege', 'SeTcbPrivilege', 'SeTimeZonePrivilege', 'SeTrustedCredManAccessPrivilege', 'SeUndockPrivilege', 'SeUnsolicitedInputPrivilege')]$Privilege, $ProcessId = $pid, [Switch]$Disable)
    $def = @'
    using System;using System.Runtime.InteropServices;public class AdjPriv{[DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)]internal static extern bool AdjustTokenPrivileges(IntPtr htok,bool disall,ref TokPriv1Luid newst,int len,IntPtr prev,IntPtr relen);[DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)]internal static extern bool OpenProcessToken(IntPtr h,int acc,ref IntPtr phtok);[DllImport("advapi32.dll",SetLastError=true)]internal static extern bool LookupPrivilegeValue(string host,string name,ref long pluid);[StructLayout(LayoutKind.Sequential,Pack=1)]internal struct TokPriv1Luid{public int Count;public long Luid;public int Attr;}public static bool EnablePrivilege(long processHandle,string privilege,bool disable){var tp=new TokPriv1Luid();tp.Count=1;tp.Attr=disable?0:2;IntPtr htok=IntPtr.Zero;if(!OpenProcessToken(new IntPtr(processHandle),0x28,ref htok))return false;if(!LookupPrivilegeValue(null,privilege,ref tp.Luid))return false;return AdjustTokenPrivileges(htok,false,ref tp,0,IntPtr.Zero,IntPtr.Zero);}}
'@
    (Add-Type $def -PassThru -EA SilentlyContinue)[0]::EnablePrivilege((Get-Process -id $ProcessId).Handle, $Privilege, $Disable)
}
Enable-Privilege SeTakeOwnershipPrivilege > $null 2>&1

# Remove OneDrive
Start-Sleep -Milliseconds 1500
Write-Host "`nRemoving OneDrive..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 1500
Write-LogMessage "Defining OneDrive Setup file paths"
$oneDriveSetupPath1 = Join-Path -Path $installMountDir -ChildPath 'Windows\System32\OneDriveSetup.exe'
$oneDriveSetupPath2 = Join-Path -Path $installMountDir -ChildPath 'Windows\SysWOW64\OneDriveSetup.exe'
$oneDriveSetupPath3 = (Join-Path -Path $installMountDir -ChildPath 'Windows\WinSxS\*microsoft-windows-onedrive-setup*\OneDriveSetup.exe' | Get-Item -ErrorAction SilentlyContinue).FullName
$oneDriveSetupPath4 = (Get-ChildItem "$installMountDir\Windows\WinSxS\amd64_microsoft-windows-onedrive-setup*" -Directory).FullName
$oneDriveShortcut = Join-Path -Path $installMountDir -ChildPath 'Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk'

Write-LogMessage "Removing OneDrive"
Set-OwnAndRemove -Path $oneDriveSetupPath1
Set-OwnAndRemove -Path $oneDriveSetupPath2
$oneDriveSetupPath3 | Where-Object { $_ } | ForEach-Object { Set-OwnAndRemove -Path $_ } > $null 2>&1
$oneDriveSetupPath4 | Where-Object { $_ } | ForEach-Object { Set-OwnAndRemove -Path $_ } > $null 2>&1
Set-OwnAndRemove -Path $oneDriveShortcut

Write-Host "OneDrive Removed" -ForegroundColor Green

# Remove EDGE
Start-Sleep -Milliseconds 1500
Write-Host
do {
    $EdgeConfirm = Read-Host "Remove Microsoft Edge? (Y/N)"
    $EdgeConfirm = $EdgeConfirm.ToUpper()

    if ($EdgeConfirm -eq 'Y') {
        Write-LogMessage "Removing EDGE"
        Write-Host "Removing EDGE..." -ForegroundColor Cyan
    
        # Edge Patterns
        $EDGEpatterns = @(
            "Microsoft.MicrosoftEdge.Stable*",
            "Microsoft.MicrosoftEdgeDevToolsClient*", 
            "Microsoft.Win32WebViewHost*",
            "MicrosoftWindows.Client.WebExperience*"
        )

        # Remove Edge Packages
        foreach ($pattern in $EDGEpatterns) {
            $matchedPackages = Get-ProvisionedAppxPackage -Path $installMountDir | 
            Where-Object { $_.PackageName -like $pattern }
    
            foreach ($package in $matchedPackages) {
                dism /image:$installMountDir /Remove-ProvisionedAppxPackage /PackageName:$($package.PackageName) > $null
            }
        }

        # Modifying reg keys
        reg load HKLM\zSOFTWARE "$installMountDir\Windows\System32\config\SOFTWARE" > $null 2>&1
        reg load HKLM\zSYSTEM "$installMountDir\Windows\System32\config\SYSTEM" > $null 2>&1
        reg load HKLM\zNTUSER "$installMountDir\Users\Default\ntuser.dat" > $null 2>&1
        reg load HKLM\zDEFAULT "$installMountDir\Windows\System32\config\default" > $null 2>&1


        reg delete "HKLM\zSOFTWARE\Microsoft\EdgeUpdate" /f > $null 2>&1
        reg delete "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f > $null 2>&1
        reg delete "HKLM\zDEFAULT\Software\Microsoft\EdgeUpdate" /f > $null 2>&1
        reg delete "HKLM\zNTUSER\Software\Microsoft\EdgeUpdate" /f > $null 2>&1
        reg delete "HKLM\zSOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" /f > $null 2>&1
        reg delete "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Edge" /f > $null 2>&1
        reg delete "HKLM\zSOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" /f > $null 2>&1
        reg delete "HKLM\zSYSTEM\CurrentControlSet\Services\edgeupdate" /f > $null 2>&1
        reg delete "HKLM\zSYSTEM\ControlSet001\Services\edgeupdate" /f > $null 2>&1
        reg delete "HKLM\zSYSTEM\CurrentControlSet\Services\edgeupdatem" /f > $null 2>&1
        reg delete "HKLM\zSYSTEM\ControlSet001\Services\edgeupdatem" /f > $null 2>&1
        reg delete "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f > $null 2>&1
        reg delete "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f > $null 2>&1
        reg add "HKLM\zSOFTWARE\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zNTUSER\Software\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zNTUSER\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSOFTWARE\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zNTUSER\Software\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zNTUSER\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSOFTWARE\Policies\Microsoft\EdgeUpdate" /v "UpdateDefault" /t REG_DWORD /d "0" /f > $null 2>&1
    
        # Disable Edge updates and installation
        $registryKeys = @(
            "HKLM\zSOFTWARE\Microsoft\EdgeUpdate",
            "HKLM\zSOFTWARE\Policies\Microsoft\EdgeUpdate",
            "HKLM\zSOFTWARE\WOW6432Node\Microsoft\EdgeUpdate",
            "HKLM\zNTUSER\Software\Microsoft\EdgeUpdate",
            "HKLM\zNTUSER\Software\Policies\Microsoft\EdgeUpdate"
        )
        foreach ($key in $registryKeys) {
            reg add "$key" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f > $null 2>&1
            reg add "$key" /v "UpdaterExperimentationAndConfigurationServiceControl" /t REG_DWORD /d "1" /f > $null 2>&1
            reg add "$key" /v "InstallDefault" /t REG_DWORD /d "1" /f > $null 2>&1
        }
    
        reg unload HKLM\zSOFTWARE > $null 2>&1
        reg unload HKLM\zSYSTEM > $null 2>&1
        reg unload HKLM\zNTUSER > $null 2>&1
        reg unload HKLM\zDEFAULT > $null 2>&1

        # Remove EDGE files
        Remove-Item -Path "$installMountDir\Program Files\Microsoft\Edge" -Recurse -Force > $null 2>&1
        Remove-Item -Path "$installMountDir\Program Files\Microsoft\EdgeCore" -Recurse -Force > $null 2>&1
        Remove-Item -Path "$installMountDir\Program Files\Microsoft\EdgeUpdate" -Recurse -Force > $null 2>&1
        Remove-Item -Path "$installMountDir\Program Files\Microsoft\EdgeWebView" -Recurse -Force > $null 2>&1
        Remove-Item -Path "$installMountDir\Program Files (x86)\Microsoft\Edge" -Recurse -Force > $null 2>&1
        Remove-Item -Path "$installMountDir\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force > $null 2>&1
        Remove-Item -Path "$installMountDir\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force > $null 2>&1
        Remove-Item -Path "$installMountDir\Program Files (x86)\Microsoft\EdgeWebView" -Recurse -Force > $null 2>&1
        Remove-Item -Path "$installMountDir\ProgramData\Microsoft\EdgeUpdate" -Recurse -Force > $null 2>&1
        Get-ChildItem "$installMountDir\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.MicrosoftEdge.Stable*" -Directory | ForEach-Object { Set-OwnAndRemove -Path $_.FullName } > $null 2>&1
        Get-ChildItem "$installMountDir\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.MicrosoftEdgeDevToolsClient*" -Directory | ForEach-Object { Set-OwnAndRemove -Path $_.FullName } > $null 2>&1
        Get-ChildItem "$installMountDir\Windows\WinSxS\*microsoft-edge-webview*" -Directory | ForEach-Object { Set-OwnAndRemove -Path $_.FullName } > $null 2>&1
        Set-OwnAndRemove -Path (Join-Path -Path $installMountDir -ChildPath 'Windows\System32\Microsoft-Edge-WebView')
        Set-OwnAndRemove -Path (Join-Path -Path $installMountDir -ChildPath 'Windows\SystemApps\Microsoft.Win32WebViewHost*' | Get-Item -ErrorAction SilentlyContinue).FullName

        # Removing EDGE-Task
        Get-ChildItem -Path "$installMountDir\Windows\System32\Tasks\MicrosoftEdge*" | Where-Object { $_ } | ForEach-Object { Set-OwnAndRemove -Path $_ } > $null 2>&1

        # For Windows 10 (Legacy EDGE)
        if ($buildNumber -lt 22000) {
            Get-ChildItem -Path "$installMountDir\Windows\SystemApps\Microsoft.MicrosoftEdge*" | Where-Object { $_ } | ForEach-Object { Set-OwnAndRemove -Path $_ } > $null 2>&1
        }
    
        Write-Host "Microsoft Edge has been removed." -ForegroundColor Green
        break
    }
    elseif ($EdgeConfirm -eq 'N') {
        Write-Host "Microsoft Edge removal cancelled." -ForegroundColor Red
        Write-LogMessage "Edge removal cancelled"
        break
    }
    else {
        Write-Host "Invalid input. Please enter 'Y' or 'N'." -ForegroundColor Yellow
    }
} while ($true)

Start-Sleep -Milliseconds 1800
Write-Host "`nLoading Registry..." -ForegroundColor Cyan
Write-LogMessage "Loading registry"
reg load HKLM\zCOMPONENTS "$installMountDir\Windows\System32\config\COMPONENTS" > $null 2>&1
reg load HKLM\zDEFAULT "$installMountDir\Windows\System32\config\default" > $null 2>&1
reg load HKLM\zNTUSER "$installMountDir\Users\Default\ntuser.dat" > $null 2>&1
reg load HKLM\zSOFTWARE "$installMountDir\Windows\System32\config\SOFTWARE" > $null 2>&1
reg load HKLM\zSYSTEM "$installMountDir\Windows\System32\config\SYSTEM" > $null 2>&1


# Setting Permissions
try {
    $sid = (New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")).Translate([System.Security.Principal.SecurityIdentifier])
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule("Administrators", "FullControl", "ContainerInherit", "None", "Allow")

    foreach ($keyPath in @("zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications", "zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows", "zSOFTWARE\Microsoft\WindowsRuntime\Server\Windows.Gaming.GameBar.Internal.PresenceWriterServer")) {
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
            if ($key) {
                $acl = $key.GetAccessControl()
                $acl.SetOwner($sid)
                $key.SetAccessControl($acl)
                $key.Close()

                $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
                $acl = $key.GetAccessControl()
                $acl.SetAccessRule($rule)
                $key.SetAccessControl($acl)
                $key.Close()
            }
        }
        catch {}
    }
}
catch {}

# Modify registry settings
Start-Sleep -Milliseconds 1000
Write-Host "`nPerforming Registry Tweaks..." -ForegroundColor Cyan

# Disable Sponsored Apps
Write-Host "Disabling Sponsored Apps"
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d '{\"pinnedList\": [{}]}' /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_SZ /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f > $null 2>&1

# Disable Telemetry
Write-Host "Disabling Telemetry"
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1

# Disable Recall on first logon
if ($buildNumber -ge 22000) {
    Write-Host "Disabling Recall"
    reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "DisableRecall" /t REG_SZ /d "dism.exe /online /disable-feature /FeatureName:recall" /f > $null 2>&1
    reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f > $null 2>&1
}

# Disable Meet Now icon
Write-Host "Disabling Meet"
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f > $null 2>&1

# Disable ad tailoring
Write-Host "Disabling Ads and Stuffs"
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f > $null 2>&1

# Disable Cortana
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f > $null 2>&1

# Changes MenuShowDelay from 400 to 200
reg add "HKLM\zNTUSER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f > $null 2>&1

# Disable everytime MRT download through Win Update
reg add "HKLM\zSOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f > $null 2>&1

# Disable OneDrive Stuffs
Write-Host "Removing OneDrive Junks"
reg delete "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Policies\Microsoft\OneDrive" /v "KFMBlockOptIn" /t REG_DWORD /d "1" /f > $null 2>&1

# Disable GameDVR
Write-Host "Disabling GameDVR and Components"
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zNTUSER\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f > $null 2>&1
reg add "HKLM\zSYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d 4 /f > $null 2>&1
reg add "HKLM\zSYSTEM\ControlSet001\Services\GameBarPresenceWriter" /v "Start" /t REG_DWORD /d 4 /f > $null 2>&1

# Removing Gamebar Popup
# Courtesy: https://pastebin.com/EAABLssA by aveyo
Write-Host "Removing Gamebar Popup"
reg add "HKLM\zNTUSER\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 0 /f > $null 2>&1
# Rest added as post install script. Somehow, implementing it directly on the image was causing corruption

# # Configure GameBarFTServer (NA)
# $packageKey = "HKLM\zSOFTWARE\Classes\PackagedCom\ClassIndex\{FD06603A-2BDF-4BB1-B7DF-5DC68F353601}"
# $app = (Get-Item "Registry::$packageKey").PSChildName
# reg add "HKLM\zSOFTWARE\Classes\PackagedCom\Package\$app\Server\0" /v "Executable" /t REG_SZ /d "systray.exe" /f > $null 2>&1

# Enabling Local Account Creation
Write-Host "Tweaking OOBE Settings"
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f > $null 2>&1
Copy-Item -Path $autounattendXmlPath -Destination $destinationPath -Force

# Prevents Dev Home Installation
Write-Host "Disabling useless junks"
reg delete "HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /v "workCompleted" /t REG_DWORD /d "1" /f > $null 2>&1

# Prevents New Outlook for Windows Installation
reg delete "HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /v "workCompleted" /t REG_DWORD /d "1" /f > $null 2>&1

# Prevents Chat Auto Installation
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d "0" /f > $null 2>&1
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f > $null 2>&1

Write-Host "Disabling Scheduled Tasks"
$win24H2 = (Get-ItemProperty -Path 'Registry::HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion).DisplayVersion -eq '24H2'
if ($win24H2) {
    # Customer Experience Improvement Program
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{780E487D-C62F-4B55-AF84-0E38116AFE07}" /f > $null 2>&1
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FD607F42-4541-418A-B812-05C32EBA8626}" /f > $null 2>&1
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E4FED5BC-D567-4044-9642-2EDADF7DE108}" /f > $null 2>&1
    # Program Data Updater
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E292525C-72F1-482C-8F35-C513FAA98DAE}" /f > $null 2>&1
    # Application Compatibility Appraiser
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{3047C197-66F1-4523-BA92-6C955FEF9E4E}" /f > $null 2>&1
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0C71CB8-E8F0-498A-901D-4EDA09E07FF4}" /f > $null 2>&1
}
else {
    # Customer Experience Improvement Program
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /f > $null 2>&1
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /f > $null 2>&1
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /f > $null 2>&1
    # Program Data Updater
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /f > $null 2>&1
    # Application Compatibility Appraiser
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /f > $null 2>&1
}
reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Application Experience\PcaPatchDbTask" /f > $null 2>&1
reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Application Experience\MareBackup" /f > $null 2>&1
reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /f > $null 2>&1
reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Autochk\Proxy" /f > $null 2>&1
reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /f > $null 2>&1
reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /f > $null 2>&1

# Disable TPM CHeck
Write-Host
do {
    $TPMConfirm = Read-Host "Bypass System Requirments Check? (Y/N)"
    $TPMConfirm = $TPMConfirm.ToUpper()
    if ($TPMConfirm -eq 'Y') {
        Write-Host "Disabling TPM Check" -ForegroundColor Cyan
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassDiskCheck" /t REG_DWORD /d "1" /f > $null 2>&1
        reg add "HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f > $null 2>&1
        
        try {
            $bootWimPath = Join-Path $destinationPath "sources\boot.wim"
            $bootMountDir = "$env:SystemDrive\WIDTemp\mountdir\bootWIM"
            New-Item -ItemType Directory -Path $bootMountDir > $null 2>&1
            dism /mount-image /imagefile:$bootWimPath /index:2 /mountdir:$bootMountDir | Out-Null

            reg load HKLM\xDEFAULT "$bootMountDir\Windows\System32\config\default" > $null 2>&1
            reg load HKLM\xNTUSER "$bootMountDir\Users\Default\ntuser.dat" > $null 2>&1
            reg load HKLM\xSYSTEM "$bootMountDir\Windows\System32\config\SYSTEM" > $null 2>&1

            reg add "HKLM\xSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1 /f > $null 2>&1
            reg add "HKLM\xSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1 /f > $null 2>&1
            reg add "HKLM\xSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d 1 /f > $null 2>&1
            reg add "HKLM\xSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d 1 /f > $null 2>&1
            reg add "HKLM\xSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d 1 /f > $null 2>&1
            reg add "HKLM\xSYSTEM\Setup\LabConfig" /v "BypassDiskCheck" /t REG_DWORD /d "1" /f > $null 2>&1
            reg add "HKLM\xSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d 1 /f > $null 2>&1

            reg unload HKLM\xDEFAULT > $null 2>&1
            reg unload HKLM\xNTUSER > $null 2>&1
            reg unload HKLM\xSYSTEM > $null 2>&1

            dism /Unmount-Image /MountDir:$bootMountDir /Commit > $null 2>&1
            Write-Host "Done" -ForegroundColor Green
        }
        catch {
            Write-LogMessage "Failed to mount boot.wim: $_"
        }
        break
    }
    elseif ($TPMConfirm -eq 'N') {
        Write-Host "Cancelled." -ForegroundColor Red
        break
    }
    else {
        Write-Host "Invalid input. Please enter 'Y' or 'N'." -ForegroundColor Yellow
    }
} while ($true)

# Bring back user folders
if ($buildNumber -ge 22000) {
    Write-Host
    do {
        $expConfirm = Read-Host "Windows 11 disables 'User Folders' in This PC. Enable those again? (Y/N)"
        $expConfirm = $expConfirm.ToUpper()
        if ($expConfirm -eq 'Y') {
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /v "HideIfEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /v "HideIfEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /v "HideIfEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /v "HideIfEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /v "HideIfEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /v "HideIfEnabled" /t REG_DWORD /d "0" /f > $null 2>&1

            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /v "HiddenByDefault" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /v "HiddenByDefault" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /v "HiddenByDefault" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /v "HiddenByDefault" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /v "HiddenByDefault" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /v "HiddenByDefault" /t REG_DWORD /d "0" /f > $null 2>&1
            break
        }
        elseif ($expConfirm -eq 'N') {
            Write-Host "Cancelled" -ForegroundColor Red
            break
        }
        else {
            Write-Host "Invalid input. Please enter 'Y' or 'N'." -ForegroundColor Yellow
        }
    } while ($true)
}

Start-Sleep -Milliseconds 1500
Write-Host "`nUnloading Registry..."
Write-LogMessage "Unloading registry"
reg unload HKLM\zCOMPONENTS > $null 2>&1
reg unload HKLM\zDEFAULT > $null 2>&1
reg unload HKLM\zNTUSER > $null 2>&1
reg unload HKLM\zSOFTWARE > $null 2>&1
reg unload HKLM\zSYSTEM > $null 2>&1

Start-Sleep -Milliseconds 1000
Write-Host "`nCleaning up image..."
Write-LogMessage "Cleaning up image"
dism /image:$installMountDir /Cleanup-Image /StartComponentCleanup /ResetBase > $null

Start-Sleep -Milliseconds 1000
Write-Host "`nUnmounting and Exporting image..."
Write-LogMessage "Unmounting image"
try {
    $unmountProcess = Start-Process -FilePath "dism" -ArgumentList "/unmount-image", "/mountdir:$installMountDir", "/commit" -PassThru -Wait -NoNewWindow
    if ($unmountProcess.ExitCode -ne 0) {
        Write-LogMessage "Failed to unmount image. Exit code: $($unmountProcess.ExitCode)"
        Write-Host "`nFailed to Unmount the Image. Check Logs for more info." -ForegroundColor Red
        Write-Host "Close all the Folders opened in the mountdir to complete the Script."
        Write-Host "Run the following code in Powershell(as admin) to unmount the broken image: "
        Write-Host "dism /unmount-image /mountdir:$installMountDir /discard" -ForegroundColor Yellow
        Read-Host -Prompt "Press Enter to exit"
        Write-LogMessage "Exiting Script"
        Exit
    }
}
catch {
    Write-LogMessage "Failed to unmount image: $_"
    Exit
}

Write-LogMessage "Exporting image"
$SourceIndex = if (Test-Path $installWimPath) { $WimIndex } else { 1 }
Write-Host
$compressRecovery = Read-Host "Compress install.wim to save disk space? (Y/N)"
$tempWimPath = "$destinationPath\sources\install_temp.wim"

if ($compressRecovery -eq 'Y' -or $compressRecovery -eq 'y') {
    dism /Export-Image /SourceImageFile:"$destinationPath\sources\install.wim" /SourceIndex:$SourceIndex /DestinationImageFile:"$tempWimPath" /Compress:recovery /CheckIntegrity
    Write-Host "`nCompression completed" -ForegroundColor Green
    Write-LogMessage "Compression completed"
}
else {
    Write-Host "Compression skipped"
    dism /Export-Image /SourceImageFile:"$destinationPath\sources\install.wim" /SourceIndex:$SourceIndex /DestinationImageFile:"$tempWimPath" /Compress:max /CheckIntegrity
}

if (Test-Path $tempWimPath) {
    Remove-Item -Path "$destinationPath\sources\install.wim" -Force
    Move-Item -Path $tempWimPath -Destination "$destinationPath\sources\install.wim" -Force
    
    if (-not (Test-Path "$destinationPath\sources\install.wim")) {
        Write-Host "Error: Final install.wim is missing" -ForegroundColor Red
        Write-LogMessage "Final install.wim missing"
        Exit
    }
} else {
    Write-Host "Error: WIM export failed" -ForegroundColor Red
    Write-LogMessage "WIM export failed"
    Exit
}

Write-LogMessage "Checking required files"
Write-Host
$ISOFileName = Read-Host -Prompt "Enter the name for the ISO file (without extension)"
$ISOFile = Join-Path -Path $scriptDirectory -ChildPath "$ISOFileName.iso"

Write-Host "`nPreparing ISO creation"
Write-LogMessage "Preparing ISO creation"

# ISOWriter class
# More Here: https://learn.microsoft.com/en-us/windows/win32/api/_imapi/
if (!('ISOWriter' -as [Type])) {
    Add-Type -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;
    using System.Runtime.InteropServices.ComTypes;

    public class ISOWriter {
        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
        private static extern void SHCreateStreamOnFileEx(string fileName, uint mode, uint attributes, bool create, IStream streamNull, out IStream stream);
        public static bool Create(string filePath, ref object imageStream, int blockSize, int totalBlocks) {IStream resultStream = (IStream)imageStream, imageFile; SHCreateStreamOnFileEx(filePath, 0x1001, 0x80, true, null, out imageFile); const int bufferSize = 1024; int remainingBlocks = totalBlocks;
            while (remainingBlocks > 0) { int blocksToWrite = Math.Min(remainingBlocks, bufferSize); resultStream.CopyTo(imageFile, blocksToWrite * blockSize, IntPtr.Zero, IntPtr.Zero); remainingBlocks -= blocksToWrite;}
            imageFile.Commit(0);
            return true;}
    }
'@
}

try {
    $comObjects = @()

    # Initialize boot configuration
    $bootStream = New-Object -ComObject ADODB.Stream -Property @{ Type = 1 }
    $comObjects += $bootStream
    $bootStream.Open()
    $bootStream.LoadFromFile("$destinationPath\efi\Microsoft\boot\efisys.bin")
    # $bootStream.LoadFromFile("$destinationPath\efi\Microsoft\boot\efisys_noprompt.bin")

    # Configure boot and filesystem
    $bootOptions = New-Object -ComObject IMAPI2FS.BootOptions -Property @{
        PlatformId = 0xEF
        Manufacturer = "Microsoft"
        Emulation = 0
    }
    $comObjects += $bootOptions
    $bootOptions.AssignBootImage($bootStream)

    $FSImage = New-Object -ComObject IMAPI2FS.MsftFileSystemImage -Property @{
        FileSystemsToCreate = 4
        UDFRevision = 0x102
        FreeMediaBlocks = 0
        VolumeName = $ISOFileName
    }
    $comObjects += $FSImage
    
    Write-LogMessage "Creating ISO structure"
    $FSImage.Root.AddTree($destinationPath, $false)
    $FSImage.BootImageOptions = $bootOptions
    
    Write-Host "`nGenerating ISO..." -ForegroundColor Cyan
    Write-LogMessage "Generating ISO file"
    $resultImage = $FSImage.CreateResultImage()
    $comObjects += $resultImage

    [ISOWriter]::Create($ISOFile, [ref]$resultImage.ImageStream, $resultImage.BlockSize, $resultImage.TotalBlocks)
    
    if ((Get-Item $ISOFile).Length -eq ($resultImage.BlockSize * $resultImage.TotalBlocks)) {
        Write-LogMessage "ISO successfully created at: $ISOFile"
    }
}
catch {
    Write-LogMessage "ISO creation failed: $_" -Type Error
}
finally {
    foreach ($obj in $comObjects) {
        if ($obj) { 
            while ([Runtime.InteropServices.Marshal]::ReleaseComObject($obj) -gt 0) { }
        }
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Write-Host "ISO generated successfully" -ForegroundColor Green
}

# Remove temporary files
Write-Host "`nRemoving temporary files..."
Write-LogMessage "Removing temporary files"
try {
    Remove-TempFiles
}
catch {
    Write-LogMessage "Failed to remove temporary files: $_"
}
finally {
    Write-LogMessage "Script completed"
}

# ISO verification
$verifyMntResult = Mount-DiskImage -ImagePath "$ISOFile" -PassThru
$verifyDrive = ($verifyMntResult | Get-Volume).DriveLetter
$isoMountPoint = "${verifyDrive}:\"
$reqFiles = @("sources\install.wim", "sources\boot.wim", "boot\bcd", "boot\boot.sdi", "bootmgr", "bootmgr.efi", "efi\microsoft\boot\efisys.bin")
$missingFiles = $reqFiles | Where-Object { -not (Test-Path (Join-Path $isoMountPoint $_)) }

Dismount-DiskImage -ImagePath "$ISOFile" | Out-Null

Start-Sleep -Milliseconds 1000
if ($missingFiles) {
    Write-LogMessage "ISO verification failed - missing files: $($missingFiles -join ', ')"
    Write-Host "`nError: Created ISO is missing critical files" -ForegroundColor Red
}
else {
    Write-LogMessage "ISO verification successful"
    Write-Host "`nScript Completed. Can find the ISO in `"$scriptDirectory"`" -ForegroundColor Green
}

Read-Host -Prompt "Press Enter to exit"
