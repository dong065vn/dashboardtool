::[Bat To Exe Converter]
::
::YAwzoRdxOk+EWAnk
::fBw5plQjdG8=
::YAwzuBVtJxjWCl3EqQJgSA==
::ZR4luwNxJguZRRnk
::Yhs/ulQjdF+5
::cxAkpRVqdFKZSDk=
::cBs/ulQjdF+5
::ZR41oxFsdFKZSDk=
::eBoioBt6dFKZSDk=
::cRo6pxp7LAbNWATEpCI=
::egkzugNsPRvcWATEpCI=
::dAsiuh18IRvcCxnZtBJQ
::cRYluBh/LU+EWAnk
::YxY4rhs+aU+JeA==
::cxY6rQJ7JhzQF1fEqQJQ
::ZQ05rAF9IBncCkqN+0xwdVs0
::ZQ05rAF9IAHYFVzEqQJQ
::eg0/rx1wNQPfEVWB+kM9LVsJDGQ=
::fBEirQZwNQPfEVWB+kM9LVsJDGQ=
::cRolqwZ3JBvQF1fEqQJQ
::dhA7uBVwLU+EWDk=
::YQ03rBFzNR3SWATElA==
::dhAmsQZ3MwfNWATElA==
::ZQ0/vhVqMQ3MEVWAtB9wSA==
::Zg8zqx1/OA3MEVWAtB9wSA==
::dhA7pRFwIByZRRnk
::Zh4grVQjdCuDJGqL8lYnKQlRcDSrCF2UOZQqxNTa2cbJp1UYNA==
::YB416Ek+ZG8=
::
::
::978f952a14a936cc963da21a135fa983
@Echo off 
title "AVL-PITVN"
pushd "%~dp0"
setlocal EnableExtensions EnableDelayedExpansion
Echo ----- Check Administrator Role
net session >nul 2>&1
if "%errorlevel%" NEQ "0" (
	Powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" && exit
)
Echo -------------- AVL. Auto Template --------------
Set "current_time=%time%"
Set "hour=%current_time:~0,2%"
If "%hour:~0,1%"==" " Set "hour=%hour:~1,1%"
set "TL1=E1"
set "TLdesc=Light Template is active"
If %hour% GEQ 19 (
	set "TLdesc=Dark Template is active"
	set "TL1=0A"
)
If %hour% LSS 7 (
	set "TLdesc=Dark Template is active"
	set "TL1=0A"
)
Call :AVLTemplate !TL1!
Echo %TLdesc%
CLS
Echo ---------- AVL. Initial Configuration ----------
bcdedit /enum {fwbootmgr} >nul 2>&1 && (Set "FirmwareType=UEFI") || (Set "FirmwareType=BIOS")
Reg delete "HKCU\Console" /f
Reg add "HKCU\Console" /v QuickEdit /t REG_DWORD /d 1 /f
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\TrueTypeFont" /v 000 /t REG_SZ /d "Cascadia Code" /f >nul 2>&1
Reg add "HKCU\Console" /v FaceName /t REG_SZ /d "Cascadia Code" /f >nul 2>&1
Reg add "HKCU\Console" /v FontSize /t REG_DWORD /d 0x00140000 /f >nul 2>&1
For /F "tokens=4 delims=.[]" %%A in ('ver') do Set "WinVer=%%A"
Reg add HKCU\Console /v QuickEdit /t REG_DWORD /d 1 /f 
Set "Aria2cStatus=Not_Check"
Set "Aria2cCheck=false"
Set "Aria2cPath="
Set "CrkURL=https://workupload.com/start/4WQkTxuPddM"
Set "apikey=nVHBz3RIsHpXHofLv3B89iFK8"
Set "OfficeSKUS=https://glennsferryschools-my.sharepoint.com/:u:/g/personal/billgates_glennsferryschools_onmicrosoft_com/EWrV0SG_BAZNguP9UTtYGO0B99B8A8dMl-8fPh1OJEukxg"
Set "WindowsSKUS=https://glennsferryschools-my.sharepoint.com/:u:/g/personal/billgates_glennsferryschools_onmicrosoft_com/Een1HwvMho9PloRvzcLviRkB-QWO3FnpLmxgxuoY8TUCiA"
Set "pidkeyURL=https://glennsferryschools-my.sharepoint.com/:u:/g/personal/billgates_glennsferryschools_onmicrosoft_com/EZYtgGBGY59ImTRu496hBwgBML_u4acWrXPJS344RBWgOw"
Set "AVLboot=https://glennsferryschools-my.sharepoint.com/:f:/g/personal/billgates_glennsferryschools_onmicrosoft_com/Em4jQfKIYXVEoXOMNRalrUcB-NYrTQokVb4umsdpz8UYWQ"
Set "NormalURL=https://www.dropbox.com/scl/fi/is51vqvzfx91a4bujh5d9/Normal.dotm?rlkey=3is31akqb1zmroto73zbpnvx5&st=3sxwirlw&dl=1"
Set "ToolURL=https://www.dropbox.com/scl/fi/aspx4fkvgzrr9gh63wltm/tool.zip?rlkey=bslspxkxux9tp9til27j7a6pu&st=1nferei8&dl=1"
Set "wimlib=https://wimlib.net/downloads/wimlib-1.14.4-windows-x86_64-bin.zip"
Set "SkusOffice=https://www.dropbox.com/scl/fi/jwjwojghu82e0j3etiu4x/PITVN_SkusOffice_20241003.zip?rlkey=ql4mirdm82b1gigmebmt040r5&st=01yc6g6w&dl=1"
Set "SkusWindows=https://www.dropbox.com/scl/fi/wx2rsrmlddiccfblvk2c7/PITVN_SkusWin_20241003.zip?rlkey=gpd6brmdbfeabivhscez9ysqs&st=51x1vwwe&dl=1"
Echo.
Echo ---- Check PATH contains Special characters ----
Set "Drive=%~d0"
For /F "tokens=1 delims=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:\_ " %%A in ("%~dp0") do (
	Echo Path To AVL      : %~dp0
	Echo Special Character: %%A
	Echo Warning          : Path contains Special Characters.
        Echo Recommendation   : AVL can still continue to run. If an error occurs, you need to Remove special characters from the folder name. Or move it to %Drive%.
	pause
)
Echo.
Echo -------- Check Powershell is available ---------
Powershell -command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
If "%ErrorLevel%" NEQ "0" (
	Setting the PowerShell execution policy ....
	reg delete "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /f
	reg delete "HKCU\Software\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /f
	Powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Undefined"
	Powershell -command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
	Exit
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.MainMenu
Set "AVLBackMenu=AVL.MainMenu"
Set "FileDel="
Set "FolderDel="
cls
Echo ------------------------- AVL. MainMenu -------------------------
Echo         AVL Tool - Author: Anthony - PITVN community
Echo             https://www.facebook.com/groups/pitvn
Echo       Support For Download, Installation and Activation
Echo   Create Date: 05 March 2025 - Update Date: 20 October 2025 
Echo                 Now Date: %DATE% %TIME:~0,8%
Echo -----------------------------------------------------------------
Echo     [1] PC Information              [A] Chocolatey    
Echo     [2] Manage Bitlocker            [B] Context Menu
Echo     [3] Manage Driver               [C] Taskbar Setting
Echo     [4] Manage Network              [D] Windows Security 
Echo     [5] Manage Windows ISO          [E] Windows Setting
Echo     [6] Manage Microsoft License    [F] Windows Update
Echo     [7] Download and Install        [G] Windows Utility 
Echo     [8] Automatic Process           [H] Fix Printer Error
Echo     [9] Template                    [I] Help
Echo     [0] Exit                        [J] Shutdown ^& Restart
CHOICE /c 0123456789ABCDEFGHIJZ /n /m "--------------- (^_^) Your Wishes Come True (^_^) ---------------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDEFGHIJZ"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.%MenuIndex%
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.1
cls 
Echo ---------------------- AVL.1. Personal Computer Information -----------------------
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject -ClassName win32_bios).Serialnumber"') do Set "Serial=%%b"
Echo %Serial%|clip 
Echo ----- Sent Serial to Clipboard
Echo ----- Getting Windows Version
For /F "tokens=4 delims=.[]" %%A in ('ver') do Set "WinVer=%%A"
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject Win32_OperatingSystem).Caption"') do Set "OsName=%%b"
For /F "tokens=3,4" %%b in ('ver') do Set "Version=%%b %%c"
For /F "tokens=3" %%b in ('Reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion') do Set OSVersion=%%b
Echo ----- Getting Office Version
For /F "tokens=2,*" %%I in ('Reg query "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" /v ProductReleaseIds 2^>nul') do Set OfficeVersion=%%J
For /F %%b in ('Powershell -Command $Env:OfficeVersion.Length') do Set OfficeVersionLen=%%b
If %OfficeVersionLen% LEQ 3 Set "OfficeVersion=Not_Available"
For /F "tokens=*" %%b in ('Powershell -command "(Get-InstalledLanguage).languageid"') do Set languageid=%%b
Echo ----- Getting CPU Information
For /F "tokens=*" %%b in ('Powershell -command "(Get-CimInstance -ClassName Win32_Processor).Name"') do Set "CPU=%%b"
For /F "tokens=*" %%b in ('Powershell -command "[Math]::Round((Get-CimInstance -ClassName Win32_Processor).MaxClockSpeed / 1000, 2)"') do Set "MaxClockSpeed=%%b"
For /F "tokens=*" %%b in ('Powershell -command "(Get-CimInstance -ClassName Win32_Processor).NumberOfCores"') do Set "NumberOfCores=%%b"
For /F "tokens=*" %%b in ('Powershell -command "(Get-CimInstance -ClassName Win32_ComputerSystem).Model"') do Set "Model=%%b"
Echo ----- Getting RAM Information
For /F "tokens=*" %%b in ('Powershell -command "[Math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)"') do Set "TPMemory=%%b"
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject -Class Win32_PhysicalMemory).ConfiguredClockSpeed"') do Set "BUS=%%b"
Echo ----- Getting Manufacturer Information
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject win32_bios).Manufacturer"') do Set "Manufacturer=%%b"
Echo ----- Getting GPU Information
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject -ClassName win32_VideoController).Description"') do Set "GPUDescription=%%b"
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject -ClassName win32_VideoController).VideoModeDescription"') do Set "VideoModeDescription=%%b"
Echo ----- Getting RAM Information
For /F "tokens=*" %%b in ('Powershell -command "[Math]::Round((Get-WmiObject -ClassName win32_VideoController).AdapterRAM / 1GB, 2)"') do Set "AdapterRAM=%%b"
If /i "%Processor_Architecture%" equ "AMD64" (Set "Architecture=64-bit")
If /i "%Processor_Architecture%" equ "x86" (Set "Architecture=32-bit")
If /i "%Processor_Architecture%" equ "ARM64" (Set "Architecture=ARM64")
Echo ----- Getting Antivirus Information
Set "antivirus="
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct).displayName"') do Set "antivirus=%antivirus%, %%b"
Set "antivirus=%antivirus:~2%"
cls
Echo ---------------------- AVL.1. Personal Computer Information -----------------------
Echo   Manufacturer      : %Manufacturer% ^| Model: %Model% ^| Serial: %Serial%
Echo   CPU Name          : %CPU% %MaxClockSpeed%GHz
Echo   Number Of Cores   : %NumberOfCores% ^| Number Of Logical Processors: %NUMBER_OF_PROCESSORS% 
Echo   Current Username  : %USERNAME% ^| Computer Name: %COMPUTERNAME%
Echo   Physical Memory   : %TPMemory% GB (RAM BUS: %BUS% MT/s)  
Echo   GPU Description   : %GPUDescription% (GPU AdapterRAM: %AdapterRAM% GB)  
Echo   Video Mode        : %VideoModeDescription%
Echo   Operating System  : %OsName% %OSVersion% %Version%
Echo   OS Language       : %languageid% ^| Office Version: %OfficeVersion%
Echo   Firmware Type     : %FirmwareType% (%Architecture%) ^| Antivirus: %antivirus%
Echo.
Echo ------------------------------ Hard Disk Information ------------------------------
PowerShell -NoProfile -Command "Get-Partition | ForEach-Object { $d = Get-Disk -Number $_.DiskNumber -EA SilentlyContinue; $v = Get-Volume -Partition $_ -EA SilentlyContinue; $blStatus = 'N/A'; if ($_.DriveLetter) { $blv = Get-BitLockerVolume -MountPoint ($_.DriveLetter + ':') -EA SilentlyContinue; if ($blv) { $blStatus = $blv.VolumeStatus; if ($blv.VolumeStatus -like '*InProgress') { $blStatus = \"$($blv.VolumeStatus) ($($blv.EncryptionPercentage)%%)\" } } }; [PSCustomObject]@{ Disk = $_.DiskNumber; Partition = $_.PartitionNumber; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; Style = $d.PartitionStyle; FileSystem = $v.FileSystem; BitLocker = $blStatus; Drive = $_.DriveLetter } } | Sort-Object Disk, Partition | Format-Table -AutoSize"
Echo ------------------------------- Network Information -------------------------------
powershell -NoProfile -Command "Get-NetAdapter | Select InterfaceDescription, MacAddress, LinkSpeed, @{n='Internet';e={ $p = Get-NetConnectionProfile -InterfaceIndex $_.IfIndex -ErrorAction SilentlyContinue; if ($p -and (($p.IPv4Connectivity -eq 'Internet') -or ($p.IPv6Connectivity -eq 'Internet'))) {'Yes'} else {'No'} }} | ft -AutoSize"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.2
Set "AVLBackMenu=AVL.2"
Set "FileDel="
Set "FolderDel="
cls
Echo --------- AVL.2. Manage Bitlocker ---------
Echo   [1] Turn Off Bitlocker All Partitions
Echo   [2] Turn On Bitlocker All Partitions
Echo   [3] Export Bitlocker Recovery Keys
Echo   [4] Check Bitlocker Status
Echo   [5] Open Device Encryption Setting
Echo   [0] Return to the previous menu
CHOICE /c 123450 /n /m "---- (^_^) Your Wishes Come True (^_^) ----"
Set /A Index=%ErrorLevel%-1
Set "List=123450"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.2.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.2.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.2.1
cls
Echo ----------- AVL.2.1. Turn Off Bitlocker All Partitions -----------
Call :AVL.TurnOffBitlocker
Powershell "Get-BitLockerVolume | Select-Object VolumeType, MountPoint, CapacityGB, VolumeStatus, ProtectionStatus | Format-Table"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.2.2
cls
Echo ----------- AVL.2.2. Turn On Bitlocker All Partitions -----------
For /F "tokens=2" %%b in ('manage-bde -status ^| findstr /b /c:"Volume"') do (
	Echo Turn On Bitlocker - Drive %%b
	manage-bde -on %%b 
	Echo ----------
)
Powershell "Get-BitLockerVolume | Select-Object VolumeType, MountPoint, CapacityGB, VolumeStatus, ProtectionStatus | Format-Table"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.2.3
cls
Echo ----------- AVL.2.3. Export Bitlocker Recovery Keys -----------
If not exist BitlockerRecovery.txt (
	Echo ===== BITLOCKER RECOVERY KEY =====>BitlockerRecovery.txt
)

Echo ----- Back up %DATE% %TIME% ----->>BitlockerRecovery.txt

For /F "tokens=2" %%b in ('manage-bde -status ^| findstr /b /c:"Volume"') do (
	Echo Get Recovery Key - Drive %%b
	manage-bde -protectors -get %%b
	Echo ----------
	manage-bde -protectors -get %%b >>BitlockerRecovery.txt
)

Set "Ans1="
Set /p Ans1="> To export file, enter Y for yes: "

If /i "%Ans1%" EQU "y" (
	Start notepad BitlockerRecovery.txt
) Else (
	Del BitlockerRecovery.txt
)

Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.2.4
Cls
Echo ----------- AVL.2.4. Check Bitlocker Status -----------
manage-bde -status | findstr /ri /c:"Encryption Method:" | findstr /vi /c:"None" >nul && set "x=true" || set "x=false"
If "%x%" EQU "true" (Echo Bitlocker is ON) else (Echo Bitlocker is OFF)
Powershell "Get-BitLockerVolume | Select-Object VolumeType, MountPoint, CapacityGB, VolumeStatus, ProtectionStatus | Format-Table"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.2.5
Echo ----------- AVL.2.5. Open Device Encryption Setting -----------
%windir%\explorer.exe shell:::{D9EF8727-CAC2-4e60-809E-86F80A666C91}
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3
Set "AVLBackMenu=AVL.3"
Set "FileDel="
Set "FolderDel="
cls
Echo --------------- AVL.3. Manage Drivers ---------------
Echo   [1] Get Non-Microsoft Driver Information 
Echo   [2] Export Network and SCSIAdapter Drivers
Echo   [3] Export Drivers
Echo   [4] Add Driver to Windows
Echo   [5] Delete Drivers
Echo   [6] Open Device Manager 
Echo   [7] Open Double-Driver Onedrive Sharing URL
Echo   [8] Open Snappy-Driver-Installer Homepage
Echo   [9] Open Snappy-Driver-Installer-Origin Homepage
Echo   [A] Open Driveroff.net category
Echo   [B] Open Drivers from Onedrive
Echo   [C] Download Intel RST
Echo   [D] Install SDIO
Echo   [E] Install Display Driver Uninstaller
Echo   [F] Install Intel Driver Support Assistant
Echo   [G] Install Driver Store Explorer
Echo   [H] Install Driver Identifier
Echo   [I] Install NVIDIA app
Echo   [J] Install AMD app
Echo   [K] Open Driver Support Website
Echo   [0] Return to the previous menu
CHOICE /c 0123456789ABCDEFGHIJK /n /m "--------- (^_^) Your Wishes Come True (^_^) ---------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDEFGHIJK"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.3.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.1
cls
Echo ------------------ AVL.3.1. Get Non-Microsoft Driver Information ------------------
Powershell "Get-WmiObject Win32_PnPSignedDriver | where {$_.InfName -like 'oem*'} | Select DeviceName, DeviceClass, Manufacturer, InfName | Sort-Object -Property DeviceName | Format-Table"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.2
cls
Echo ------------------ AVL.3.2. Export Network and SCSIAdapter Drivers ------------------
If not exist Drivers md Drivers
Set "class=Net"
Echo Exporting Network driver...
If not exist Drivers\%class% md Drivers\%class%
For /F "tokens=3" %%b in ('pnputil /enum-drivers /class "%class%" ^| findstr /b /c:"Published Name"') do pnputil /export-driver %%b Drivers\%class%
Set "class=SCSIAdapter"
Echo Exporting %class% driver...
If not exist Drivers\%class% md Drivers\%class%
For /F "tokens=3" %%b in ('pnputil /enum-drivers /class "%class%" ^| findstr /b /c:"Published Name"') do pnputil /export-driver %%b Drivers\%class%
Dir Drivers\Net
Dir Drivers\%class%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.3
Set "AVLBackMenu=AVL.3.3"
Set "FileDel="
Set "FolderDel="
cls
Echo --------- AVL.3.3. Export Driver ---------
Echo   [1] AudioProcessingObject
Echo   [2] Biometric
Echo   [3] Bluetooth
Echo   [4] Camera
Echo   [5] Display
Echo   [6] Firmware
Echo   [7] HIDClass
Echo   [8] MEDIA
Echo   [9] Monitor
Echo   [A] Network (Wifi - Lan)
Echo   [B] SCSIAdapter (Intel RST VMD)
Echo   [C] SoftwareComponent
Echo   [D] System
Echo   [E] All Non-Microsoft Drivers
Echo   [F] All Include-Microsoft Drivers
Echo   [0] Go to the previous Menu
CHOICE /c 123456789ABCDEF0 /n /m "--- (^_^) Your Wishes Come True (^_^) ---"
If %ErrorLevel%==1 (Set "class=AudioProcessingObject") && (Goto ExportClassDriver)
If %ErrorLevel%==2 (Set "class=Biometric") && (Goto ExportClassDriver)
If %ErrorLevel%==3 (Set "class=Bluetooth") && (Goto ExportClassDriver)
If %ErrorLevel%==4 (Set "class=Camera") && (Goto ExportClassDriver)
If %ErrorLevel%==5 (Set "class=Display") && (Goto ExportClassDriver)
If %ErrorLevel%==6 (Set "class=Firmware") && (Goto ExportClassDriver)
If %ErrorLevel%==7 (Set "class=HIDClass") && (Goto ExportClassDriver)
If %ErrorLevel%==8 (Set "class=MEDIA") && (Goto ExportClassDriver)
If %ErrorLevel%==9 (Set "class=Monitor") && (Goto ExportClassDriver)
If %ErrorLevel%==10 (Set "class=Net") && (Goto ExportClassDriver)
If %ErrorLevel%==11 (Set "class=SCSIAdapter") && (Goto ExportClassDriver)
If %ErrorLevel%==12 (Set "class=SoftwareComponent") && (Goto ExportClassDriver)
If %ErrorLevel%==13 (Set "class=System") && (Goto ExportClassDriver)
If %ErrorLevel%==14 Goto AVL.3.3.E
If %ErrorLevel%==15 Goto AVL.3.3.F
If %ErrorLevel%==16 Goto AVL.3

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:ExportClassDriver
CLS
Echo ------ AVL.3.3. Export %class% driver ------
If not exist Drivers\%class% md Drivers\%class%
For /F "tokens=3" %%b in ('pnputil /enum-drivers /class "%class%" ^| findstr /b /c:"Published Name"') do pnputil /export-driver %%b Drivers\%class%
Dir Drivers\%class%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.3.E
cls
Echo ------------ AVL.3.3.E All Non-Microsoft Drivers ------------
Echo Export Non-Microsoft Drivers...
If not exist Drivers\NonMicrosoft md Drivers\NonMicrosoft
For /F "tokens=3" %%b in ('pnputil /enum-drivers ^| findstr /b /c:"Published Name"') do (
	If not exist Drivers\NonMicrosoft\%%b md Drivers\NonMicrosoft\%%b
	pnputil /export-driver %%b Drivers\NonMicrosoft\%%b
)
Dir Drivers\NonMicrosoft
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.3.F
Cls
Echo ------------ AVL.3.3.F All Include-Microsoft Drivers ------------
Echo Export All Drivers...
If not exist Drivers md Drivers
pnputil /export-driver * Drivers
Dir Drivers
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.4
cls
Echo ------------ AVL.3.4. Add Driver to Windows ------------
Reg Query "HKLM\System\CurrentControlSet\Control\MiniNT" >nul 2>&1
If %ErrorLevel% EQU 0 (
	Echo This is WinPE.
	Call :AVL.AddDriverInWinPE
	Goto :EOF
)

If exist "Drivers" (
	pnputil /add-driver "Drivers\*.inf" /subdirs /install
	Call :AVL.Finish "Added driver"
)
Set "DriverPath="
Set /p "DriverPath=> Input driver path (press Enter to exit): "
If "!DriverPath!" equ "" (Goto !AVLBackMenu!)
If not exist "!DriverPath!" (Call :AVL.Finish "Path not found")
pnputil /add-driver "!DriverPath!\*.inf" /subdirs /install
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.AddDriverInWinPE
Set "DriverPath="
Set /p "DriverPath=> Input driver path (press Enter to exit): "
If "!DriverPath!" equ "" (Goto !AVLBackMenu!)
If not exist "!DriverPath!" (Call :AVL.Finish "Path not found")

For %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) Do (
    If Exist "%%d:\Windows\System32" (
	Call :AVL.AddDriverInWinPE.1 "%%d:"
    )
)
Call :AVL.Finish "No Windows installation found"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.AddDriverInWinPE.1
Set "OSDrive=%~1"
DISM /Image:"%OSDrive%\" /Add-Driver /Driver:"%DriverPath%" /Recurse /ForceUnsigned
If !ERRORLEVEL! equ 0 (
    Echo Drivers added successfully to %OSDrive%
) Else (
    Echo Failed to add drivers to %OSDrive% (Error: !ERRORLEVEL!)
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.5
cls
Echo ------------ AVL.3.5. Delete Drivers ------------
Powershell "Get-WmiObject Win32_PnPSignedDriver | where {$_.InfName -like 'oem*'} | Select DeviceName, DeviceClass, Manufacturer, InfName | Sort-Object -Property DeviceName | Format-Table"
Goto AVL.3.5.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.5.1
Set "InfName="
Set /p "InfName=> Input InfName to Delete (press Enter to exit): "
If "!InfName!" EQU "" Goto !AVLBackMenu!
Echo You delete Driver %InfName% may cause system error.
CHOICE /c 1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ /n /m "----- Press Y For Yes, Press any key For No ? "
If "%ErrorLevel%"=="35" pnputil /delete-driver %InfName% /force /uninstall 
Goto AVL.3.5.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.6 
Start devmgmt.msc
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.7
Start "" "https://glennsferryschools-my.sharepoint.com/:u:/g/personal/billgates_glennsferryschools_onmicrosoft_com/EbQpZ2J2DL9Fk7iuRfQzVl4BofqJzOWeSALwcgzole89nw"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.8
Start "" "https://sdi-tool.org/download/"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.9
Start "" "https://www.glenn.delahoy.com/snappy-driver-installer-origin"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.A
Start "" "https://driveroff.net/category/"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.B
Start "" "https://glennsferryschools-my.sharepoint.com/:f:/g/personal/billgates_glennsferryschools_onmicrosoft_com/ErAREQmlsxtIld_gHxHVrLIBvxIPk8xGYwfQWNaSBju89Q"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.C
Start "" "https://www.station-drivers.com/index.php/en/component/remository/Drivers/Intel/Rapid-Storage-Technology-(RST)/Drivers/lang,en-gb/"
Start "" "https://www.intel.com/content/www/us/en/support/products/55005/technologies/intel-rapid-storage-technology-intel-rst.html"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.D
cls
Echo ------------ AVL.3.D. Auto Install SDI-Origin ------------
Set "URL=https://www.glenn.delahoy.com/snappy-driver-installer-origin/"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "(Select-String -Path a.txt -Pattern '/downloads/sdio/SDIO_\d+\.\d+\.\d+\.\d+\.zip').Matches.Value"') do (Set "URL=https://www.glenn.delahoy.com%%A")
Del a.txt
Set "File=SDIO.zip"
Set "FileDel=%File%"
Set "FolderDel=SDIO"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Running %File%
For /r "SDIO" %%f in (SDIO_R*.exe) do @Start "" /D"SDIO" "%%~nxf"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.E
cls
Echo ------------ AVL.3.E. Display Driver Uninstaller ------------
Set "DDUURL=https://www.wagnardsoft.com/display-driver-uninstaller-ddu-"
Set "URL=%DDUURL%"
Set "File=DDU.TXT"
Set "FileDel=%File%"
Set "FolderDel=DDU"
Call :AVLDownload
For /F "delims=" %%A in ('Powershell -Command "(Get-Content DDU.txt | Select-String 'Download-Display-Driver-Uninstaller-DDU-(\d+)').Matches.Groups[1].Value"') do Set "result=%%A"
Del %File%
Set "X=%result%"
Set "Y=%X:~0,2%.%X:~2,1%.%X:~3,1%.%X:~4,1%"
Set "URL=https://www.wagnardsoft.com/DDU/download/DDU%%20v%Y%.exe"
Echo %URL%
Set "File=DDU.EXE"
Set "FileDel=%File%"
Set "FolderDel=DDU"
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Echo -
Echo Press Extract button...
pause
If exist "DDU v%y%\Display Driver Uninstaller.exe" (Start "" "DDU v%y%\Display Driver Uninstaller.exe")
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.F
cls
Echo ------------ AVL.3.F. Intel Driver Support Assistant ------------
Call :AVL.InstallIntelDriverSupport
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.InstallIntelDriverSupport
Set "URL=https://dsadata.intel.com/installer"
Set "File=IntelInstaller.EXE"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
GoTo :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.G
cls
Echo ------------ AVL.3.G. Install Driver Store Explorer ------------
Set "URL=https://github.com/lostindark/DriverStoreExplorer/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Del a.txt
Set "URL=https://github.com/lostindark/DriverStoreExplorer/releases/download/%t1%/DriverStoreExplorer.%t1%.zip"
Set "File=DriverStoreExplorer.zip"
Set "FileDel=%File%"
Set "FolderDel=DriverStoreExplorer"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo Run Driver Store Explorer ...
Start DriverStoreExplorer\Rapr.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.H
cls
Echo ------------ AVL.3.H. Install Driver Identifier ------------
Set "URL=https://www.driveridentifier.com/files/driveridentifier_setup.exe"
Set "File=DriverIdentifier.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.I
CLS
Echo -------------- AVL.3.I. NVIDIA app --------------
Call :AVL.InstallNvidiaApp
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.InstallNvidiaApp
Echo ----- Getting the latest Version
Set "URL=https://www.nvidia.com/en-us/software/nvidia-app/"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
:: Find https://us.download.nvidia.com/nvapp/client/11.0.5.245/NVIDIA_app_v11.0.5.245.exe
For /f "delims=" %%A in ('powershell -NoProfile -Command "(Select-String -Path 'a.txt' -Pattern 'https://us.download.nvidia.com/nvapp/client/[\d\.]+/NVIDIA_app_v[\d\.]+\.exe' -AllMatches | Select-Object -First 1).Matches[0].Value"') do set "Url=%%A"
Del a.txt
Set "File=NVIDIA_app.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
GoTo :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.J
CLS
Echo -------------- AVL.3.J. AMD app --------------
Call :AVL.InstallAmdApp
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.InstallAmdApp
Echo ----- Getting the latest Version
Set "URL=https://www.amd.com/en/support/download/drivers.html"
aria2c ^
  --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" ^
  --header="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ^
  --header="Accept-Language: en-US,en;q=0.9" ^
  --referer="https://www.amd.com/en/support" ^
  -o a.html "https://www.amd.com/en/support/download/drivers.html"

For /f "delims=" %%A in ('powershell -NoProfile -Command "(Select-String -Path 'a.html' -Pattern 'https://drivers.amd.com/drivers/installer/[\d\.]+/whql/amd-software-adrenalin-edition-[\d\.]+-minimalsetup-.*?\.exe' -AllMatches | Select-Object -First 1).Matches[0].Value"') do set "URL=%%A"
Del a.html

aria2c ^
  --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" ^
  --header="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ^
  --header="Accept-Language: en-US,en;q=0.9" ^
  --referer="https://www.amd.com/en/support" ^
  -o AMD_app.exe "%URL%"

Set "File=AMD_app.exe"
Set "FileDel=%File%"
Set "FolderDel="
Echo ----- Running %File%
Start %File%
GoTo :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.3.K
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject -ClassName win32_bios).Serialnumber"') do Set "Serial=%%b"
Echo %Serial%|clip 
cls
Echo ---- AVL.3.K. Driver Support Website ----
Echo (Serial Number is sent to the Clipboard)
Echo   [1] Dell
Echo   [2] HP
Echo   [3] Lenovo
Echo   [4] Asus
Echo   [5] Acer
Echo   [6] MSI
Echo   [0] Return to the previous menu
CHOICE /c 1234560 /n /m "--- (^_^) Your Wishes Come True (^_^) ---"
If %ErrorLevel%==1 (Start "" "https://www.dell.com/support/home/en-us?app=drivers") & Goto !AVLBackMenu!
If %ErrorLevel%==2 (Start "" "https://support.hp.com/us-en/drivers/laptops") & Goto !AVLBackMenu!
If %ErrorLevel%==3 (Start "" "https://pcsupport.lenovo.com/us/en") & Goto !AVLBackMenu!
If %ErrorLevel%==4 (Start "" "https://www.asus.com/support/download-center/") & Goto !AVLBackMenu!
If %ErrorLevel%==5 (Start "" "https://www.acer.com/us-en/support/drivers-and-manuals") & Goto !AVLBackMenu!
If %ErrorLevel%==6 (Start "" "https://www.msi.com/support/download") & Goto !AVLBackMenu!
If %ErrorLevel%==7 Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.4
Set "AVLBackMenu=AVL.4"
Set "FileDel="
Set "FolderDel="
cls
Echo --------- AVL.4. Manage Network ---------
Echo   [1] Export Wifi Profiles
Echo   [2] Import Wifi Profiles
Echo   [3] Show All Wifi Profiles
Echo   [4] Show Wifi Information
Echo   [5] Scan IP in Lan Network
Echo   [6] Get information of Network Adapter
Echo   [7] Delete Wifi profile
Echo   [0] Go to the previous Menu
CHOICE /c 12345670 /n /m "--- (^_^) Your Wishes Come True (^_^) ---"
If %ErrorLevel%==1 Goto AVL.4.1
If %ErrorLevel%==2 Goto AVL.4.2
If %ErrorLevel%==3 Goto AVL.4.3
If %ErrorLevel%==4 Goto AVL.4.4
If %ErrorLevel%==5 Goto AVL.4.5
If %ErrorLevel%==6 Goto AVL.4.6
If %ErrorLevel%==7 Goto AVL.4.7
If %ErrorLevel%==8 Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.4.1
If not exist "Wifi" mkdir "Wifi"
cls
Echo ------------ AVL.4.1. Export Wifi Profiles ------------
Echo Exporting Wifi Profiles ...
netsh wlan export profile key=clear folder=Wifi
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.4.2
cls
Echo ------------ AVL.4.2. Import Wifi Profiles ------------
If not exist "Wifi" (
	Echo No Wifi Profiles to Import ...	
	Call :AVL.Finish ""
	
)
Echo Importing Wifi Profiles to Windows ...
For /F %%b in ('Dir /b Wifi') do (netsh wlan add profile filename="Wifi\%%b")
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.4.3
cls
Echo ------------ AVL.4.3. Show Wifi Profiles ------------
Echo ----- List of Wifi Profiles -----
If Not Exist "WiFi_Profiles.txt" Echo ----- List of Wifi Profiles ----->"WiFi_Profiles.txt"
Echo ----- Export Time: %DATE% %TIME% ----->>"WiFi_Profiles.txt"
For /F "tokens=2 delims=:" %%A in ('netsh wlan show profiles ^| findstr "All User Profile"') do (
    Set "WIFI_NAME=%%A"
    Set "WIFI_NAME=!WIFI_NAME:~1!"
    For /F "tokens=2 delims=:" %%B in ('netsh wlan show profile name^="!WIFI_NAME!" key^=clear ^| findstr "Key Content"') do (
        Set "WIFI_PASS=%%B"
        Set "WIFI_PASS=!WIFI_PASS:~1!"
        Echo WiFi ID : !WIFI_NAME!
        Echo Password: !WIFI_PASS!
        Echo ---------------------
        Echo WiFi ID : !WIFI_NAME! >>"WiFi_Profiles.txt"
        Echo Password: !WIFI_PASS! >>"WiFi_Profiles.txt"
        Echo --------------------- >>"WiFi_Profiles.txt"
    )
)
Set "ans2="
Set /p "ans2=> To export result to WiFi_Profiles.txt, type Y and press Enter: "
If /i "%ans2%" NEQ "y" (
	Del WiFi_Profiles.txt
) Else (
	Start notepad "WiFi_Profiles.txt"
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.4.4
cls
Echo ------------ AVL.4.4. Show Wifi Information ------------
netsh wlan show interfaces | findstr /C:"Name" >nul
If %errorlevel% NEQ 0 (
    	Echo No Wi-Fi adapter has been detected.
	Call :AVL.Finish ""
)
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "Description"') do Set "Description=%%i"
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "State"') do Set "State=%%i"
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "Radio"') do Set "RadioType=%%i"
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "Authentication"') do Set "Authentication=%%i"
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "Connection"') do Set "ConnectionMode=%%i"
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "Receive"') do Set "ReceiveRate=%%i"
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "Transmit"') do Set "TransmitRate=%%i"
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "Signal"') do Set "Signal=%%i"
For /F "tokens=2 delims=:" %%i in ('netsh wlan show interfaces ^| findstr "Band"') do Set "Band=%%i"
For /F "tokens=4 delims=: " %%i in ('netsh wlan show profile ^| findstr "All User Profile"') do Set "WifiName1=%%i"
For /F "tokens=3 delims=: " %%i in ('netsh wlan show profile name^="!WifiName1!" key^=clear ^| findstr "Key Content"') do (Set "Pass1=%%i")
Echo   Description    :%Description%
Echo   State          :%State%
Echo   Wifi ID        : %WifiName1%
Echo   Wifi Password  : %Pass1%
Echo   Authentication :%Authentication%
Echo   Radio Type     :%RadioType%
Echo   Connection Mode:%ConnectionMode%
Echo   Band           :%Band%
Echo   Receive Rate   :%ReceiveRate%
Echo   Transmit Rate  :%TransmitRate%
Echo   Signal Strength:%Signal%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.4.5
cls
Echo ------------ AVL.4.5. Scan IP in Lan Network ------------
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| find "IPv4"') do set myip=%%i
set myip=%myip: =%
for /f "tokens=1-3 delims=." %%a in ("%myip%") do set networkbase=%%a.%%b.%%c

echo Your IP is %myip%
echo Scanning network %networkbase%.X for active devices.
Set /p "X=Enter a value for X to scan (1 to 254): "
set active_ips=0
Call :AVL_Numberic %X%
IF %X% LSS 1 (Call :AVL.Finish "Input invalid")
IF %X% GTR 255 (Call :AVL.Finish "Input invalid")
:: Loop through all addresses, print the ones that reply, and count them
for /L %%i in (1,1,%X%) do (
    ping -n 1 !networkbase!.%%i -w 200 | find "Reply from" >nul && (
        set /a active_ips+=1
        IF !active_ips! lss 10 echo IP  !active_ips!: !networkbase!.%%i
        IF !active_ips! GEQ 10 echo IP !active_ips!: !networkbase!.%%i
    )
)
arp -d * >nul 2>&1   rem clear stale ARP cache
echo.
echo Found !active_ips! active devices on the network.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.4.6
cls
Echo ------------ AVL.4.6. Get information of Network Adapter ------------
powershell -NoProfile -Command "Get-NetAdapter | Select Name, InterfaceDescription, MacAddress, LinkSpeed"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.4.7
cls
Echo ------------ AVL.4.7. Delete Wifi profile ------------
Set t=0
For /F "tokens=2 delims=:" %%b in ('netsh wlan show profiles ^| find "All User Profile"') do (
	Set /a t+=1
	set "name=%%b"
	set "name=!name:~1!"
	Echo Profile !t!: !name!
	Set "WifiProfile[!t!]=!name!"
)
Set "No="
Set /p "No=> Input Number of profile to delete (press Enter to exit):"
If "!No!" EQU "" (Goto !AVLBackMenu!)
Call :AVL_Numberic %No%
If %No% Lss 1 (Call :AVL.Finish "Input invalid")
If %No% Gtr %t% (Call :AVL.Finish "Input invalid")
netsh wlan delete profile name="!WifiProfile[%No%]!"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5
cd /d "%~dp0"
Set "AVLBackMenu=AVL.5"
Set "FileDel="
Set "FolderDel="
cls
Echo -------- AVL.5. Manage Windows ISO --------
Echo   [1] FIDO
Echo   [2] Hasleo Windows ISO Downloader
Echo   [3] Open PITVN Resources 
Echo   [4] Open MassGrave.Dev 
Echo   [5] Media Creation Tool - Windows 10 
Echo   [6] Media Creation Tool - Windows 11
Echo   [7] Manage Windows ISO 
Echo   [8] Bypass Windows 11 requirements
Echo   [9] Install DISMTools
Echo   [A] Install NTLite 
Echo   [B] Install WinMerge
Echo   [C] Calculate CheckSum
Echo   [D] Download Windows ESD Image
Echo   [E] Download ISO from rg-adguard.net
Echo   [0] Return to the previous Menu
CHOICE /c 0123456789ABCDE /n /m "---- (^_^) Your Wishes Come True (^_^) ----"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDE"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.5.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.1
cls
Echo ------- AVL.5.1. FIDO -------
If not exist "Fido.zip" Call :AVL.FIDOdownload
For /F %%b in ('dir /a:d /b "Fido\Fido*"') do Set "FidoPath=%~dp0Fido\%%b"
Echo ----- Running Fido
Powershell "%FidoPath%\Fido.ps1"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.FIDOdownload
Set "URL=https://github.com/pbatard/Fido/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
If not exist "a.txt" Del a.txt
Set "URL=https://github.com/pbatard/Fido/archive/refs/tags/%t1%.zip"
Set "File=Fido.zip"
Set "FileDel=%File%"
Set "FolderDel=Fido"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
If exist "Fido.zip" (Del Fido.zip)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.2
cls
Echo ------- AVL.5.2. Hasleo Windows ISO Downloader -------
:: Get windows-iso-downloader from https://www.easyuefi.com/windows-iso-downloader/windows-iso-downloader.html
Set "URL=https://www.easyuefi.com/windows-iso-downloader/downloads/win-iso-downloader.zip"
Set "File=Hasleo.zip"
Set "FileDel=%File%"
Set "FolderDel=Hasleo"
Call :AVLDownload
Echo ----- Extracting Hasleo Windows ISO Downloader
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Running Hasleo Windows ISO Downloader
If exist "%windir%\SysWOW64" (Start "" "Hasleo\win-iso-downloader\x64\WinISODownloader.exe") ELSE (Start "" "Hasleo\win-iso-downloader\x86\WinISODownloader.exe")
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.3
Start "" "https://docs.google.com/spreadsheets/d/14-j0xDo6PUk55BweSbUqQra6w5cCftvVVvHcVomHDtU/edit?gid=0#gid=0"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.4
Set "link1=https://massG"
Set "link2=rave.dev"
Start "" "%link1%%link2%/genuine-installation-media"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.5
cls
Echo ------- AVL.5.5. Media Creation Tool - Windows 10 -------
Set "URL=https://go.microsoft.com/fwlink/?linkid=691209"
Set "File=MediaCreationTool.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo VK7JG-NPHTM-C97JM-9MPGT-3V66T|clip
Echo ----- Running %File%
Echo Input Product Key VK7JG-NPHTM-C97JM-9MPGT-3V66T (Product key is sent to Clipboard)
Start MediaCreationTool.exe /Eula Accept /Retail /MediaArch x64 /MediaLangCode en-US /MediaEdition Professional
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.6
cls
Echo ------- AVL.5.6. Media Creation Tool - Windows 11 -------
Set "URL=https://go.microsoft.com/fwlink/?linkid=2156295"
Set "File=MediaCreationTool.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo VK7JG-NPHTM-C97JM-9MPGT-3V66T|clip
Echo ----- Running %File%
Echo Input Product Key VK7JG-NPHTM-C97JM-9MPGT-3V66T (Product key is sent to Clipboard)
Start MediaCreationTool.exe /Eula Accept /Retail /MediaArch x64 /MediaLangCode en-US /MediaEdition Professional
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7
Set "AVLBackMenu=AVL.5.7.Menu"
Set "FileDel="
Set "FolderDel="
Set "IsoSelect=False"
Set "ExtractSelect=False"
Set "WimSelect=False"
Goto AVL.5.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.Menu
cls
Echo -------------- AVL.5.7. Manage Windows ISO --------------
Echo   [1] Select Windows ISO (%IsoSelect%)
Echo   [2] Extract Windows ISO (%ExtractSelect%)
Echo   [3] Select Wim file (%WimSelect%)
Echo   [4] List all index images
Echo   [5] Delete One Index Image From Wim (Keep All Others)
Echo   [6] Delete All Index Images From Wim (Keep One Image)
Echo   [7] Add Drivers to Index Image
Echo   [8] Remove Drivers from Index Image
Echo   [9] Add bypass requirements to Wim
Echo   [A] Remove Bloatware From Index Image
Echo   [B] Add AutoUnattend.xml to ISO path
Echo   [C] Create ISO from Wim Path
Echo   [0] Go to the previous menu
CHOICE /c 123456789ABC0 /n /m "----------- (^_^) Your Wishes Come True (^_^) -----------"
Set /A Index=%ErrorLevel%-1
Set "List=123456789ABC0"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.5.7.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.0
Goto AVL.5

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.1
cls
Echo ------- AVL.5.7.1. Select Windows ISO -------
Echo Example: "D:\Folder\Windows10.iso"
Set /p ISOPath="Input Path of Windows ISO (Enter Nothing To Exit): "
If "%ISOPath%"=="" Goto !AVLBackMenu!
Set ISOPath=!ISOPath:"=!
If not exist "%ISOPath%" (
	Set "IsoSelect=False"
	Echo The ISO file was not found ...
	Call :AVL.Finish ""	
)
Echo The ISO file is found ...
Set "IsoSelect=True"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.2
cls
Echo ------- AVL.5.7.2. Extract Windows ISO -------
If "%IsoSelect%"=="False" (
	Echo No Windows ISO is selected. Press any key to select a Windows ISO file.
	Pause
	Goto AVL.5.7.1
)
Set /p ExtractPath="Input the destination path for ISO extraction (Enter Nothing To Exit): "
If "%ExtractPath%"=="" Call :%AVLBackMenu%
If not exist "%ExtractPath%" mkdir "%ExtractPath%"
Powershell -Command "Mount-DiskImage -ImagePath '%ISOPath%'"
choice /T 5 /D Y /N > nul
For /f "tokens=*" %%I in ('Powershell -Command "(Get-DiskImage -ImagePath '%ISOPath%' | Get-Volume).DriveLetter"') do Set "MountDrive=%%I:"
If "%MountDrive%"=="" (
	Echo "Error: Failed to mount the ISO"
	Call :AVL.Finish ""
) 
xcopy "%MountDrive%\*" "%ExtractPath%" /e /h /k
Powershell -Command "Dismount-DiskImage -ImagePath '%ISOPath%'"
Set "ExtractSelect=True"
Set "WimPath=%ExtractPath%\sources\install.wim"
Set "WimSelect=True"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.3
Set "err1=0"
cls
Echo ------- AVL.5.7.3. Select Wim file -------
Echo - Example: "D:\IsoExtract\sources\install.wim"
Echo - Input Nothing To Exit
Set /p WimPath="> Input Path of Wim: "
If "%WimPath%"=="" Goto !AVLBackMenu!
Set WimPath=!WimPath:"=!
Echo %WimPath% | findstr /i "\.wim" >nul
If not %errorlevel%==0 Set "err1=1"
If not exist "%WimPath%" Set "err1=1"
If "%err1%"=="1" (
	Set "WimSelect=False"
	Echo The Wim file was not found ...
	Call :AVL.Finish ""
)
Echo The Wim file is found ...
attrib -r "%WimPath%"
Set "WimSelect=True"
Set "ISOPath=!WimPath:\sources\install.wim=!"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.4
cls
Echo ------- AVL.5.7.4. List all index images -------
Echo.
Call :ListAllIndexImages
Echo.
Call :AVL.Finish ""

:ListAllIndexImages
If "%WimSelect%"=="False" (
	Echo No Wim File is selected.
	Call :AVL.Finish ""	
)
Set "count="
Set "Index="
Set "AllIndex="
Set "Name="
Set "AllName="
Echo Path: %WimPath%
Echo Index  Name
Echo -----  ----
For /f "tokens=1,* delims=:" %%A in ('DISM /Get-WimInfo /WimFile:"%WimPath%"') do (
	Set "Tag=%%A"
	Set "Value=%%B"
	Set "Tag=!Tag: =!"
	Set "Value=!Value:~1!"
 	If /I "!Tag!"=="Index" Set "Index=!Value!"
	If /I "!Tag!"=="Name" (
		Set /a "count+=1"
		Set "AllIndex=!Index! !AllIndex!"
		Set "AllName[!count!]=!Value!"
		Set "IndexArray[!count!]=!Index!"
		Set "Name=!Value!"
		If !Index! LSS 10 (Echo !Index!      !Name!) Else (Echo !Index!     !Name!)
    	)
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.5
Set "WimIndex="
cls
Echo ------- AVL.5.7.5. Delete One Index Image from Wim -------
Call :ListAllIndexImages
Echo.
Echo Input Index of Wim to Delete
Echo Input Nothing To Exit
Set /p WimIndex="> Your Wishes: "
If "%WimIndex%"=="" Goto !AVLBackMenu!
Echo %AllIndex% | findstr /c:"%WimIndex%" >nul
If %errorlevel% NEQ 0 (
	Echo Index is Not Valid
	Call :AVL.Finish ""	
)
Echo Image Index is Valid
DISM.exe /Delete-Image /ImageFile:"%WimPath%" /Index:%WimIndex%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.6
Set "WimIndex="
cls
Echo ------- AVL.5.7.6. Delete All Index Images From Wim (Keep One Image) -------
Call :ListAllIndexImages
Echo.
Set /p WimIndex="Input Index of Wim to Keep, Delete all other Images (Enter Nothing To Exit): "
If "%WimIndex%"=="" Goto !AVLBackMenu!
Echo %AllIndex% | findstr /c:"%WimIndex%" >nul
If %errorlevel% NEQ 0 (
	Echo Index is Not Valid
	Call :AVL.Finish ""	
)
Echo Image Index is Valid
For %%I in (%AllIndex%) do (
    	If not "%%I"=="%WimIndex%" (
		Echo Deleting Index %%I Image From Wim
		DISM.exe /Delete-Image /ImageFile:"%WimPath%" /Index:%%I
    	)
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.7
Set "WimIndex="
cls
Echo ------- AVL.5.7.7. Add Drivers to Index Image -------
Call :ListAllIndexImages
Echo.
Echo - Input index of wim to add Driver (Ex: 1 or 2).
Echo - Input "A" to add Driver to all index images.
Echo - Input nothing, press Enter to exit.
Set /p WimIndex="----- (^_^) Your Wishes Come True (^_^) -----"
If "%WimIndex%"=="" Goto !AVLBackMenu!
Set "WimIndex=!WimIndex:"=!"
Echo "%AllIndex% A"| findstr /i /c:"%WimIndex%" >nul
If %errorlevel% NEQ 0 (
	Echo Image Index is Not Valid
	Call :AVL.Finish ""
)
Echo Image Index is Valid
Echo.
Echo ----- Input Driver Folder
Echo D:\Software\PITVN_AVL\Drivers|clip
Set /p DriversFolder="Input Path of Folder to add Driver (Enter Nothing To Exit): "
If "%DriversFolder%"=="" Goto !AVLBackMenu!
Set "DriversFolder=!DriversFolder:"=!"
If not exist "%DriversFolder%" (
	Echo The Driver Folder was not found ...
	Call :AVL.Finish ""
)
Dir /b /s "%DriversFolder%\*.inf" >nul 2>&1
If %errorlevel% NEQ 0 (
	Echo %DriversFolder% does not contains driver files.
	Call :AVL.Finish ""	
)
Echo Driver Folder is Valid
Echo.
Set "MountPath=%~dp0WimMount"
If not exist "%MountPath%" mkdir "%MountPath%"
If /i "%WimIndex%"=="A" Call :AVL.5.7.7.All
Echo ----- Mounting index %WimIndex% from %WimPath%
Echo The process is time-consuming. Please wait For completion...
Dism /Mount-Image /ImageFile:"%WimPath%" /Index:%WimIndex% /MountDir:"%MountPath%"
If %errorlevel% NEQ 0 (
    	Echo Failed to mount WIM.
	Call :AVL.Finish ""	
)
Echo Mount index successfully.
Echo.
Echo ----- Adding drivers from %DriversFolder%
Echo The process is time-consuming. Please wait For completion...
Dism /Image:"%MountPath%" /Add-Driver /Driver:"%DriversFolder%" /Recurse /ForceUnsigned
If %errorlevel% NEQ 0 (
    	Echo Failed to add drivers.
   	Dism /UnMount-Image /MountDir:"%MountPath%" /Discard
	Call :AVL.Finish ""
	
)
Echo Add drivers successfully.
Echo.
Echo ----- Committing changes and unmounting
Echo The process is time-consuming. Please wait For completion...
Dism /UnMount-Image /MountDir:"%MountPath%" /Commit
If %errorlevel% NEQ 0 (
    	Echo Failed to add drivers.
   	Dism /UnMount-Image /MountDir:"%MountPath%" /Discard
	Call :AVL.Finish ""	
)
Echo Unmount successfully.
Echo.
Echo ----- Finished Adding Drivers to Index Image.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.7.All
Set "TotalIndex=0"
For %%i in (%AllIndex%) do (
    	Set /a TotalIndex+=1
)
For /l %%i in (1,1,!TotalIndex!) do (
    	Echo ----- Mounting index %%i
	Echo The process is time-consuming. Please wait For completion...
    	dism /Mount-Image /ImageFile:"%WimPath%" /Index:%%i /MountDir:"%MountPath%"
	If %errorlevel% NEQ 0 (
        	Echo Failed to mount index %%i
		Call :AVL.Finish ""		
    	)
	Echo ----- Adding drivers to index %%i
	Echo The process is time-consuming. Please wait For completion...
    	dism /Image:"%MountPath%" /Add-Driver /Driver:"%DriversFolder%" /Recurse /ForceUnsigned
	Echo ----- Committing changes and unmounting
	Echo The process is time-consuming. Please wait For completion...
    	dism /UnMount-Image /MountDir:"%MountPath%" /Commit
)
Echo Finished adding drivers to all indexes!
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.8
Set "WimIndex="
cls
Echo ------- AVL.5.7.8. Remove Drivers from Index Image -------
Call :ListAllIndexImages
Echo.
Echo - Input index of wim to remove Driver (Ex: 1 or 2).
Echo - Input nothing, press Enter to exit.
Set /p WimIndex="----- (^_^) Your Wishes Come True (^_^) -----"
If "%WimIndex%"=="" Goto !AVLBackMenu!
Set "WimIndex=!WimIndex:"=!"
Echo "%AllIndex%"| findstr /i /c:"%WimIndex%" >nul
If %errorlevel% NEQ 0 (
	Echo Image Index is Not Valid
	Call :AVL.Finish ""	
)
Echo Image Index is Valid
Echo.
Set "MountPath=%~dp0WimMount"
If not exist "%MountPath%" mkdir "%MountPath%"
If exist "%MountPath%\Windows" call :Mounting1
Echo ----- Mounting index %WimIndex% from %WimPath%
Echo The process is time-consuming. Please wait For completion...
Dism /Mount-Image /ImageFile:"%WimPath%" /Index:%WimIndex% /MountDir:"%MountPath%"
If %errorlevel% NEQ 0 (
    	Echo Failed to mount WIM.
	Call :AVL.Finish ""	
)
Echo Mount index successfully.
Echo.

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:Mounting1
Echo ----- Getting Driver information from Index %WimIndex%
DISM /Image:"%MountPath%" /Get-Drivers
Echo.
Echo - Input Published Name (from the list above) to remove driver from Index Image. 
Echo - Input nothing and press Enter to exit.
Set /p PublishedName="----- (^_^) Your Wishes Come True (^_^) -----"
If "%PublishedName%"=="" (
    	Echo Published Name is empty.
	call :Unmount1
)
Echo "%PublishedName%"| findstr /i /c:"\.inf" >nul
If %errorlevel% NEQ 0 (
    	Echo Published Name is Not Valid.
	call :Unmount1
)
Echo Published Name is Valid.
Echo.
Echo ----- Removing Driver from Index %WimIndex%
DISM /Image:"%MountPath%" /Remove-Driver /Driver:"%PublishedName%"

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:Unmount1
Echo ----- Committing changes and unmounting
Echo The process is time-consuming. Please wait For completion...
DISM /UnMount-Image /MountDir:"%MountPath%" /Commit
Set "FolderDel=%MountPath%"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.9
Set "WimIndex="
cls
Echo ------- AVL.5.7.9. Add bypass requirements to the Wim -------
Call :ListAllIndexImages
Echo.
Echo - Input index of wim to add bypass requirements (Ex: 1 or 2).
Echo - Input nothing, press Enter to exit.
Set /p WimIndex="----- (^_^) Your Wishes Come True (^_^) -----"
If "%WimIndex%"=="" Goto !AVLBackMenu!
Set "WimIndex=!WimIndex:"=!"
Echo "%AllIndex%"| findstr /i /c:"%WimIndex%" >nul
If %errorlevel% NEQ 0 (
	Echo Image Index is Not Valid
	Call :AVL.Finish ""
)
Echo Image Index is Valid
Echo.
Echo ----- Mounting index %WimIndex% from %WimPath%
Set "MountPath=%~dp0WimMount"
If not exist "%MountPath%" mkdir "%MountPath%"
Echo The process is time-consuming. Please wait For completion...
Dism /Mount-Image /ImageFile:"%WimPath%" /Index:%WimIndex% /MountDir:"%MountPath%"
If %errorlevel% NEQ 0 (
    	Echo Failed to mount WIM.
	Call :AVL.Finish ""	
)
Echo Mount index successfully.
Echo.
Echo ----- Load Offline Registry Hive
Reg load "HKLM\OfflineSystem" "%MountPath%\Windows\System32\config\SYSTEM" >nul
Echo ----- Add bypass login
Reg add "HKLM\OfflineSystem\Software\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d 1 /f >nul
Reg query "HKLM\OfflineSystem\Software\Microsoft\Windows\CurrentVersion\OOBE"
Echo ----- Add bypass windows 11 requirements
Reg add "HKLM\OfflineSystem\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f >nul
Reg add "HKLM\OfflineSystem\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f >nul
Reg add "HKLM\OfflineSystem\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f >nul
Reg query "HKLM\OfflineSystem\Setup\LabConfig"
Echo ----- Unload Offline Registry Hive
Reg unload "HKLM\OfflineSystem" >nul
Echo ----- Committing changes and unmounting
Echo The process is time-consuming. Please wait For completion...
DISM /UnMount-Image /MountDir:"%MountPath%" /Commit
Set "FolderDel=%MountPath%"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.A
Set "AVLBackMenu=AVL.5.7"
Set "WimIndex="
cls
Echo ------- AVL.5.7.A. Remove Bloatware From Index Image -------
Call :ListAllIndexImages
Echo.
Echo - Input index of wim to remove Bloatware (Ex: 1 or 2).
Echo - Input nothing and press Enter to exit.
Set /p WimIndex="----- (^_^) Your Wishes Come True (^_^) -----"
If "%WimIndex%"=="" Goto !AVLBackMenu!
Set "WimIndex=!WimIndex:"=!"
Echo "%AllIndex%"| findstr /i /c:"%WimIndex%" >nul
If %errorlevel% NEQ 0 (
	Echo Image Index is Not Valid
	Call :AVL.Finish ""	
)
Echo Image Index is Valid
Echo.
Echo ----- Mounting index %WimIndex% from %WimPath%
Set "MountPath=%~dp0WimMount"
If exist "%MountPath%\Windows" Call :AVL.5.7.A.1
If not exist "%MountPath%" mkdir "%MountPath%"
Echo The process is time-consuming. Please wait For completion...
Dism /Mount-Image /ImageFile:"%WimPath%" /Index:%WimIndex% /MountDir:"%MountPath%"
If %errorlevel% NEQ 0 (
    	Echo Failed to mount WIM.
	Call :AVL.Finish ""	
)
Echo Mount index successfully.
Echo.

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.A.1
Echo ----- Getting AppxPackages Name
Echo.
Echo Package Name
Echo ------------
For /F "tokens=2 delims=:" %%A IN ('DISM /Image:"%MountPath%" /Get-ProvisionedAppxPackages ^| FINDSTR /i /C:"PackageName"') DO (Echo %%A)
Echo.

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.A.2
Echo - Input Package Name to Remove from Index Image
Echo - Input nothing and press Enter to exit
Set /p PackageName1="----- (^_^) Your Wishes Come True (^_^) -----"
If Not defined PackageName1 (Goto AVL.5.7.A.3)
If "!PackageName1!" EQU "" (Goto AVL.5.7.A.3)
DISM /Image:"%MountPath%" /Remove-ProvisionedAppxPackage /PackageName:"%PackageName1%"
Goto AVL.5.7.A.2

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.A.3
Echo ----- Committing changes and unmounting
Echo The process is time-consuming. Please wait For completion...
Echo %MountPath%
DISM /UnMount-Image /MountDir:"%MountPath%" /Commit
Set "FolderDel=%MountPath%"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.B
Set "AutoUnattendPath="
cls
Echo ------- AVL.5.7.B. Add AutoUnattend.xml to ISO Path-------
If "%WimSelect%"=="False" (
	Echo No Wim File is selected.
	Call :AVL.Finish ""	
)
Echo - Input Path of AutoUnattend.xml
Echo - Input nothing and press Enter to exit
Echo - Ex: "D:\Folder\AutoUnattend.xml"
Set /p AutoUnattendPath="----- (^_^) Your Wishes Come True (^_^) -----"
Set "AutoUnattendPath=!AutoUnattendPath:"=!"
If "%AutoUnattendPath%"=="" Goto !AVLBackMenu!
If Not Exist "%AutoUnattendPath%" (
	Echo %AutoUnattendPath% is not found.
	Call :AVL.Finish "" 
)
ren "%AutoUnattendPath%" "autounattend.xml"
For %%i in ("%AutoUnattendPath%") do Set "Path1=%%~dpi"
If Exist "%ISOPath%\autounattend.xml" Ren "%ISOPath%\autounattend.xml" autounattend1.xml
xcopy "%Path1%\autounattend.xml" "%ISOPath%\" /Q /Y
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.7.C
cls
Echo ------- AVL.5.7.C. Create ISO from Wim Path -------
If "%WimSelect%"=="False" (
	Echo No Wim File is selected.
	Call :AVL.Finish ""	
)
winget --version >nul 2>&1
If %ErrorLevel% NEQ 0 Goto :AVL.7.U
dir C:\oscdimg.exe /s | find /i "%Processor_Architecture%" >Nul 2>&1
If %errorlevel% NEQ 0 (winget install --id=Microsoft.WindowsADK -e)
For /F "Tokens=2 delims=:" %%A IN ('dir C:\oscdimg.exe /s ^| find /i "%Processor_Architecture%"') DO Set "OscdimgPATH=C:%%A"
If exist "%~dp0NewWindows.iso" del "%~dp0NewWindows.iso"
If exist "%ISOPath%\boot\etfsboot.com" (
	"%OscdimgPATH%\oscdimg.exe" -o -m -u2 -bootdata:2#p0,e,b"%ISOPath%\boot\etfsboot.com"#pEF,e,b"%ISOPath%\efi\microsoft\boot\efisys.bin" "%ISOPath%" "%~dp0NewWindows.iso"
) Else (
	Echo Failed to make ISO.
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.8
cls
Echo ------- AVL.5.8. Bypass Windows 11 requirements -------
reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d 1 /f
If %ErrorLevel% EQU 0 (
    Echo Bypass added successfully to %1
) Else (
   Start Powershell iex (irm https://raw.githubusercontent.com/Win11Modder/Win11-Req-Bypass/main/Win11_Bypass.ps1) 
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.9
cls
Echo ------- AVL.5.9. Install DISMTools -------
Set "URL=https://github.com/CodingWonders/DISMTools/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Del a.txt
Set "URL=https://github.com/CodingWonders/DISMTools/releases/download/%t1%/dt_setup.exe"
Set "File=DISMTools_setup.exe.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running  %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.A
cls
Echo ------- AVL.5.A. Install NTLite -------
If exist "%windir%\SysWOW64" (
	Set "URL=https://downloads.ntlite.com/files/NTLite_setup_x64.exe"
) ELSE (
	Set "URL=https://downloads.ntlite.com/files/NTLite_setup_x86.exe"
)
Set "File=NTLiteSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running Hasleo Windows ISO Downloader
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.B
cls
Echo ------- AVL.5.B. Install WinMerge -------
Set "URL=https://github.com/WinMerge/winmerge/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set t1=%t1:~1%
Del a.txt
If EXIST "%Windir%\SysWOW64" (
	Set "URL=https://github.com/WinMerge/winmerge/releases/download/v%t1%/WinMerge-%t1%-x64-Setup.exe"
) ELSE (
	Set "URL=https://github.com/WinMerge/winmerge/releases/download/v%t1%/WinMerge-%t1%-Setup.exe"
)
Set "File=WinMergeSetup.exe"
Set "FileDel=%File%"
Set "FolderDel=Fido"
Call :AVLDownload
Echo ----- Extracting %File%
Echo Run WinMerge ...
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.C
CLS
Echo ------- AVL.5.C. Calculate CheckSum -------
Set /p FilePath="> Please input File Path: "
Set FilePath=%FilePath:"=%
If not exist "%FilePath%" (
	Echo File path not found. Aborting...
	Call :AVL.Finish ""	
)
Call :AVL.CheckSum "!FilePath!"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.D
cls
Echo ------- AVL.5.D. Download Windows ESD Image -------
Start "" "https://worproject.com/esd"
Echo Please download ESD from Website.
Set /p "ans2=> Do you want to create an ISO from the ESD ? To continue, type Y and press Enter: "
If /i "%ans2%" NEQ "Y" Call :AVL.Finish ""
Rem  ----- Download Tool
If not exist "%~dp0Tool\7z.exe" (Call :AVL.DownloadTool)
Echo ----- Download Decrypt.cmd
Set "URL=https://raw.githubusercontent.com/abbodi1406/WHD/refs/heads/master/scripts/esd-decrypter-wimlib-65.7z"
Set "File=ESDdecrypter.7z"
Set "FileDel=%File%"
Set "FolderDel="
If not exist "%~dp0Tool\decrypt.cmd" (
	Call :AVLDownload
	%~dp0Tool\7z.exe x ESDdecrypter.7z -o%~dp0Tool
	
)
If exist "%~dp0ESDdecrypter.7z" (Del %File%)
Echo ----- Check ESD path
Set "ESDpath="
For %%i in (*.esd) do (
	Set "ESDpath=%~dp0%%i")
	Set "ESDname=%%i"
)
If "!ESDpath!" EQU "" Set "ESDpath=No_ESD_is_found"
Echo ESD is available: "%ESDpath%"
Set /p ESDpath="> Please input ESD path (Enter nothing to choose the ESD above):"
Set ESDpath=%ESDpath:"=%
If not exist "%ESDpath%" (
	Echo Input invalid. Aborting...
	Call :AVL.Finish ""
)
Echo.
For %%A in ("%ESDpath%") do (set ESDsize=%%~zA)
For /F %%S IN ('Powershell -Command "[math]::Round((Get-Item \"%ESDpath%\").Length / 1MB)"') DO SET "ESDsize=%%S"
Echo The selected ESD: "%ESDpath%"
Echo The capacity of ESD: %ESDsize% MB
Echo.
Echo ----- Calculating checksum for ESD
Echo [1]. MD5       [2]. SHA1       [3]. SHA256       [0]. Skip Check
CHOICE /c 1230 /n /m "> Your Wishes: "
If %ErrorLevel%==1 Set "ALG=MD5"
If %ErrorLevel%==2 Set "ALG=SHA1"
If %ErrorLevel%==3 Set "ALG=SHA256"
If %ErrorLevel%==4 (
	Start "" cmd /k ""%~dp0Tool\Decrypt.cmd" "%ESDpath%""
	Call :AVL.Finish ""
)
Set /p "SelectedCheckSum=> Please input %ALG% checksum (Enter nothing to skip check): "
If "%SelectedCheckSum%"=="" (Call :AVL.Finish "")
for /f %%H in ('powershell -NoProfile -Command "Get-FileHash -Path '%ESDpath%' -Algorithm %ALG% | ForEach-Object { $_.Hash.ToUpper() }"') do set "ActualCheckSum=%%H"
Echo Actual ESD %ALG% Checksum: %ActualCheckSum%
if /I "%SelectedCheckSum%"=="%ActualCheckSum%" (
	Echo Result: %ALG% checksum matches.
) Else (
	Echo Result: %ALG% does not match. The ESD may be corrupted, please download it again.
	Call :AVL.Finish ""	
)

If exist "%~dp0Tool\Decrypt.cmd" (
	Start "" cmd /k ""%~dp0Tool\Decrypt.cmd" "%ESDpath%""
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.5.E
Start "" "https://files.rg-adguard.net/version/f0bd8307-d897-ef77-dbd6-216fefbe94c5"
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6
cd /d "%~dp0"
Set "FileDel="
Set "FolderDel="
Echo ----- Getting Windows Version
For /F "tokens=4 delims=.[]" %%A in ('ver') do Set "WinVer=%%A"
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject Win32_OperatingSystem).Caption"') do Set "OsName=%%b"
For /F "tokens=3,4" %%b in ('ver') do Set "Version=%%b %%c"
For /F "tokens=3" %%b in ('Reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion') do Set "OSVersion=%%b"
For /F "tokens=3" %%b in ('cscript %windir%\system32\slmgr.vbs /dli ^| findstr /b /c:"License Status"') do Set "LicenseStatus=%%b"
For /F "tokens=*" %%b in ('cscript %windir%\system32\slmgr.vbs /xpr') do Set "Expiration=%%b"
For /F "tokens=2,*" %%I in ('Reg query "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" /v ProductReleaseIds 2^>nul') do Set "OfficeVersion=%%J"
For /F %%b in ('Powershell -Command $Env:OfficeVersion.Length') do Set "OfficeVersionLen=%%b"
If %OfficeVersionLen% LEQ 3 Set "OfficeVersion=Not_Available"
Goto AVL.6.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Menu
cd /d "%~dp0"
Set "FileDel="
Set "FolderDel="
Set "AVLBackMenu=AVL.6.Menu"
Set "WmicActivation=0"
cls
Echo ------------ AVL.6. Manage Microsoft License ------------
Echo   Operating System: %OsName%.
Echo   Windows Version : %OSVersion% %Version%
Echo   License Status  : %LicenseStatus%.
Echo   Expiration      : %Expiration%
Echo   Office Version  : %OfficeVersion%.
Echo ---------------------------------------------------------
Echo   [1] Activate License From Clipboard
Echo   [2] Activate License From Clipboard by Wmic
Echo   [3] Check License Status
Echo   [4] Install Office-Project-Visio SKUS (Convert)
Echo   [5] Uninstall Office-Project-Visio Key
Echo   [6] Install Product Key
Echo   [7] Get Windows-Office-Project-Visio Installation ID
Echo   [8] Get Confirmation ID from Installation ID
Echo   [9] Install Confirmation ID
Echo   [A] Open Activation Setting
Echo   [B] Upgrade Windows To Professional Edition
Echo   [C] Backup Microsoft License 
Echo   [D] Restore Microsoft License
Echo   [E] Download Microsoft-Activation-Scripts
Echo   [F] Download Office SKUS
Echo   [G] Download Windows SKUS
Echo   [H] Download PIDkey
Echo   [I] Download Office-Tool-Plus Downloader
Echo   [J] Download PMAS
Echo   [K] Download VAMT
Echo   [L] Get Product Key From Mainboard
Echo   [M] Check Product Key Status
Echo   [0] Return to the previous menu
CHOICE /c 0123456789ABCDEFGHIJKLMZ /n /m "----------- (^_^) Your Wishes Come True (^_^) -----------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDEFGHIJKLMZ"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:OfficePath
For /f "delims=" %%a in ('dir /s /b "%ProgramFiles(x86)%\Microsoft Office\ospp.vbs" 2^>nul ^|^| dir /s /b "%ProgramFiles%\Microsoft Office\ospp.vbs" 2^>nul') do cd /d %%~dpa
For /f "delims=" %%a in ('dir /s /b /ad "%ProgramFiles(x86)%\Microsoft Office\Licenses16" 2^>nul ^|^| dir /s /b /ad "%ProgramFiles%\Microsoft Office\Licenses16" 2^>nul') do set "Licenses16Path=%%a" 
If not exist "ospp.vbs" (Call :AVL.Finish "Not exist Ospp.vbs")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:CheckProductKey
Set "Status=Valid"
For /F %%b in ('Powershell -Command $Env:k1.Length') do Set KeyLen=%%b
If "%KeyLen%" NEQ "29" Set "Status=InValid"
For /f "delims=" %%A in ('Powershell -Command "& {If ('%k1%' -match '^[A-Za-z0-9-]+$') {Echo Status=Valid} else {Echo Status=InValid}}"') do Set %%A
Set h1=%k1:~5,1%
Set h2=%k1:~11,1%
Set h3=%k1:~17,1%
Set h4=%k1:~23,1%
If "%h1%%h2%%h3%%h4%" NEQ "----" Set "Status=InValid"
Echo Product key is %Status%.
If %Status% EQU InValid (Call :AVL.Finish "")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.1
cls
Echo ---------- Checking License From Clipboard ----------
Echo ----- Getting Product Key From Clipboard 
For /F "tokens=*" %%b in ('Powershell -command "get-clipboard"') do Set k1=%%b
Echo ----- Clearing Clipboard 
::For /F tokens^=2* %%i in ('sc query^|find "Clipboard"')do >nul cd.|clip & net stop "%%i %%j" && net Start "%%i %%j"
Powershell Restart-Service -Name "cbdhsvc*" -force 
Echo ----- Checking Product Key 
Call :CheckProductKey
For /F "tokens=*" %%b in ('Powershell -Command "$req = [System.Net.WebRequest]::Create('https://pidkey.com/ajax/pidms_api?keys=%k1%&justgetdescription=0&apikey=%apikey%');$resp = New-Object System.IO.StreamReader $req.GetResponse().GetResponseStream(); $resp.ReadToEnd()"') do Set CheckKey=%%b
Set "CheckKey1=!CheckKey:"=_!"
For /F "tokens=12 delims=," %%b in ("!CheckKey1!") do Set Keyerr=%%b
If "%Keyerr%" EQU "_errorcode_:_0xC004C060_" (Call :AVL.Finish "Product Key is blocked by Microsoft")
If "%Keyerr%" EQU "_errorcode_:_0xC004C003_" (Call :AVL.Finish "Product Key is blocked by Microsoft")
For /F "tokens=11 delims=," %%b in ("%CheckKey1%") do Set Keyerr=%%b
If "%Keyerr%" EQU "_blocked_:1" (Call :AVL.Finish "Product Key is blocked by Microsoft")
For /F "tokens=6 delims=," %%b in ("%CheckKey1%") do Set CheckKey2=%%b
For /F "tokens=2 delims=:" %%b in ("%CheckKey2%") do Set prd=%%b
For /F "tokens=2 delims=_" %%b in ("%prd%") do Set Kind=%%b
Set CheckOffVer=%prd:~7,2%
Set "OffVer=Licenses16"
If "%CheckOffVer%" == "14" Set "OffVer=Licenses"
If "%CheckOffVer%" == "15" Set "OffVer=Licenses15"
Set prd1=%prd:~1,3%
Set prd2=%prd:~1,6%
Set prd3=%prd:~1,4%
Echo ----- Type: %prd% 
If "%prd3%" == "null" (Call :AVL.Finish "Product Key is undefined")
If "%WmicActivation%"=="1" Goto AVL.6.1.wmic
If "%prd1%" == "Win" Goto AVL.6.1.ActivateWindows
If "%prd2%" == "Office" Goto AVL.6.1.ActivateOffice
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.1.wmic
Echo ---------- AVL.6.2. Activate License From Clipboard by Wmic ----------
Echo ----- Check Ospp.vbs
If not exist "ospp.vbs" Call :OfficePath
Echo ----- Check WMIC status
If not exist "%windir%\System32\wbem\WMIC.exe" (
	Echo WMIC is Disable 
	Echo Adding WMIC to Windows ...
	DISM /Online /Add-Capability /CapabilityName:WMIC~~~~
) Else (Echo WMIC is Available)
Echo ----- Installing License %prd%
If "%prd2%" == "Office" (
	For /F "tokens=3" %%b in ('cscript ospp.vbs /inpkey:%k1% ^| findstr /b /c:"ERROR CODE:"') do Set err=%%b
	Call :AVL.InstallOfficeSkus
)
Echo ----- Import Product Key
wmic path SoftwareLicensingService where (Version is not null) call InstallProductKey ProductKey='%k1%'
For /F "tokens=5 delims=-" %%a in ("%k1%") do Set partialkey=%%a
Echo ----- Get IID
For /F "tokens=2 delims==" %%a in ('"wmic path SoftwareLicensingProduct where (PartialProductKey='%partialkey%') get OfflineInstallationId /value"') do Set IID=%%a
Echo IID=%IID%
Echo ----- Get CID
For /F "tokens=9 delims=," %%b in ('Powershell -Command "$req = [System.Net.WebRequest]::Create('https://pidkey.com/ajax/cidms_api?iids=%IID%&justforcheck=0&apikey=%apikey%');$resp = New-Object System.IO.StreamReader $req.GetResponse().GetResponseStream(); $resp.ReadToEnd()"') do Set ACID=%%b
Set CID=%ACID:~27,48%
Echo CID=%CID%
Echo ----- Import CID
wmic path SoftwareLicensingProduct where (PartialProductKey='%partialkey%') call DepositOfflineConfirmationId InstallationID='%IID%' ConfirmationId='%CID%'
Echo ----- Activating
wmic path SoftwareLicensingProduct where (PartialProductKey='%partialkey%') call Activate
Echo ----- Export Result
wmic path SoftwareLicensingProduct where (PartialProductKey='%partialkey%') get PartialProductKey,Name,LicenseStatus,GracePeriodRemaining,Description /value>k3.txt
Echo %prd%>>k3.txt & Echo IID:%IID%>>k3.txt & Echo CID:%CID%>>k3.txt & Echo %DATE%_%TIME%>>k3.txt 
Start Notepad k3.txt
Set "ans1="
Set /p "ans1=> To back up Microsoft licenses, type Y and press Enter: "
If /i "%ans1%" EQU "y" (Call :AVL.6.C)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.1.ActivateWindows
Echo ---------- AVL.6.1. Activate Windows License From Clipboard ----------
Echo ----- Activating Windows %prd%
cd /d "%windir%\system32"
Echo ----- Import Product Key
cscript slmgr.vbs /ipk %k1% >nul
If "%ErrorLevel%" NEQ "0" (Call :AVL.Finish "Import Product Key Unsuccessfully")
Echo ----- Get IID
For /F "tokens=3" %%b in ('cscript slmgr.vbs /dti ^| findstr /b /c:"Installation"') do Set IID=%%b
Echo IID=%IID%
Echo ----- Get CID
For /F "tokens=9 delims=," %%b in ('Powershell -Command "$req = [System.Net.WebRequest]::Create('https://pidkey.com/ajax/cidms_api?iids=%IID%&justforcheck=0&apikey=%apikey%');$resp = New-Object System.IO.StreamReader $req.GetResponse().GetResponseStream(); $resp.ReadToEnd()"') do Set ACID=%%b
Set CID=%ACID:~27,48%
Echo CID=%CID%
Echo ----- Import CID
cscript slmgr.vbs /atp %CID%
Echo ----- Activating
cscript slmgr.vbs /ato
Echo ----- Export Result
Echo %prd%>k2.txt & Echo IID:%IID% >>k2.txt & Echo CID:%CID% >>k2.txt & Echo %DATE%_%TIME% >> k2.txt  & ver>>k2.txt & cscript slmgr.vbs /dli >>k2.txt & cscript slmgr.vbs /xpr >>k2.txt 
Start Notepad k2.txt 
Start ms-settings:activation
Set "ans1="
Set /p "ans1=> To back up Microsoft licenses, type Y and press Enter: "
If /i "%ans1%" EQU "y" (Call :AVL.6.C)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.InstallOfficeSkus
Echo ----- Installing Skus %prd%
If exist "..\root\%OffVer%" (
	For /F %%x in ('dir /b "..\root\%OffVer%\%Kind%*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\%OffVer%\%%x"
) Else (
	For /F %%x in ('dir /b "..\%OffVer%\%Kind%*.xrm-ms"') do cscript ospp.vbs /inslic:"..\%OffVer%\%%x"
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.1.ActivateOffice
Echo ---------- AVL.6.1. Activate Office-Project-Visio License From Clipboard ----------
Echo ----- Check Ospp.vbs
If not exist "ospp.vbs" Call :OfficePath
Echo ----- Activating %prd%
Echo ----- Import Product Key
For /F "tokens=3" %%b in ('cscript ospp.vbs /inpkey:%k1% ^| findstr /b /c:"ERROR CODE:"') do Set err=%%b
If "%err%" == "0xC004F069" (
	Call :AVL.InstallOfficeSkus
	cscript ospp.vbs /inpkey:%k1%
)
If "%ErrorLevel%" NEQ "0" (Call :AVL.Finish "Import Product Key Unsuccessfully")
Echo ----- Get IID
For /F "tokens=8" %%b in ('cscript ospp.vbs /dinstid ^| findstr /c:"%kind%"') do Set IID=%%b
Echo IID=%IID%
Echo ----- Get CID
For /F "tokens=9 delims=," %%b in ('Powershell -Command "$req = [System.Net.WebRequest]::Create('https://pidkey.com/ajax/cidms_api?iids=%IID%&justforcheck=0&apikey=%apikey%');$resp = New-Object System.IO.StreamReader $req.GetResponse().GetResponseStream(); $resp.ReadToEnd()"') do Set ACID=%%b
Set CID=%ACID:~27,48%
Echo CID=%CID%
Echo ----- Import CID
cscript ospp.vbs /actcid:%CID%
Echo ----- Activating
cscript ospp.vbs /act
Echo ----- Export Result
Echo %prd%>k1.txt & Echo IID:%IID%>>k1.txt & Echo CID:%CID%>>k1.txt & Echo %DATE%_%TIME% >> k1.txt & cscript ospp.vbs /dstatus >>k1.txt
Start Notepad k1.txt
Echo %prd% | findstr /I "Visio" >nul && Start visio
Echo %prd% | findstr /I "Project" >nul && Start winproj
Echo %prd% | findstr /I "Office" >nul && Start winword
Set "ans1="
Set /p "ans1=> To back up Microsoft licenses, type Y and press Enter: "
If /i "%ans1%" EQU "y" (Call :AVL.6.C)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.2
Set "WmicActivation=1"
Goto AVL.6.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.3
Echo ----- Check Ospp.vbs
If not exist "ospp.vbs" Call :OfficePath
cls
Echo ---------- AVL.6.3. Check License Status ----------
cscript %windir%\system32\slmgr.vbs /dli
cscript %windir%\system32\slmgr.vbs /xpr
cscript ospp.vbs /dstatus
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4
Set "AVLBackMenu=AVL.6.4"
Echo %OfficeVersion% | findstr /i "retail" >nul && (
	Set RecommendConvert=%OfficeVersion:Retail=VL_MAK%
) || (
	Set "RecommendConvert=Not_Available"
)
Echo %OfficeVersion% | findstr /i "365" >nul && (
	Set "RecommendConvert=Not_Available"
)
Echo ----- Check Ospp.vbs
If not exist "ospp.vbs" Call :OfficePath
cls
Echo ----- AVL.6.4. Install SKUS (Convert) -----
Echo   Current Office: %OfficeVersion%     
Echo   [1] Version 2024     
Echo   [2] Version 2021     
Echo   [3] Version 2019     
Echo   [4] Version 2016     
Echo   [5] Version 2013     
Echo   [6] Install SKUS %RecommendConvert%     
Echo   [0] Return to the previous menu
CHOICE /c 0123456 /n /m "---- (^_^) Your Wishes Come True (^_^) ----"
Set /A Index=%ErrorLevel%-1
Set "List=0123456"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.4.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.6
If "%RecommendConvert%" EQU "Not_Available" (Call :AVL.Finish "Fail to Convert")
cls
Echo -------- AVL.6.4. Install SKUS %RecommendConvert% --------
IF EXIST "..\root\Licenses15\%RecommendConvert%*.xrm-ms" (
	For /f %%x in ('dir /b "..\root\Licenses15\%RecommendConvert%*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
) ELSE (
	For /f %%x in ('dir /b "%Licenses16Path%\%RecommendConverad1t%*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.0
Goto AVL.6

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1
Set "AVLBackMenu=AVL.6.4.1"
cls
Echo ----- AVL.6.4.1 Install version 2024 SKUS -----
Echo   [1] Office 2024 Pro Plus Retail
Echo   [2] Office 2024 Pro Plus Volume
Echo   [3] Office 2024 Standard Volume
Echo   [4] Office 2024 Visio Pro Retail
Echo   [5] Office 2024 Visio Pro Volume
Echo   [6] Office 2024 Visio Standard Retail
Echo   [7] Office 2024 Visio Standard Volume
Echo   [8] Office 2024 Project Pro Retail
Echo   [9] Office 2024 Project Pro Volume
Echo   [A] Office 2024 Project Standard Retail
Echo   [B] Office 2024 Project Standard Volume
Echo   [0] Return to the previous menu
CHOICE /c 0123456789AB /n /m "------ (^_^) Your Wishes Come True (^_^) ------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789AB"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.4.1.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.0
Goto AVL.6.4

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.1
CLS
Echo ----- AVL.6.4.1.1. Install Office 2024 Pro Plus Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProPlus2024R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.2
CLS
Echo ----- AVL.6.4.1.2. Install Office 2024 Pro Plus Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProPlus2024VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.3
CLS
Echo ----- AVL.6.4.1.3. Install Office 2024 Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\Standard2024VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.4
CLS
Echo ----- AVL.6.4.1.4. Install Office 2024 Visio Pro Retail
For /f %%x in ('dir /b "%Licenses16Path%\VisioPro2024R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.5
CLS
Echo ----- AVL.6.4.1.5. Install Office 2024 Visio Pro Volume
For /f %%x in ('dir /b "%Licenses16Path%\VisioPro2024VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.6
CLS
Echo ----- AVL.6.4.1.6. Install Office 2024 Visio Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\VisioStd2024R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.7
CLS
Echo ----- AVL.6.4.1.7. Install Office 2024 Visio Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\VisioStd2024VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.8
CLS
Echo ----- AVL.6.4.1.8. Install Office 2024 Project Pro Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProjectPro2024R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.9
CLS
Echo ----- AVL.6.4.1.9. Install Office 2024 Project Pro Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProjectPro2024VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.A
CLS
Echo ----- AVL.6.4.1.A. Install Office 2024 Project Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProjectStd2024R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.1.B
CLS
Echo ----- AVL.6.4.1.B. Install Office 2024 Project Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProjectStd2024VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2
Set "AVLBackMenu=AVL.6.4.2"
cls
Echo ----- AVL.6.4.2 Install version 2021 SKUS -----
Echo   [1] Office 2021 Pro Plus Retail
Echo   [2] Office 2021 Pro Plus Volume
Echo   [3] Office 2021 Standard Retail
Echo   [4] Office 2021 Standard Volume
Echo   [5] Office 2021 Visio Pro Retail
Echo   [6] Office 2021 Visio Pro Volume
Echo   [7] Office 2021 Visio Standard Retail
Echo   [8] Office 2021 Visio Standard Volume
Echo   [9] Office 2021 Project Pro Retail
Echo   [A] Office 2021 Project Pro Volume
Echo   [B] Office 2021 Project Standard Retail
Echo   [C] Office 2021 Project Standard Volume
Echo   [0] Return to the previous menu
CHOICE /c 0123456789ABC /n /m "------ (^_^) Your Wishes Come True (^_^) ------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABC"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.4.2.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.0
Goto AVL.6.4

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.1
CLS
Echo ----- AVL.6.4.2.1. Install Office 2021 Pro Plus Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProPlus2021R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\ProPlus2021MSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.2
CLS
Echo ----- AVL.6.4.2.2. Install Office 2021 Pro Plus Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProPlus2021VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.3
CLS
Echo ----- AVL.6.4.2.3. Install Office 2021 Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\Standard2021MSDNR*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\Standard2021R*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.4
CLS
Echo ----- AVL.6.4.2.4. Install Office 2021 Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\Standard2021VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.5
CLS
Echo ----- AVL.6.4.2.5. Install Office 2021 Visio Pro Retail
For /f %%x in ('dir /b "%Licenses16Path%\VisioPro2021R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\VisioPro2021MSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.6
CLS
Echo ----- AVL.6.4.2.6. Install Office 2021 Visio Pro Volume
For /f %%x in ('dir /b "%Licenses16Path%\VisioPro2021VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.7
CLS
Echo ----- AVL.6.4.2.7. Install Office 2021 Visio Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\VisioStd2021R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.8
CLS
Echo ----- AVL.6.4.2.8. Install Office 2021 Visio Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\VisioStd2021VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.9
CLS
Echo ----- AVL.6.4.2.9. Install Office 2021 Project Pro Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProjectPro2021R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\ProjectPro2021MSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.A
CLS
Echo ----- AVL.6.4.2.A. Install Office 2021 Project Pro Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProjectPro2021VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.B
CLS
Echo ----- AVL.6.4.2.B. Install Office 2021 Project Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProjectStd2021R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.2.C
CLS
Echo ----- AVL.6.4.2.C. Install Office 2021 Project Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProjectStd2021VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3
Set "AVLBackMenu=AVL.6.4.3"
cls
Echo ----- AVL.6.4.3 Install version 2019 SKUS -----
Echo   [1] Office 2019 Pro Plus Retail
Echo   [2] Office 2019 Pro Plus Volume
Echo   [3] Office 2019 Standard Retail
Echo   [4] Office 2019 Standard Volume
Echo   [5] Office 2019 Visio Pro Retail
Echo   [6] Office 2019 Visio Pro Volume
Echo   [7] Office 2019 Visio Standard Retail
Echo   [8] Office 2019 Visio Standard Volume
Echo   [9] Office 2019 Project Pro Retail
Echo   [A] Office 2019 Project Pro Volume
Echo   [B] Office 2019 Project Standard Retail
Echo   [C] Office 2019 Project Standard Volume
Echo   [0] Return to the previous menu
CHOICE /c 0123456789ABC /n /m "------ (^_^) Your Wishes Come True (^_^) ------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABC"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.4.3.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.0
Goto AVL.6.4

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.1
CLS
Echo ----- AVL.6.4.3.1. Install Office 2019 Pro Plus Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProPlus2019R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\ProPlus2019MSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.2
CLS
Echo ----- AVL.6.4.3.2. Install Office 2019 Pro Plus Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProPlus2019VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.3
CLS
Echo ----- AVL.6.4.3.3. Install Office 2019 Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\Standard2019MSDNR*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\Standard2019R*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.4
CLS
Echo ----- AVL.6.4.3.4. Install Office 2019 Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\Standard2019VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.5
CLS
Echo ----- AVL.6.4.3.5. Install Office 2019 Visio Pro Retail
For /f %%x in ('dir /b "%Licenses16Path%\VisioPro2019R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\VisioPro2019MSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.6
CLS
Echo ----- AVL.6.4.3.6. Install Office 2019 Visio Pro Volume
For /f %%x in ('dir /b "%Licenses16Path%\VisioPro2019VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.7
CLS
Echo ----- AVL.6.4.3.7. Install Office 2019 Visio Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\VisioStd2019R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.8
CLS
Echo ----- AVL.6.4.3.8. Install Office 2019 Visio Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\VisioStd2019VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.9
CLS
Echo ----- AVL.6.4.3.9. Install Office 2019 Project Pro Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProjectPro2019R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\ProjectPro2019MSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.A
CLS
Echo ----- AVL.6.4.3.A. Install Office 2019 Project Pro Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProjectPro2019VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.B
CLS
Echo ----- AVL.6.4.3.B. Install Office 2019 Project Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProjectStd2019R_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.3.C
CLS
Echo ----- AVL.6.4.3.C. Install Office 2019 Project Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProjectStd2019VL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4
Set "AVLBackMenu=AVL.6.4.4"
cls
Echo ----- AVL.6.4.4 Install version 2016 SKUS -----
Echo   [1] Office 2016 Pro Plus Retail
Echo   [2] Office 2016 Pro Plus Volume
Echo   [3] Office 2016 Standard Retail
Echo   [4] Office 2016 Standard Volume
Echo   [5] Office 2016 Visio Pro Retail
Echo   [6] Office 2016 Visio Pro Volume
Echo   [7] Office 2016 Visio Standard Retail
Echo   [8] Office 2016 Visio Standard Volume
Echo   [9] Office 2016 Project Pro Retail
Echo   [A] Office 2016 Project Pro Volume
Echo   [B] Office 2016 Project Standard Retail
Echo   [C] Office 2016 Project Standard Volume
Echo   [0] Return to the previous menu
CHOICE /c 0123456789ABC /n /m "------ (^_^) Your Wishes Come True (^_^) ------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABC"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.4.4.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.0
Goto AVL.6.4

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.1
CLS
Echo ----- AVL.6.4.4.1. Install Office 2016 Pro Plus Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProPlusR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\ProPlusMSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.2
CLS
Echo ----- AVL.6.4.4.2. Install Office 2016 Pro Plus Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProPlusVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.3
CLS
Echo ----- AVL.6.4.4.3. Install Office 2016 Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\StandardMSDNR*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\StandardR*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.4
CLS
Echo ----- AVL.6.4.4.4. Install Office 2016 Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\StandardVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.5
CLS
Echo ----- AVL.6.4.4.5. Install Office 2016 Visio Pro Retail
For /f %%x in ('dir /b "%Licenses16Path%\VisioProR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\VisioProMSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.6
CLS
Echo ----- AVL.6.4.4.6. Install Office 2016 Visio Pro Volume
For /f %%x in ('dir /b "%Licenses16Path%\VisioProVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.7
CLS
Echo ----- AVL.6.4.4.7. Install Office 2016 Visio Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\VisioStdR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.8
CLS
Echo ----- AVL.6.4.4.8. Install Office 2016 Visio Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\VisioStdVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.9
CLS
Echo ----- AVL.6.4.4.9. Install Office 2016 Project Pro Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProjectProR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
For /f %%x in ('dir /b "%Licenses16Path%\ProjectProMSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.A
CLS
Echo ----- AVL.6.4.4.A. Install Office 2016 Project Pro Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProjectProVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.B
CLS
Echo ----- AVL.6.4.4.B. Install Office 2016 Project Standard Retail
For /f %%x in ('dir /b "%Licenses16Path%\ProjectStdR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.4.C
CLS
Echo ----- AVL.6.4.4.C. Install Office 2016 Project Standard Volume
For /f %%x in ('dir /b "%Licenses16Path%\ProjectStdVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"%Licenses16Path%\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5
Set "AVLBackMenu=AVL.6.4.5"
cls
Echo ----- AVL.6.4.5 Install version 2013 SKUS -----
Echo   [1] Office 2013 Pro Plus Retail
Echo   [2] Office 2013 Pro Plus Volume
Echo   [3] Office 2013 Standard Retail
Echo   [4] Office 2013 Standard Volume
Echo   [5] Office 2013 Visio Pro Retail
Echo   [6] Office 2013 Visio Pro Volume
Echo   [7] Office 2013 Visio Standard Retail
Echo   [8] Office 2013 Visio Standard Volume
Echo   [9] Office 2013 Project Pro Retail
Echo   [A] Office 2013 Project Pro Volume
Echo   [B] Office 2013 Project Standard Retail
Echo   [C] Office 2013 Project Standard Volume
Echo   [0] Return to the previous menu
CHOICE /c 0123456789ABC /n /m "------ (^_^) Your Wishes Come True (^_^) ------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABC"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.4.5.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.0
Goto AVL.6.4

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.1
CLS
Echo ----- AVL.6.4.5.1. Install Office 2013 Pro Plus Retail
for /f %%x in ('dir /b "..\root\Licenses15\ProPlusR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
for /f %%x in ('dir /b "..\root\Licenses15\ProPlusMSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.2
CLS
Echo ----- AVL.6.4.5.2. Install Office 2013 Pro Plus Volume
for /f %%x in ('dir /b "..\root\Licenses15\ProPlusVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.3
CLS
Echo ----- AVL.6.4.5.3. Install Office 2013 Standard Retail
for /f %%x in ('dir /b "..\root\Licenses15\StandardMSDNR*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
for /f %%x in ('dir /b "..\root\Licenses15\StandardR*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.4
CLS
Echo ----- AVL.6.4.5.4. Install Office 2013 Standard Volume
for /f %%x in ('dir /b "..\root\Licenses15\StandardVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.5
CLS
Echo ----- AVL.6.4.5.5. Install Office 2013 Visio Pro Retail
for /f %%x in ('dir /b "..\root\Licenses15\VisioProR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
for /f %%x in ('dir /b "..\root\Licenses15\VisioProMSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.6
CLS
Echo ----- AVL.6.4.5.6. Install Office 2013 Visio Pro Volume
for /f %%x in ('dir /b "..\root\Licenses15\VisioProVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.7
CLS
Echo ----- AVL.6.4.5.7. Install Office 2013 Visio Standard Retail
for /f %%x in ('dir /b "..\root\Licenses15\VisioStdR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.8
CLS
Echo ----- AVL.6.4.5.8. Install Office 2013 Visio Standard Volume
for /f %%x in ('dir /b "..\root\Licenses15\VisioStdVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.9
CLS
Echo ----- AVL.6.4.5.9. Install Office 2013 Project Pro Retail
for /f %%x in ('dir /b "..\root\Licenses15\ProjectProR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
for /f %%x in ('dir /b "..\root\Licenses15\ProjectProMSDNR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.A
CLS
Echo ----- AVL.6.4.5.A. Install Office 2013 Project Pro Volume
for /f %%x in ('dir /b "..\root\Licenses15\ProjectProVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.B
CLS
Echo ----- AVL.6.4.5.B. Install Office 2013 Project Standard Retail
for /f %%x in ('dir /b "..\root\Licenses15\ProjectStdR_Retail*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.4.5.C
CLS
Echo ----- AVL.6.4.5.C. Install Office 2013 Project Standard Volume
for /f %%x in ('dir /b "..\root\Licenses15\ProjectStdVL_MAK*.xrm-ms"') do cscript ospp.vbs /inslic:"..\root\Licenses15\%%x" 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.5
Echo ----- Check Ospp.vbs
If not exist "ospp.vbs" Call :OfficePath
cls
Echo ---------- AVL.6.5. Uninstall Office-Project-Visio Key ----------
cscript ospp.vbs /dstatus 
Goto AVL.6.5.loop

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.5.loop
Set "uninstallkey="
Echo Press Enter to exit, or enter A to uninstall all product keys.
set /p "uninstallkey=Enter the last 5 characters of installed product key: "
If "!uninstallkey!" EQU "" (Call :AVL.Finish "Enter nothing")
If /i "!uninstallkey!" EQU "A" (
	For /f "tokens=8" %%b in ('cscript ospp.vbs /dstatus ^| findstr /b /c:"Last 5"') do (cscript ospp.vbs /unpkey:%%b) 
	Call :AVL.Finish ""
)
For /F %%b in ('Powershell -Command $Env:uninstallkey.Length') do Set uninstallkeyLen=%%b
If "%uninstallkeyLen%" NEQ "5" (Call :AVL.Finish "The last 5 characters you entered are invalid")
cscript ospp.vbs /unpkey:%uninstallkey%
Goto AVL.6.5.loop

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.6
Set "AVLBackMenu=AVL.6.6"
cls
Echo ---------- AVL.6.6. Install Product Key ---------
Echo   [1] Install Office-Project-Visio Product Key
Echo   [2] Install Windows Product Key
Echo   [0] Return to the previous menu
CHOICE /c 012 /n /m "------- (^_^) Your Wishes Come True (^_^) -------"
Set /A Index=%ErrorLevel%-1
Set "List=012"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.6.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.6.0
Goto AVL.6

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.6.1
cls
Echo ---------- AVL.6.6.1. Install Office-Project-Visio Product Key ----------
Echo ----- Check Ospp.vbs
If not exist "ospp.vbs" Call :OfficePath
Echo ----- Input Office-Project-Visio Product Key
Set /p "install=> Enter the product key (Enter Nothing To Exit): "
If "!install!" EQU "" Goto !AVLBackMenu!
cscript ospp.vbs /inpkey:%install%
cscript ospp.vbs /dinstid
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.6.2
cls
Echo ---------- AVL.6.6.2. Install Windows Product Key ----------
Set /p "install=> Enter the product key (Enter Nothing To Exit): "
If "!install!" EQU "" Goto !AVLBackMenu!
cscript %windir%\system32\slmgr.vbs /ipk %install% 
cscript %windir%\system32\slmgr.vbs /dti
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.7
Echo ----- Check Ospp.vbs
If not exist "ospp.vbs" Call :OfficePath
cls
Echo ---------- AVL.6.7. Get Windows-Office-Project-Visio Installation ID ----------
Echo ----- Windows Installation ID
cscript %windir%\system32\slmgr.vbs /dti
Echo ----- Office-Project-Visio Installation ID
cscript ospp.vbs /dinstid
Echo.
Set /p "Ans4=To export the result to iid.txt, type Y and press Enter: "
If /i "%Ans4%" NEQ "y" Call :AVL.Finish ""
Echo ----- Windows Installation ID>"iid.txt"
cscript %windir%\system32\slmgr.vbs /dti>>"iid.txt"
Echo ----- Office-Project-Visio Installation ID>>"iid.txt"
cscript ospp.vbs /dinstid>>"iid.txt"
Start notepad iid.txt
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.8
Set "iid="
cls
Echo ---------- AVL.6.8. Get Confirmation ID from Installation ID ----------
Set /p "IID=Input Installation ID (Enter Nothing To Exit):"
If "!IID!" EQU "" Goto !AVLBackMenu!
Set IID=%IID: =%
Set IID=%IID:-=%
For /f "delims=" %%A in ('Powershell -Command "& {If ('%IID%' -match '^[0-9]+$') {Echo result=Valid} else {Echo result=InValid}}"') do Set %%A
For /F %%b in ('Powershell -Command $Env:IID.Length') do Set "IIDLen=%%b"
If %IIDLen% LSS 60 (
	Echo The Installation ID is InValid.
	Call :AVL.Finish ""
)
set "hasNon="
for /f "delims=0123456789" %%A in ("%IID%") do set "hasNon=%%A"
if defined hasNon (Call :AVL.Finish "Error: The Installation ID is not numeric")

::Set "ACID={"short_result":"Key blocked"Unfortunately, we cannot complete this transaction. Microsoft does not recognize this as a legitimate product. Please verify that you are using a genuine product key when attempting to activate your product. You may be able to return the software to your reseller for a new product.","typeiid":6,"userID":885,"confirmationid":"","have_cid":-1,"professional_have_cid":-1,"confirmation_id_with_dash":null,"confirmation_id_no_dash":null,"error_executing":null,"had_occurred":0}"
::Set "ACID={"short_result":"Confirmation ID (CID):\r\n413713-292920-571236-472353-232966-465044-054755-887506","result":"Successfully","typeiid":1,"userID":885,"confirmationid":"413713-292920-571236-472353-232966-465044-054755-887506","have_cid":1,"professional_have_cid":1,"confirmation_id_with_dash":"413713-292920-571236-472353-232966-465044-054755-887506","confirmation_id_no_dash":"413713292920571236472353232966465044054755887506","error_executing":null,"had_occurred":0}"
::Set "ACID={"short_result":null,"result":null,"typeiid":null,"userID":null,"confirmationid":null,"have_cid":null,"professional_have_cid":null,"confirmation_id_with_dash":null,"confirmation_id_no_dash":null,"error_executing":"Unfortunately, we cannot complete this transaction. Microsoft does not recognize this as a legitimate product. Please verify that you are using a genuine product key when attempting to activate your product. You may be able to return the software to your reseller for a new product.","had_occurred":1}

For /F "tokens=*" %%b in ('Powershell -Command "$req = [System.Net.WebRequest]::Create('https://pidkey.com/ajax/cidms_api?iids=%iid%&justforcheck=0&apikey=%apikey%');$resp = New-Object System.IO.StreamReader $req.GetResponse().GetResponseStream(); $resp.ReadToEnd()"') do Set ACID=%%b
Set ACID1=%ACID:"=_%
Set ACID1=%ACID1:,_=;%
For /F "tokens=1 delims=;" %%b in ("%ACID1%") do Set "Message=%%b"
For /F "tokens=2 delims=:" %%b in ("%Message%") do Set "Message=%%b"
For /F "tokens=9 delims=;" %%b in ("%ACID1%") do Set "CID=%%b"
For /F "tokens=2 delims=:" %%b in ("%CID%") do Set "CID=%%b"
::Set CID=%ACID:~27,48%
Set CID=%CID:_=%
For /F %%b in ('Powershell -Command $Env:CID.Length') do Set CIDLen=%%b

If "%CID%%Message%" EQU "nullnull" (
	For /F "tokens=10 delims=;" %%b in ("%ACID1%") do Set "Message=%%b"
	For /F "tokens=2 delims=:" %%b in ("%Message%") do Set "Message=%%b"
)

If %CIDLen% LSS 40 (
	Echo Confirmation ID: Not Available.
	Echo Error: %Message%
) else (
	Echo Confirmation ID: %CID%
	Echo %CID%|clip
	Echo Note: The CID is sent to Clipboard.
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.9
Set "AVLBackMenu=AVL.6.9"
cls
Echo ---------- AVL.6.9. Install Confirmation ID ---------
Echo   [1] Install Office-Project-Visio Confirmation ID
Echo   [2] Install Windows Confirmation ID
Echo   [0] Return to the previous menu
CHOICE /c 012 /n /m "--------- (^_^) Your Wishes Come True (^_^) ---------"
Set /A Index=%ErrorLevel%-1
Set "List=012"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.9.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.9.0
Goto AVL.6

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.9.1
Echo ----- Check Ospp.vbs
If not exist "ospp.vbs" Call :OfficePath
cls
Echo ---------- AVL.6.9.1. Install Office-Project-Visio Confirmation ID ----------
Set "CID="
Set /p "CID=Input the CID (Enter Nothing to Exit):"
If "!CID!" EQU "" Goto !AVLBackMenu!
cscript ospp.vbs /actcid:%CID%
cscript ospp.vbs /act 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.9.2
cls
Echo ---------- AVL.6.9.2. Install Windows Confirmation ID ----------
Set "CID="
Set /p "CID=Input the CID (Enter Nothing to Exit):"
If "!CID!" EQU "" Goto !AVLBackMenu!
cscript %windir%\system32\slmgr.vbs /atp %CID%
cscript %windir%\system32\slmgr.vbs /ato
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.A
cls
Echo ---------- AVL.6.A. Open Activation Setting ----------
Start ms-settings:activation
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.B
cls
Echo ---------- AVL.6.B. Upgrade Windows To Professional Edition ----------
Echo ----- Checking Edition
For /F "tokens=*" %%b in ('Powershell -command "(Get-WmiObject Win32_OperatingSystem).Caption"') do Set "OsName=%%b"
Echo %OsName% | find /I " Pro" >nul 2>&1
If "%ErrorLevel%" EQU "0" (
	Echo Your current Windows Edition is Professional.
	Call :AVL.Finish ""	
)
For /F "tokens=3,4" %%b in ('ver') do Set "Version=%%b %%c"
Echo Operating System Edition: %OsName% %Version%
For /F "tokens=4" %%b in ('Powershell -command "(Get-WmiObject Win32_OperatingSystem).Caption"') do Set "Edition=%%b"
If "%Edition%" EQU "Pro" (Call :AVL.Finish "Your current Windows Edition is Professional")
Echo ----- Upgrading Windows To Professional Edition
cd %windir%\system32
sc config LicenseManager start= auto & net Start LicenseManager
sc config wuauserv start= auto & net Start wuauserv
changepk.exe /productkey VK7JG-NPHTM-C97JM-9MPGT-3V66T
Call :AVL.Finish "Wait to upgrade then restart windows"

:AVL.CheckFileInUse
set "file=%windir%\System32\spp\store\2.0\tokens.dat"
powershell -NoProfile -Command "$f='%file%'; $locked=$false; try { $s=[IO.File]::Open($f,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None); $s.Close() } catch [IO.IOException] { if( ($_.Exception.HResult -band 0xFFFF) -in 32,33 ){ $locked=$true } }; if($locked){ exit 1 } else { exit 0 }"
if errorlevel 1 (
    	Echo The file is in use: "%file%". Please wait...
	choice /T 5 /D Y /N > nul
	Goto :AVL.CheckFileInUse
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.C
cls
Echo ---------- AVL.6.C. Backup Microsoft License ----------
Call :AVL.CheckFileInUse
For /F "tokens=*" %%b in ('Powershell Get-Date -Format "yyyyMMdd_HHmmss"') do Set "CurrentTime=%%b"
Powershell Compress-Archive -Path "%windir%\System32\spp\store" -DestinationPath "%~dp0AVLBackup_%CurrentTime%.zip"
If "%ErrorLevel%" NEQ "0" (Call :AVL.Finish "Fail to back up the licenses")
If exist "%~dp0AVLBackup_%CurrentTime%.zip" (
	Echo Microsoft licenses have been backed up to AVLBackup_%CurrentTime%.zip
	Echo The backup includes licenses for Windows, Office, Project, and Visio.
) Else (
	Echo Fail to back up the licenses.
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.D
cls
Echo ---------- AVL.6.D. Restore Microsoft License ----------
Echo ----- Input Backup File
Call :AVL.CheckFileInUse
Set "BackUpFile=Not_Available"
For %%i in (AVLBackup_*.zip) do (Set "BackUpFile=%~dp0%%i")
Echo The recommended backup file: "%BackUpFile%"
Set /p "BackUpFile=> Input the path of the back-up file (Enter nothing to choose file above) : "
Set BackUpFile=%BackUpFile:"=%
If not exist "%BackUpFile%" (
	Echo Back-up file is not exist.
	Call :AVL.Finish ""
)
Echo.
Echo The selected backup file: "%BackUpFile%"
If exist "AVLBackup" Rmdir /s /q "AVLBackup"
Set "FolderDel=AVLBackup"
Powershell -command Expand-Archive -LiteralPath "%BackUpFile%" -DestinationPath "AVLBackup"
If exist "%~dp0AVLBackup\store\2.0\tokens.dat" (Set ch1=1) Else (Set ch1=0)
If exist "%~dp0AVLBackup\OfficeSoftwareProtectionPlatform" (Set ch2=1) Else (Set ch2=0)
If "%ch1%%ch2%" EQU "00" (
	Echo The back-up file is not invalid. It cannot be restored.
	Call :AVL.Finish ""
)
Echo ----- Stopping some services
net stop sppsvc>nul 2>&1 
net stop osppsvc>nul 2>&1
For /F "tokens=6 delims=[.] " %%a in ('ver') do Set ver1=%%a
Echo ----- Copying License to OS Drive	
If %ver1% LEQ 4 (
	XCOPY "AVLBackup\*" "%Windir%\System32\spp" /E /H /Q /Y
	XCOPY "AVLBackup\OfficeSoftwareProtectionPlatform\*" "%ProgramData%\Microsoft\OfficeSoftwareProtectionPlatform" /E /H /Q /Y
)
If %ver1% LEQ 7601 (XCOPY "AVLBackup\SoftwareProtectionPlatform\*" "%Windir%\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SoftwareProtectionPlatform" /E /H /Q /Y)
If %ver1% GTR 7601 (
	powershell -NoProfile -Command "Rename-Item -LiteralPath '%Windir%\System32\spp\store' -NewName 'store%RANDOM%' -Force"
	XCOPY "AVLBackup\*" "%Windir%\System32\spp" /E /H /Q /Y
)
Echo ----- Restoring Microsoft License
<nul Set /p=Do not close this windows. It takes a long time. Please wait ...
sc config sppsvc start= auto >nul 2>&1& net Start sppsvc >nul 2>&1
sc config osppsvc  start= auto >nul 2>&1& net Start osppsvc >nul 2>&1
sc config wuauserv start= auto >nul 2>&1& net Start wuauserv >nul 2>&1
sc config LicenseManager start= auto >nul 2>&1& net Start LicenseManager >nul 2>&1
cscript %windir%\system32\slmgr.vbs -rilc >nul 2>&1
cscript %windir%\system32\slmgr.vbs -dli >nul 2>&1
cscript %windir%\system32\slmgr.vbs -ato 
Echo ----- Checking Microsoft License Status
If not exist "ospp.vbs" Call :OfficePath
cscript %windir%\system32\slmgr.vbs /dli
cscript %windir%\system32\slmgr.vbs /xpr
cscript ospp.vbs /dstatus
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.E
cls
Echo ---------- AVL.6.E. Download Microsoft-Activation-Scripts ----------
Start "" "https://git.activated.win/massgrave/Microsoft-Activation-Scripts"
Start "" "https://github.com/massgravel/Microsoft-Activation-Scripts/releases/latest"
Echo powershell iex (irm https://get.activated.win)|clip 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.F
Cls
Echo ---------- AVL.6.F. Install Office Skus ----------
Set "URL=%SkusOffice%"
Set "File=SkusOffice.zip"
Set "FileDel=%File%"
Set "FolderDel=SkusOffice"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Running %File%
Start "" "%OfficeSKUS%"
Start SkusOffice\Install_License.bat
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.G 
Cls
Echo ---------- AVL.6.G. Install Windows Skus ----------
Set "URL=%SkusWindows%"
Set "File=SkusWindows.zip"
Set "FileDel=%File%"
Set "FolderDel=SkusWindows"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Running %File%
Start "" "%WindowsSKUS%"
Start SkusWindows\Install_License.bat
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.H 
Cls
Echo ---------- AVL.6.H. Download PIDkey ----------
Start "" "%pidkeyURL%"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.I
cls
Echo ---------- AVL.6.I. Download Office-Tool-Plus Downloader ----------
Set "link1=Powershell iex (irm https://www.officetool" 
Set "link2=.plus)"
Start %link1%%link2% 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.J
Cls
Echo ---------- AVL.6.J. Download PMAS ----------
Start "" "https://github.com/abdullah-erturk/pmas/releases/latest"
Call :AVL.Finish ""

:AVL.CheckSQLserver
set "x=false"
reg query "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2>nul | findstr /I /L "MSSQL16. MSSQL15. MSSQL14." >nul && set "x=true"

if /I "%x%"=="false" (
  reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2>nul | findstr /I /L "MSSQL16. MSSQL15. MSSQL14." >nul && set "x=true"
)

If "%x%" EQU "true" (
	Set "CheckSQLserver=Already_Installed"
) Else ( 
	Set "CheckSQLserver=Not_Available"
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.K
Cls
Echo ---------- AVL.6.K. Download VAMT ----------
Echo ----- Download ADK
Set "URL=https://go.microsoft.com/fwlink/?linkid=2289980"
Set "File=ADKsetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
If not exist "%File%" (Call :AVLDownload)
Echo ----- Install VAMT
Set "VAMTpath="
for /f "delims=" %%a in ('dir /s /b "%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\VAMT.msc" 2^>nul') do set VAMTpath=%%a
If "!VAMTpath!" EQU "" (
	Echo Installing VAMT
	start /wait "" "%File%" /quiet /norestart /features OptionId.VolumeActivationManagementTool /log %TEMP%\ADK_VAMT.log
) else (
	Echo VAMT has already been installed.
)
Del ADKsetup.exe
Call :AVL.CheckSQLserver
Echo ---------- Install SQL Server -----------
Echo   Status: %CheckSQLserver%
Echo   [1] SQL Server 2022 Express Edition
Echo   [2] SQL Server 2019 Express Edition
Echo   [3] SQL Server 2017 Express Edition
Echo   [0] Return to the previous menu
CHOICE /c 0123 /n /m "-------- (^_^) Your Wishes (^_^) --------"
Set /A Index=%ErrorLevel%-1
Set "List=0123"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.K.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.K.0
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.K.1
Echo ----- Installing SQL Server 2022 Express Edition
Set "URL=https://go.microsoft.com/fwlink/p/?linkid=2216019&clcid=0x409&culture=en-us&country=us"
Call :AVL.6.K.ALL

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.K.2
Echo ----- Installing SQL Server 2019 Express Edition
Set "URL=https://go.microsoft.com/fwlink/?linkid=866658"
Call :AVL.6.K.ALL

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.K.3
Echo ----- Installing SQL Server 2017 Express Edition
Set "URL=https://www.microsoft.com/en-us/download/details.aspx?id=55994"
Call :AVL.6.K.ALL

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.K.ALL
Set "File=SQLserverSetup.exe"
Set "FileDel=%File%"
Set "FolderDel=SQLInstallMedia"
If not exist "%File%" (Call :AVLDownload)
Echo ----- Running %File%
Start %File% 
Start "" "https://docs.google.com/document/u/1/d/e/2PACX-1vR5rcxvHggZqNojqoFjcide-1DRcBvnvILrCMYoXhAhp8LguzED7G5Z3rN45TrBLYUn-_IiOz65GEW9/pub"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.L
Cls
Echo ---------- AVL.6.L. Get Product Key From Mainboard ----------
For /F "tokens=*" %%a in ('Powershell "(Get-WmiObject SoftwareLicensingService).OA3xOriginalProductKey"') do (Set "ProductKey=%%a")
For /F %%b in ('Powershell -Command $Env:ProductKey.Length') do Set ProductKeyLen=%%b
If %ProductKeyLen% LSS 5 (
	Set "ProductKey=Not_Available"
	Set "Description=Not_Available"
	Set "PkPn=Not_Available"
) ELSE (
	For /F "tokens=*" %%a in ('Powershell "(Get-WmiObject SoftwareLicensingService).OA3xOriginalProductKeyDescription"') do (Set "Description=%%a")
	For /F "tokens=*" %%a in ('Powershell "(Get-WmiObject SoftwareLicensingService).OA3xOriginalProductKeyPkPn"') do (Set "PkPn=%%a")
)
Echo   Product Key : %ProductKey%
Echo   Description : %Description% 
Echo   Type        : %PkPn% 
Echo   (Product Key is sent to clipboard)
Echo %ProductKey%|clip
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.M
Set "k1="
cls
Echo ---------- AVL.6.M. Check Product Key Status ----------
Set /p "k1=Input Key (Enter Nothing To Exit):"
If "!k1!" EQU "" Goto !AVLBackMenu!
Call :CheckProductKey
Set "URL=https://pidkey.com/ajax/pidms_api?keys=%k1%&justgetdescription=0&apikey=%apikey%"
Powershell -Command "$response = Invoke-RestMethod -Uri '%URL%' -Method Get; Write-Output $response"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z
Set "A24=TjNGUVgtWDM0NlAtSkI3MkctOVFDSEYtOEI4ODM"
Set "A21=R0tWVEQtMktQVjItR0RZVzYtM005RkMtUjdOVEs"
Set "A19=TjlXVkotM1dZRFQtSkdCSjItOTZZS0MtTVAzM0Q"
Set "A16=TlhHMlAtRjZUWUItRFA5QjctUUhDRlItN0g3QkI"
Set "A13=UEg0SzgtS05HUDYtSjJRMlgtRjhZOVYtUkdCRzc"
Set "A10=SjQySjgtQzg5SDQtNFlKSkctWU1WM1YtNEQ0M0Y"
Set "B10=OUJHTkgtR0MzVEctVldEUUstWUpKSk0tTVk0OU0"
CLS
Echo ------ AVL.6. Auto Activation -------
Echo   [1] Windows 10 - 11 Pro
Echo   [2] Office 2024 Pro Plus Volume
Echo   [3] Office 2021 Pro Plus Volume
Echo   [4] Office 2019 Pro Plus Volume
Echo   [5] Office 2016 Pro Plus Volume
Echo   [6] Office 2013 Pro Plus Volume
Echo   [7] Office 2010 Pro Plus Volume
Echo   [0] Return to the previous menu
CHOICE /c 01234567 /n /m "------ (^_^) Your Wishes (^_^) ------"
Set /A Index=%ErrorLevel%-1
Set "List=01234567"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.6.Z.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z.0
Set "Y1=Uo0O2mQF8Mc1"
Set "Y2=Tmc5YXNiVDNHcDFTZQ"
For /f %%i in ('Powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%Y2%=='))"') do Set "apikey=%Y1%%%i"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z.1
For /f %%i in ('Powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%B10%='))"') do Set "k1=%%i"
Echo %k1%|clip
Goto AVL.6.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z.2
For /f %%i in ('Powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%A24%='))"') do Set "k1=%%i"
Echo %k1%|clip
Goto AVL.6.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z.3
For /f %%i in ('Powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%A21%='))"') do Set "k1=%%i"
Echo %k1%|clip
Goto AVL.6.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z.4
For /f %%i in ('Powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%A19%='))"') do Set "k1=%%i"
Echo %k1%|clip
Goto AVL.6.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z.5
For /f %%i in ('Powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%A16%='))"') do Set "k1=%%i"
Echo %k1%|clip
Goto AVL.6.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z.6
For /f %%i in ('Powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%A13%='))"') do Set "k1=%%i"
Echo %k1%|clip
Goto AVL.6.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.6.Z.7
For /f %%i in ('Powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%A10%='))"') do Set "k1=%%i"
Echo %k1%|clip
Goto AVL.6.1

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7
For %%a in (Zip7Status AnyDeskStatus EVKeyStatus FDMStatus HttpToolkitStatus HWinfoStatus ^
IDMStatus OBSStudioStatus OpenHashTabStatus RevoUninstallerStatus TeamViewerStatus TelegramStatus ^
UltraViewerStatus UnikeyStatus WindowsStoreStatus WinRARStatus ZaloStatus WingetStatus NeatDMStatus ABDMStatus DownloadMasterStatus) do Set "%%a=Not_Check"
Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Menu
cd /d "%~dp0"
Set "AVLBackMenu=AVL.7.Menu"
Set "FileDel="
Set "FolderDel="
cls
Echo ---------------------------- AVL.7. Download and Install ---------------------------- 
Echo   [1] Advanced IP Scanner                        [H] Office Tool - Yerong
Echo   [2] Android Emulator                           [I] Open-Hash-Tab (%OpenHashTabStatus%)
Echo   [3] Antivirus                                  [J] Open WinPE AVLboot URL
Echo   [4] Aria2c (%Aria2cStatus%)                         [K] Remote Support (Teamviewer...)
Echo   [5] Compressor (zip, rar, 7z)                  [L] Revo Uninstaller (%RevoUninstallerStatus%)
Echo   [6] Disk Space Analysis                        [M] Rufus
Echo   [7] DotNet Framework, DotNet Desktop Runtime   [N] Shortcut (Video Editor)
Echo   [8] Download Manager (IDM, NDM, FDM, ABDM)     [O] SpotX (Blocks Ads)
Echo   [9] Free-File-Sync                             [P] Telegram (%TelegramStatus%)
Echo   [A] Http Toolkit (%HttpToolkitStatus%)                   [Q] Vietnamese Keyboard (Unikey...)
Echo   [B] HWinfo (%HWinfoStatus%)                         [R] Ventoy
Echo   [C] K-Lite Codec Pack                          [S] VPN
Echo   [D] Microsoft Office 2016-2019-2021-2024-365   [T] Website Browser
Echo   [E] Microsoft Store (%WindowsStoreStatus%)                [U] Winget (%WingetStatus%)
Echo   [F] Microsoft Visual C++ Redistributable       [V] Zalo (%ZaloStatus%)
Echo   [G] OBSstudio (%OBSStudioStatus%)                      [X] Powershell
Echo   [0] Return to the Main Menu                    [Z] Check software status
CHOICE /c 0123456789ABCDEFGHIJKLMNOPQRSTUVXZ /n /m "------------------------- (^_^) Your Wishes Come True (^_^) -------------------------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDEFGHIJKLMNOPQRSTUVXZ"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.7.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::

:AVL.7.1
CLS
Echo -------------- AVL.7.1. Advanced IP Scanner --------------
Set "URL=https://www.advanced-ip-scanner.com/download/"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "(Select-String -Path a.txt -Pattern 'https://download\.advanced-ip-scanner\.com/download/files/Advanced_IP_Scanner_\d+\.\d+\.\d+\.\d+\.exe').Matches.Value"') do (Set "URL=%%A")
Del a.txt
Set "File=AdvancedIPScanner.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2
Echo ----- Check AndroidStudioStatus
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Android Studio" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Android Studio" >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "AndroidStudioStatus=%Result%"
Echo ----- Check BlueStacksStatus
Set "findstring=BlueStacks
Call :AndroidEmulatorStatus
Set "BlueStacksStatus=%Result%"
Echo ----- Check GameLoopStatus
Set "findstring=GameLoop"
Call :AndroidEmulatorStatus
Set "GameLoopStatus=%Result%"
Echo ----- Check GenymobileStatus
Set "findstring=Genymotion"
Call :AndroidEmulatorStatus
Set "GenymobileStatus=%Result%"
Echo ----- Check LDPlayerStatus
Set "findstring=LDPlayer"
Call :AndroidEmulatorStatus
Set "LDPlayerStatus=%Result%"
Echo ----- Check MEmuPlayerStatus
Set "findstring=Memu"
Call :AndroidEmulatorStatus
Set "MEmuPlayerStatus=%Result%"
If exist "%ProgramFiles%\Microvirt\MEmu\MEmu.exe" Set "MEmuPlayerStatus=Installed"
If exist "%ProgramFiles(x86)%\Microvirt\MEmu\MEmu.exe" Set "MEmuPlayerStatus=Installed"
If exist "D:\Program Files\Microvirt\MEmu\MEmu.exe" Set "MEmuPlayerStatus=Installed"
If exist "E:\Program Files\Microvirt\MEmu\MEmu.exe" Set "MEmuPlayerStatus=Installed"
If exist "F:\Program Files\Microvirt\MEmu\MEmu.exe" Set "MEmuPlayerStatus=Installed"
Echo ----- Check MuMuPlayerStatus
Set "findstring=MuMu"
Call :AndroidEmulatorStatus
Set "MuMuPlayerStatus=%Result%"
Echo ----- Check NoxPlayerStatus
Set "findstring=Nox"
Call :AndroidEmulatorStatus
Set "NoxPlayerStatus=%Result%"
Goto AVL.7.2.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.Menu
Set "AVLBackMenu=AVL.7.2.Menu"
Set "FileDel="
Set "FolderDel="
cls
Echo ------- AVL.7.2. Android Emulator -------
Echo   [1] Android Studio (%AndroidStudioStatus%)
Echo   [2] BlueStacks (%BlueStacksStatus%)
Echo   [3] GameLoop (%GameLoopStatus%)
Echo   [4] Genymotion (%GenymobileStatus%)
Echo   [5] LDPlayer (%LDPlayerStatus%)
Echo   [6] MEmuPlayer (%MEmuPlayerStatus%)
Echo   [7] MuMuPlayer (%MuMuPlayerStatus%)
Echo   [8] NoxPlayer (%NoxPlayerStatus%)
Echo   [0] Go to the previous Menu
CHOICE /c 123456780 /n /m "--- (^_^) Your Wishes Come True (^_^) ---"
If %ErrorLevel%==1 Goto AVL.7.2.1
If %ErrorLevel%==2 Goto AVL.7.2.2
If %ErrorLevel%==3 Goto AVL.7.2.3
If %ErrorLevel%==4 Goto AVL.7.2.4
If %ErrorLevel%==5 Goto AVL.7.2.5
If %ErrorLevel%==6 Goto AVL.7.2.6
If %ErrorLevel%==7 Goto AVL.7.2.7
If %ErrorLevel%==8 Goto AVL.7.2.8
If %ErrorLevel%==9 Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.1
CLS
Echo -------------- AVL.7.2.1. Android Studio --------------
Echo ----- Getting the latest version
Set "URL=https://developer.android.com/studio"
Set "File=a.txt"
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "$content = Get-Content a.txt -Raw; If ($content -match 'https://redirector\.gvt1\.com/edgedl/android/studio/install/.+?/android-studio-.+?-windows\.exe') { $matches[0] }"') do Set "URL=%%A"
Del a.txt
Set "File=AndroidStudio.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.2
CLS
Echo -------------- AVL.7.2.2. BlueStacks --------------
Set "URL=https://cloud.bluestacks.com/api/getdownloadnow"
Set "File=BlueStacksSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.3
CLS
Echo -------------- AVL.7.2.3. GameLoop --------------
Set "URL=https://down.gameloop.com/channel/3/26460/GLP_installer_900223150_market.exe"
netsh interface ip Set dns name="Ethernet" static 168.95.1.1
netsh interface ip add dns name="Ethernet" 168.95.192.1 index=2
netsh interface ip Set dns name="Wi-Fi" static 168.95.1.1
netsh interface ip add dns name="Wi-Fi" 168.95.192.1 index=2
Set "File=GLPinstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
netsh interface ip Set dns name="Wi-Fi" dhcp
netsh interface ip Set dns name="Ethernet" dhcp
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.4
CLS
Echo -------------- AVL.7.2.4. Genymotion --------------
Echo ----- Getting the latest version
Set "URL=https://www.genymotion.com/product-desktop/download/"
Set "File=a.txt"
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "$content = Get-Content a.txt -Raw; If ($content -match 'https://dl\.genymotion\.com/releases/genymotion-[0-9]+\.[0-9]+\.[0-9]+/genymotion-[0-9]+\.[0-9]+\.[0-9]+-vbox\.exe') { $matches[0] }"') do Set "URL=%%A"
Del a.txt
Set "File=genymotion.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.5
CLS
Echo -------------- AVL.7.2.5. LDPlayer --------------
Set "URL=https://vi.ldplayer.net/versions"
Set "File=a.txt"
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "$content = Get-Content a.txt -Raw; If ($content -match 'https://res\.ldrescdn\.com/download/LDPlayer[0-9]+\.exe') { $matches[0] }"') do Set "URL=%%A"
Del a.txt
Set "File=ldplayer.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.6
CLS
Echo -------------- AVL.7.2.6.MEmuPlayer --------------
Set "URL=https://www.memuplay.com/download-new.php?from=official_release_download"
Set "File=MEmuSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.7
CLS
Echo -------------- AVL.7.2.7. MuMuPlayer --------------
Set "URL=https://adl.easebar.com/d/g/a11/c/en_top"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "$content = Get-Content a.txt -Raw; If ($content -match 'https://[a-zA-Z0-9.-]+/MuMuInstaller_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_[a-zA-Z0-9_-]+\.exe') { $matches[0] }"') do Set "URL=%%A"
Del a.txt
Set "File=MuMuInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.2.8
CLS
Echo -------------- AVL.7.2.8. NoxPlayer --------------
Start "" "https://www.bignox.com/en/download/fullPackage"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AndroidEmulatorStatus
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /I "%findstring%" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "%findstring%" >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3
Set "AVLBackMenu=AVL.7.3"
Set "FileDel="
Set "FolderDel="
cls
Echo -------------- AVL.7.3. Antivrus --------------
Echo   [1] Install ESet Essential 
Echo   [2] Install ESet Premium 
Echo   [3] Install ESet Small Business Security
Echo   [4] Install Malwarebytes Version 4
Echo   [5] Install Malwarebytes Version 5
Echo   [6] Install Kaspersky Standard/Plus/Premium
Echo   [7] Install Kaspersky Small Office Security
Echo   [8] Scan by ESet Online Scanner 
Echo   [9] Scan by Microsoft Safety Scanner
Echo   [A] Scan by Emsisoft Emergency Kit
Echo   [B] Scan by Kaspersky - AVZ Toolkit
Echo   [C] Scan by DrWeb CureIt
Echo   [D] Antivirus Removal Tool
Echo   [0] Go to the previous menu
CHOICE /c 0123456789ABC /n /m "------ (^_^) Your Wishes Come True (^_^) ------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABC"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.7.3.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.0
Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.1
CLS
Echo -------------- AVL.7.3.1. ESet Essential --------------
Set "URL=https://download.eset.com/com/eset/tools/installers/live_eis/latest/eset_internet_security_live_installer.exe"
Set "File=EsetInternetSecurityInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.2
CLS
Echo -------------- AVL.7.3.2. ESet Premium --------------
Set "URL=https://download.eset.com/com/eset/tools/installers/live_essp/latest/eset_smart_security_premium_live_installer.exe"
Set "File=EsetSmartSecurityInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.3
CLS
Echo -------------- AVL.7.3.3. ESet Small Business Security --------------
Set "URL=https://download.eset.com/com/eset/tools/installers/live_esbs/latest/eset_small_business_security_live_installer.exe"
Set "File=EsetSmartBusinessSecurityInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.4
CLS
Echo -------------- AVL.7.3.4. Malwarebytes Version 4 --------------
Set "URL=https://data-cdn.mbamupdates.com/web/mb4-setup-consumer/offline/MBSetup.exe"
Set "File=MBSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.5
CLS
Echo -------------- AVL.7.3.5. Malwarebytes Version 5 --------------
Set "URL=https://data-cdn.mbamupdates.com/web/mb5-setup-consumer/MBSetup.exe"
Set "File=MBSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.6
CLS
Echo -------------- AVL.7.3.6. Install Kaspersky Standard/Plus/Premium --------------
Set "URL=https://box.kaspersky.com/f/9862e26c0aed494481b0/?dl=1"
Set "File=KasperskyInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.7
CLS
Echo -------------- AVL.7.3.7. Install Kaspersky Small Office Security --------------
Set "URL=https://kas.pr/ksos_vi_vn"
Set "File=KsosInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.8
CLS
Echo -------------- AVL.7.3.8. Scan by ESet --------------
Set "URL=https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner_enu.exe"
Set "File=esetonlinescanner.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.9
CLS
Echo -------------- AVL.7.3.9. Scan by Microsoft Safety Scanner --------------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=212732"
If /i exist "%windir%\SysWOW64" Set "URL=https://go.microsoft.com/fwlink/?LinkId=212733"
Set "File=msert.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.A
cls
Echo ------------ AVL.7.3.A. Scan by Emsisoft Emergency Kit ------------
Set "URL=https://dl.emsisoft.com/EmsisoftEmergencyKit.exe"
Set "File=EmsisoftEmergencyKit.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Run %File%
Start %File%"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.B
CLS
Echo -------------- AVL.7.3.B. Scan by Kaspersky --------------
Set "URL=https://media.kaspersky.com/utilities/ConsumerUtilities/avz5.zip"
Set "File=avz5.zip"
Set "FileDel=%File%"
Set "FolderDel=avz5"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Running %File%
Start avz5\avz5rn.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.C
CLS
Echo -------------- AVL.7.3.C. Scan by DrWeb --------------
Set "URL=https://free.drweb.com/download+cureit/gr/?lng=en"
Set "File=drwebsetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.3.D
cls
Echo ------------ AVL.7.3.D. Anitivirus Removal Tool ------------
Set "URL=https://antivirus-removal-tool.com/download/click.php?id=Antivirus_Removal_Tool"
Set "File=AntivirusRemovalTool.zip"
Set "FileDel=%File%"
Set "FolderDel=AntivirusRemovalTool"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Run Anitivirus Removal Tool
Start AntivirusRemovalTool\Antivirus_Removal_Tool.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.4
cls
Echo ---------- AVL.7.4. Aria2c -----------
If "!Aria2cCheck!" equ "false" (Call :AVL.CheckAria2c) 
If "!Aria2cStatus!" equ "Installed" (
	Echo Aria2c is available at "!Aria2cPath!".
) Else ( 
	Call :AVL.DownloadAria2c
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.5
cls
Echo ----- Check WinRARStatus
Set "link1=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
Set "link2=HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set "findstring=WinRAR archiver"
Call :SoftwareStatus
Set "WinRARStatus=%Result%"
Echo %Result%
Echo ----- Check 7ZipStatus
Set "link1=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
Set "link2=HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set "findstring=7-Zip"
Call :SoftwareStatus
Set "Zip7Status=%Result%"
Echo %Result%
cls
Set "AVLBackMenu=AVL.7.5"
Echo ------------ AVL.7.5. Compressor ------------
Echo   [1] 7-zip (%Zip7Status%)
Echo   [2] WinRar (%WinRARStatus%)
Echo   [0] Go to the previous Menu
CHOICE /c 120 /n /m "----- (^_^) Your Wishes Come True (^_^) -----"
If %ErrorLevel%==1 Goto AVL.7.5.1
If %ErrorLevel%==2 Goto AVL.7.5.2
If %ErrorLevel%==3 Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.5.1
CLS
Echo -------------- AVL.7.5.1. 7-Zip --------------
Echo ----- Getting the latest Version
Set "URL=https://www.7-zip.org"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=3 delims=() " %%a in ('find "Windows x64 (64-bit)" a.txt') do Set t1=%%a
Set t1=%t1:.=%
Del a.txt
Set "zip64=https://www.7-zip.org/a/7z%t1%-x64.exe"
Set "zip86=https://www.7-zip.org/a/7z%t1%.exe"
If EXIST "%Windir%\SysWOW64" (Set "URL=%zip64%") ELSE (Set "URL=%zip86%")
Set "File=zip7.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start "" "7z2501-x64" /S /D="%ProgramFiles%\7-Zip"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.5.2
CLS
Echo -------------- AVL.7.5.2 WinRAR --------------
Call :AVL.InstallWinRar
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.InstallWinRar
Set "URL=https://www.rarlab.com/download.htm"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('powershell -NoProfile -Command "(Select-String -Path 'a.txt' -Pattern '/rar/winrar-x64-.*?\.exe' -AllMatches | Select-Object -First 1).Matches[0].Value"') do set "URL=https://www.rarlab.com%%A"
Del a.txt
Set "File=winrar_setup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Echo RAR registration data>rarreg.key
Echo PITVN>>rarreg.key
Echo PITVN Community>>rarreg.key
Echo UID=5aa63b8a672358293772>>rarreg.key
Echo 641221225037725832e8886919730128dca6f27a78014744a9033d>>rarreg.key
Echo a93bb7f60acb9f6802f160ee145036bd6364b56873af282c39d7b8>>rarreg.key
Echo 71db23962ff3386eb16859182fabf97a7c12fea7c95e4c575a9270>>rarreg.key
Echo 8081e9679fbeceb80c7ec112805195b6716016ff78c6e633b08387>>rarreg.key
Echo 54717b04027ffe3b9a315c97c869436f077ec56a7e014987837445>>rarreg.key
Echo 9419199aca97c006b31cb34710b0b712c11b0844c308fbe260fd04>>rarreg.key
Echo 037ef0e4a78f9e36b5b3bbeaed780b6a44a84d9a2d921750704113>>rarreg.key
Start /Wait %File% /s
If exist "%ProgramFiles%\WinRAR" (Move /Y "rarreg.key" "%ProgramFiles%\WinRAR")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.6
Set "AVLBackMenu=AVL.7.6"
Set "FileDel="
Set "FolderDel="
cls
Echo ------ AVL.7.6. Disk Space Analysis -------
Echo   [1] Space-Sniffer
Echo   [2] Tree-Size
Echo   [3] Folder-Sizes
Echo   [4] Open Storage setting
Echo   [0] Return to the Main Menu                   
CHOICE /c 01234 /n /m "---- (^_^) Your Wishes Come True (^_^) ----"
Set /A Index=%ErrorLevel%-1
Set "List=01234"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.7.6.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.6.0
Goto AVL.7

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.6.1
cls
Echo -------------- AVL.7.6.1. Space Sniffer --------------
Echo ----- Getting the latest Version
Set "URL=https://www.uderzo.it/main_products/space_sniffer/download_alt.html"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('powershell -NoProfile -Command "(Select-String -Path 'a.txt' -Pattern 'files[\\/]spacesniffer.*?\.zip' -AllMatches | Select-Object -First 1).Matches[0].Value"') do set "Url=https://www.uderzo.it/main_products/space_sniffer/%%A"
Del a.txt
Set "File=SpaceSniffer.zip"
Set "FileDel=%File%"
Set "FolderDel=SpaceSniffer"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Running %File%
Start SpaceSniffer\SpaceSniffer.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.6.2
CLS
Echo -------------- AVL.7.6.2. Tree Size --------------
Set "URL=https://downloads.jam-software.de/treesize_free/TreeSizeFreeSetup.exe"
Set "File=TreeSizeFreeSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.6.3
cls
Echo -------------- AVL.7.6.3. Folder Sizes --------------
Echo ----- Getting the latest Version
Set "URL=https://www.foldersizes.com/download/downloading"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
for /f "delims=" %%A in ('powershell -NoProfile -Command "$match = Select-String -Path 'a.txt' -Pattern '/content/download/.*?\.exe' | Select-Object -First 1; if ($match) { $match.Matches[0].Value }"') do set "Url=https://www.foldersizes.com%%A"
Del a.txt
Echo URL=%URL%
Set "File=FolderSizesSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo 9UUUUU3UUUUU1VJMDU89XGQH0EYAYM2FQ58Q0NWUUPNM2DX3P3YHNUJSVSVTMSMG|clip
Echo Key: 9UUUUU3UUUUU1VJMDU89XGQH0EYAYM2FQ58Q0NWUUPNM2DX3P3YHNUJSVSVTMSMG
Echo The Key has been copied to the clipboard. Paste it into the application to activate.
Echo ----- Running %File%
Start %File%"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.6.4
Start ms-settings:storagesense
Call :%AVLBackMenu%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7
Reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5" /v Install >nul 2>&1
If %ErrorLevel%==0 (Set "status350=Installed") Else (Set "status350=Not_Exist")
For /f "tokens=3" %%v in ('Reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Version') do Set NET_VERSION=%%v
Reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Version >nul 2>&1
If %ErrorLevel% NEQ 0 Set "NET_VERSION=Not_Exist"
Set "DotNet8=Not_Exist"
For /f "tokens=1,2" %%i in ('dotnet --list-runtimes ^| findstr /c:"Microsoft.WindowsDesktop.App 8."') do (Set "DotNet8=version %%j")
Set "DotNet9=Not_Exist"
For /f "tokens=1,2" %%i in ('dotnet --list-runtimes ^| findstr /c:"Microsoft.WindowsDesktop.App 9."') do (Set "DotNet9=version %%j")

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.Menu
Set "AVLBackMenu=AVL.7.7.Menu"
Set "FileDel="
Set "FolderDel="
cls
Echo ----- AVL.7.7. .NET Framework, .NET Desktop Runtime -----
Echo   .NET Framework 3.5: %status350%
Echo   [1] .NET Framework 3.5 SP1
Echo   .NET Framework 4: version %NET_VERSION%
Echo   [2] .NET Framework 4.6.2 online
Echo   [3] .NET Framework 4.6.2 offline
Echo   [4] .NET Framework 4.7 online
Echo   [5] .NET Framework 4.7 offline
Echo   [6] .NET Framework 4.7.1 online
Echo   [7] .NET Framework 4.7.1 offline
Echo   [8] .NET Framework 4.7.2 online
Echo   [9] .NET Framework 4.7.2 offline
Echo   [A] .NET Framework 4.8 online
Echo   [B] .NET Framework 4.8 offline
Echo   [C] .NET Framework 4.8.1 online
Echo   [D] .NET Framework 4.8.1 offline
Echo   [E] Open .NET Framework download link
Echo   .NET Desktop Runtime 8: %DotNet8%
Echo   [F] .NET Desktop Runtime 8
Echo   .NET Desktop Runtime 9: %DotNet9%
Echo   [G] .NET Desktop Runtime 9
Echo   [0] Go to the previous Menu
CHOICE /c 0123456789ABCDEFG /n /m "----------- (^_^) Your Wishes Come True (^_^) -----------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDEFG"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.7.7.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.0
Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:Process

Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.1
CLS
Echo ------- AVL.7.7.1. DotNet Framework 3.5 SP1 -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=2186537"
Set "File=dotnet350.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.2
CLS
Echo ------- AVL.7.7.2. DotNet Framework 4.6.2 online -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=780596"
Set "File=dotnet462online.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.3
CLS
Echo ------- AVL.7.7.3. DotNet Framework 4.6.2 offline -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=2099468"
Set "File=dotnet462offline.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.4
CLS
Echo ------- AVL.7.7.4. DotNet Framework 4.7 online -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=825298"
Set "File=dotnet470online.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.5
CLS
Echo ------- AVL.7.7.5. DotNet Framework 4.7 offline -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=2099385"
Set "File=dotnet470offline.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.6
CLS
Echo ------- AVL.7.7.6. DotNet Framework 4.7.1 online -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=852092"
Set "File=dotnet471online.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.7
CLS
Echo ------- AVL.7.7.7. DotNet Framework 4.7.1 offline -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=2099383"
Set "File=dotnet471offline.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.8
CLS
Echo ------- AVL.7.7.8. DotNet Framework 4.7.2 online -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=863262"
Set "File=dotnet472online.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.9
CLS
Echo ------- AVL.7.7.9. DotNet Framework 4.7.2 offline -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=863265"
Set "File=dotnet472offline.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.A
CLS
Echo ------- AVL.7.7.A. DotNet Framework 4.8 online -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=2085155"
Set "File=dotnet480online.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.B
CLS
Echo ------- AVL.7.7.B. DotNet Framework 4.8 offline -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=2088631"
Set "File=dotnet480offline.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.C
CLS
Echo ------- AVL.7.7.C. DotNet Framework 4.8.1 online -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=2203304"
Set "File=dotnet481online.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.D
CLS
Echo ------- AVL.7.7.D. DotNet Framework 4.8.1 offline -------
Set "URL=https://go.microsoft.com/fwlink/?LinkId=2203305"
Set "File=dotnet481offline.exe"
Call :Process

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.E
Start "" "https://dotnet.microsoft.com/en-us/download/dotnet-framework"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.F
Set "URL=https://dotnet.microsoft.com/en-us/download/dotnet/8.0"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "(Select-String -Path a.txt -Pattern '/en-us/download/dotnet/thank-you/runtime-desktop-\d+.\d+.\d+-windows-x64-installer').Matches.Value"') do (Set "Url64=%%A")
For /f "tokens=5 delims=-" %%A in ("%Url64%") do Set "version1=%%A"
Set "URL=https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/%version1%/windowsdesktop-runtime-%version1%-win-x64.exe"
Set "File=DotNet8_64Setup.exe"
Call :AVLDownload
Echo ----- Running %File%
Start /wait %File%
Set "URL=https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/%version1%/windowsdesktop-runtime-%version1%-win-x86.exe"
Set "File=DotNet8_86Setup.exe"
Set "FileDel=DotNet8*"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start /wait %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.7.G
Set "URL=https://dotnet.microsoft.com/en-us/download/dotnet/9.0"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "(Select-String -Path a.txt -Pattern '/en-us/download/dotnet/thank-you/runtime-desktop-\d+.\d+.\d+-windows-x64-installer').Matches.Value"') do (Set "Url64=%%A")
For /f "tokens=5 delims=-" %%A in ("%Url64%") do Set "version1=%%A"
Set "URL=https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/%version1%/windowsdesktop-runtime-%version1%-win-x64.exe"
Set "File=DotNet9_64Setup.exe"
Call :AVLDownload
Echo ----- Running %File%
Start /wait %File%
Set "URL=https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/%version1%/windowsdesktop-runtime-%version1%-win-x86.exe"
Set "File=DotNet9_86Setup.exe"
Set "FileDel=DotNet9*"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start /wait %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8
cls
Set "AVLBackMenu=AVL.7.8"
Echo --------- AVL.7.8. Download Manager ---------
Echo   [1] Internet Download Manager (%IDMStatus%)
Echo   [2] Free Download Manager (%FDMStatus%)
Echo   [3] Neat Download Manager (%NeatDMStatus%)
Echo   [4] AB Download Manager (%ABDMStatus%)
Echo   [5] Download Master (%DownloadMasterStatus%)
Echo   [6] Check Status
Echo   [0] Go to the previous Menu
CHOICE /c 1234560 /n /m "----- (^_^) Your Wishes Come True (^_^) -----"
If %ErrorLevel%==1 Goto AVL.7.8.1
If %ErrorLevel%==2 Goto AVL.7.8.2
If %ErrorLevel%==3 Goto AVL.7.8.3
If %ErrorLevel%==4 Goto AVL.7.8.4
If %ErrorLevel%==5 Goto AVL.7.8.5
If %ErrorLevel%==6 Goto AVL.7.8.6
If %ErrorLevel%==7 Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1
Echo ----- Check IDMStatus
For /f "usebackq delims=" %%a in (`Powershell -Command "(Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -like '*Internet Download*' }).DisplayVersion"`) do Set idmver=%%a
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Internet Download Manager" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
Reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Internet Download Manager" >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If exist "%ProgramFiles(x86)%\Internet Download Manager\IDMan.exe" (Set "c3=1") ELSE (Set "c3=0")
If "%c1%%c2%%c3%" NEQ "000" (Set "IDMStatus=Installed - Version: %idmver%") Else (Set "IDMStatus=Not_Exist")
Reg query "HKCU\Software\DownloadManager" /v Serial >nul 2>&1
If %errorlevel%==0 (
    Set "IDMStatus=%IDMStatus% - Licensed"
)
Set "AVLBackMenu=AVL.7.8.1"
Set "FileDel="
Set "FolderDel="
CLS
Echo ------------ AVL.7.8.1. Internet Download Manager -----------
Echo   Status: %IDMStatus%
Echo   [1] Install the latest version Internet Download Manager
Echo   [2] Run IAS from sh4mim
Echo   [3] Run IDM Auto reset from shariful998765
Echo   [4] Download IDM-Activator 
Echo   [5] Uninstall IDM
Echo   [6] Query IDM registry
Echo   [7] Remove IDM registry
Echo   [8] Reset IDM Trial 
Echo   [9] Open IDM extension in Chrome/Edge Store
Echo   [0] Go to the previous Menu
CHOICE /c 1234567890 /n /m "------------- (^_^) Your Wishes Come True (^_^) -------------"
Set /A Index=%ErrorLevel%-1
Set "List=1234567890"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.7.8.1.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.0
Goto AVL.7.8

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.1
cls
Echo ----- AVL.7.8.1.1. Install the latest version IDM -----
Set "URL=https://www.internetdownloadmanager.com/download.html"
Set "File=a.html"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "$Pattern='https://mirror2.internetdownloadmanager\.com/idman\d+build\d+\.exe';" ^
	"$Matches=[regex]::Match((Get-Content -Raw a.html), $Pattern);" ^
	"If ($Matches.Success) { $Matches.Value }"') do Set "URL=%%A"
DEL %File%
Set "File=idman_setup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start "" "%File%" /skipdlgs
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.2
cls
Echo ----- AVL.7.8.1.2. Download IAS from sh4mim -----
Set "Link1=https://gitla"
Set "Link2=b.com/sh4mim/IDM-Activation-Script/-/raw/main/IAS.cmd"
Set "URL=%Link1%%Link2%"
Set "File=IAS.cmd"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.3
cls
Echo ----- AVL.7.8.1.3. Download IDM Auto reset from shariful998765 -----
Set "URL=https://github.com/shariful998765/IDM_Auto_Reg_reset_Tools_Script/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set t1=%t1:~1%
Del a.txt
Set "URL=https://github.com/shariful998765/IDM_Auto_Reg_reset_Tools_Script/archive/refs/tags/v%t1%.zip"
Set "File=IDMAutoreset.zip"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Extracting IDM Auto reset
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo Run IDM Auto reset ...
Echo ----- Running %File%
Start IDMAutoreset\idm_auto_trial_reset.bat
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.4
cls
Echo ----- AVL.7.8.1.4. Download IDM-Activator -----
Start "" "%CrkURL%"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.5
cls
Echo ----- AVL.7.8.1.5. Uninstall IDM -----
taskkill /f /im IDMan.exe >nul 2>&1
Set "path1=%ProgramFiles%\Internet Download Manager\uninstall.exe"
If exist "%path1%" (Start /wait "" "%path1%")
Set "path2=%ProgramFiles(x86)%\Internet Download Manager\uninstall.exe"
If exist "%path2%" (Start /wait "" "%path2%")
Reg delete "HKCU\Software\DownloadManager" /f >nul 2>&1
Call :AVL.Finish "IDM has been successfully uninstalled"

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.6
cls
Echo ----- AVL.7.8.1.6 Query IDM registry -----
Reg query "HKCU\Software\DownloadManager" | findstr /i "Fname Lname Email Serial"
If %ErrorLevel%==0 (
	Echo Query successfully !
) Else (
	Echo Failed to Query !
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.7
cls
Echo ----- AVL.7.8.1.7 Remove IDM registry -----
Reg delete "HKCU\Software\DownloadManager" /f >nul 2>&1
If %ErrorLevel%==0 (
	Echo Remove successfully !
) Else (
	Echo Failed to Remove !
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.8
cls
Echo ----- AVL.7.8.1.8 reset IDM Trial -----
Echo ----- Check If IDM is running
tasklist /FI "IMAGENAME eq IDMan.exe" 2>nul | findstr /I "IDMan.exe" >nul
If %errorlevel%==0 (taskkill /im IDMan.exe /f >nul 2>&1)
Echo ----- Remove AppData folder first (safe operation)
If exist "%APPDATA%\IDM" (
    rd /s /q "%APPDATA%\IDM" >nul 2>&1
    If !errorlevel! == 0 (
        Echo Successfully deleted folder: %APPDATA%\IDM
    ) else (
        Echo FAILED to delete folder: %APPDATA%\IDM
    )
) else (
    Echo Folder not found: %APPDATA%\IDM
)
Echo ----- Starting registry cleanup
Reg delete "HKCU\Software\DownloadManager" /f >nul 2>&1
If %ErrorLevel%==0 (
	Echo Remove successfully !
) Else (
	Echo Failed to Remove !
)
Echo ----- Try to reopen IDM
Set "path1=%ProgramFiles%\Internet Download Manager\IDMan.exe"
If exist %path1% Start "" "%path1%"
Set "path2=%ProgramFiles(x86)%\Internet Download Manager\IDMan.exe"
If exist %path2% Start "" "%path2%"
Call :AVL.Finish "IDM has been reset and restarted"

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.1.9
cls
Echo -------- Open IDM extension in Chrome/Edge Store  --------
Start "" "https://chromewebstore.google.com/detail/idm-integration-module-mv/ehembjnecgpecgjpdpfaembeeifahnfd"
Start "" "https://microsoftedge.microsoft.com/addons/detail/idm-integration-module/llbjbkhnmlidjebalopleeepgdfgcpec"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.2
cls
Echo -------------- AVL.7.8.2 Free Download Manager --------------
:: Get FDM from https://www.freedownloadmanager.org/download.htm
Set "freedownloadmanager64=https://files2.freedownloadmanager.org/6/latest/fdm_x64_setup.exe"
Set "freedownloadmanager86=https://files2.freedownloadmanager.org/6/latest/fdm_x86_setup.exe"
If EXIST "%Windir%\SysWOW64" (Set "URL=%freedownloadmanager64%") ELSE (Set "URL=%freedownloadmanager86%")
Set "File=FreeDownloadManager.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.3
cls
Echo -------------- AVL.7.8.3. Neat Download Manager --------------
Set "URL=https://neatdownloadmanager.com/file/NeatDM_setup.exe"
Set "File=NeatDM_setup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start /Wait %File% /SILENT
choice /T 5 /D Y /N > nul
Start "" "%ProgramFiles(x86)%\Neat Download Manager\NeatDM.exe"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.4
cls
Echo -------------- AVL.7.8.4. AB Download Manager --------------
Set "URL=https://github.com/amir1376/ab-download-manager/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set t1=%t1:~1%
Del a.txt
Set "URL=https://github.com/amir1376/ab-download-manager/releases/download/v%t1%/ABDownloadManager_%t1%_windows_x64.exe"
Set "File=ABDM_Setup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.5
cls
Echo -------------- AVL.7.8.5. Download Master --------------
Set "URL=https://download.westbyte.com/dm/dmaster.exe"
Set "File=dmaster.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.8.6
cls
Echo ----------- AVL.7.8.6. Check Status -----------
dir /s /a "C:\Program Files\Neat Download Manager" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
dir /s /a "C:\Program Files (x86)\Neat Download Manager" >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "NeatDMStatus=%Result%"
Echo %Result%
Echo ----- Check FDMStatus
dir /s /a "C:\Program Files\FreeDownloadManager" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
dir /s /a "C:\Program Files (x86)\FreeDownloadManager" >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "FDMStatus=%Result%"
Echo %Result%
Echo ----- Check IDMStatus
Set "link1=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
Set "link2=HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set "findstring=Internet Download Manager"
Call :SoftwareStatus
Set "IDMStatus=%Result%"
Echo %Result%
Echo ----- Check ABDMStatus
If exist "%LOCALAPPDATA%\ABDownloadManager\ABDownloadManager.exe" (Set "c1=1") ELSE (Set "c1=0")
tasklist | findstr /i "abdownloadmanager*"
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "ABDMStatus=Installed") Else (Set "ABDMStatus=Not_Exist")
Echo %ABDMStatus%
Echo ----- Check DownloadMasterStatus
::"C:\Program Files (x86)\Download Master\dmaster.exe"
If exist "%ProgramFiles(x86)%\Download Master\dmaster.exe" (Set "c1=1") ELSE (Set "c1=0")
If exist "%ProgramFiles)%\Download Master\dmaster.exe" (Set "c3=1") ELSE (Set "c3=0")
tasklist | findstr /i "dmaster.exe" >nul
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "!c1!!c2!!c3!" NEQ "000" (Set "DownloadMasterStatus=Installed") Else (Set "DownloadMasterStatus=Not_Exist")
Echo %DownloadMasterStatus%
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.9
CLS
Echo -------------- AVL.7.9. Free File Sync --------------
Set "URL=https://freefilesync.org/download.php"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "$content = Get-Content a.txt -Raw; If ($content -match '/download/FreeFileSync_+?.+?_Windows_Setup.exe') { $matches[0] }"') do Set "URL=https://freefilesync.org%%A"
Del a.txt
Set "File=FreeFileSync.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.A
CLS
Echo -------------- AVL.7.A. Http Toolkit --------------
Set "URL=https://github.com/httptoolkit/httptoolkit-desktop/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set t1=%t1:~1%
Del a.txt
Set "URL=https://github.com/httptoolkit/httptoolkit-desktop/releases/download/v%t1%/HttpToolkit-%t1%.exe"
Set "File=HttpToolkit.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.B
CLS
Echo -------------- AVL.7.B. HWInfo --------------
Set "URL=https://www.hwinfo.com/download/"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%a in ('Powershell -nologo -command "(Select-String -Path 'a.txt' -Pattern 'https://www\.sac\.sk/download/utildiag/hwi_\d+\.zip').Matches[0].Value"') do Set "URL=%%a"
Del a.txt
Set "File=hwinfo.zip"
Set "FileDel=%File%"
Set "FolderDel=HwInfo"
Call :AVLDownload
Echo ----- Extracting HwInfo
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo Run HwInfo ...
If exist "%windir%\SysWOW64" (Start "" "%~dp0HwInfo\HWiNFO64.exe") else (Start "" "%~dp0HwInfo\HWiNFO32.exe")
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.C
CLS
Set "AVLBackMenu=AVL.7.C"
Set "FileDel="
Set "FolderDel="
Echo ---- AVL.7.C. K-Lite Codec Pack -----
Echo   [1] Standard K-Lite Codec Pack
Echo   [2] Full K-Lite Codec Pack
Echo   [3] Mega K-Lite Codec Pack
Echo   [4] Basic K-Lite Codec Pack
Echo   [0] Go to the previous Menu
CHOICE /c 01234 /n /m "------ (^_^) Your Wishes (^_^) ------"
Set /A Index=%ErrorLevel%-1
Set "List=01234"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.7.C.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.C.0
Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.C.1
CLS
Echo -------------- AVL.7.C.1. Standard K-Lite Codec Pack --------------
Echo ----- Getting the latest Version
Set "URL=https://www.codecguide.com/download_k-lite_codec_pack_standard.htm"
Set "SearchPattern=https://files2.codecguide.com/K-Lite_Codec_Pack_\d+_Standard.exe"
Goto AVL.7.C.Download

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.C.2
CLS
Echo -------------- AVL.7.C.2. Full K-Lite Codec Pack --------------
Echo ----- Getting the latest Version
Set "URL=https://www.codecguide.com/download_k-lite_codec_pack_full.htm"
Set "SearchPattern=https://files2.codecguide.com/K-Lite_Codec_Pack_\d+_Full.exe"
Goto AVL.7.C.Download

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.C.3
CLS
Echo -------------- AVL.7.C.3. Mega K-Lite Codec Pack --------------
Echo ----- Getting the latest Version
Set "URL=https://www.codecguide.com/download_k-lite_codec_pack_mega.htm"
Set "SearchPattern=https://files2.codecguide.com/K-Lite_Codec_Pack_\d+_Mega.exe"
Goto AVL.7.C.Download

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.C.4
CLS
Echo -------------- AVL.7.C.4. Basic K-Lite Codec Pack --------------
Echo ----- Getting the latest Version
Set "URL=https://www.codecguide.com/download_k-lite_codec_pack_basic.htm"
Set "SearchPattern=https://files2.codecguide.com/K-Lite_Codec_Pack_\d+_Basic.exe"
Goto AVL.7.C.Download

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.C.Download
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
for /f "delims=" %%A in ('powershell -NoProfile -Command "$match = Select-String -Path 'a.txt' -Pattern '%SearchPattern%' | Select-Object -First 1; if ($match) { $match.Matches[0].Value }"') do set "URL=%%A"
Del a.txt
Set "File=KLiteSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D
Set "AVLBackMenu=AVL.7.Menu"
cd /d "%~dp0"
cls
Echo ---------- AVL.7.D. Microsoft Office 2016, 2019, 2021, 2024, 365 ----------
Echo ----- Getting Information
For /F "tokens=2,*" %%I in ('Reg query "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" /v ProductReleaseIds 2^>nul') do Set OfficeVersion=%%J
For /F %%b in ('Powershell -Command $Env:OfficeVersion.Length') do Set OfficeVersionLen=%%b
For /f "tokens=2,* delims= " %%A in ('Reg query "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" /v ProductReleaseIds ^| find "ProductReleaseIds" 2^>nul') do (
	For /f "tokens=1 delims=," %%C in ("%%B") do Set "ProductID=%%C"
)
For /F %%b in ('Powershell -Command "$Env:ProductID.Length"') do Set "ProductIDLen=%%b"
If %ProductIDLen% LSS 5 (Set "ProductID=Not_Available")
Echo ----- Get the ExcludedApps list from registry
For /f "tokens=1,2,* delims= " %%A in ('Reg query "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" ^| find "ExcludedApps" 2^>nul') do Set ExcludedApps=%%C
Echo ----- List of all Office apps
Set "AllApps=Word Excel Powerpoint Access Outlook Onenote Publisher Teams Onedrive Lync Groove Bing"
Echo ----- Initialize result variable
Set "result="
Echo ----- Compare lists and store installed apps
For %%A in (%AllApps%) do (
    Echo %ExcludedApps% | findstr /i /c:"%%A" >nul || Set "result=!result!, %%A"
)
Echo ----- Remove leading comma and space
Set "InstalledApps=%result:~2%"
For /f "delims=" %%A in ('Powershell -Command "$culture = New-Object System.Globalization.CultureInfo('en-US'); $culture.TextInfo.ToTitleCase('%InstalledApps%')"') do Set "InstalledApps=%%A"
If %OfficeVersionLen% LSS 5 (
	Set "OfficeVersion=Not_Available"
	Set "InstalledApps=Not_Available"
)
Echo ----- Download Office Deployment Tool
Set "ODTpath=%~dp0Tool\setup.exe"
If exist "!ODTpath!" Goto AVL.7.D.1
For /f "tokens=*" %%A in ('Powershell -Command "& {$url='https://www.microsoft.com/en-us/download/details.aspx?id=49117';$content=Invoke-WebRequest -Uri $url -UseBasicParsing;$link=$content.Links | Where-Object {$_.href -match 'https://download.microsoft.com/download/.*officedeploymenttool.*\.exe'} | Select-Object -ExpandProperty href;Write-Output $link}"') do Set "URL=%%A"
Echo %URL%
::Set "URL=https://download.microsoft.com/download/6c1eeb25-cf8b-41d9-8d0d-cc1dbc032140/officedeploymenttool_18526-20146.exe"
Set "File=officedeploymenttool.exe"
Set "FilePath=%~dp0!File!"
Set "FileDel=!File!"
Set "FolderDel="
Call :AVLDownload
If not exist "Tool" md "Tool"
Move /y "%~dp0officedeploymenttool.exe" "%~dp0Tool"
Echo ----- Extract Setup.exe from OfficeDeploymentTool.exe
%~dp0Tool\officedeploymenttool.exe /quiet /extract:"%~dp0Tool"
Echo ----- Check If setup.exe is available
If exist "!ODTpath!" (
	Del "%~dp0Tool\officedeploymenttool.exe"
	Del "%~dp0Tool\configuration-Office365-x64.xml"
) Else (
	Call :AVL.Finish "Fail to extract"
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.1
If "%Processor_Architecture%"=="x86" (Set "Architecture=32-bit") Else (Set "Architecture=64-bit")
Set "on=(Yes)"
Set "off=(No) "
For /F "tokens=*" %%b in ('Powershell -command "(Get-InstalledLanguage).LanguageID"') do Set "LanguageID=%%b"

Echo ----- Getting Version, Apps, Updatel Channel, Language
If "%ProductID%" EQU "Not_Available" Goto AVL.7.D.G
Set "allowed=O365ProPlusRetail O365BusinessRetail ProPlus2024Volume ProPlus2024Retail ProPlus2021Volume ProPlus2021Retail ProPlus2019Volume ProPlus2019Retail ProPlusRetail"
Echo %allowed% | findstr /C:"%ProductID%" >nul
If %errorlevel% NEQ 0 goto AVL.7.D.G
Echo %InstalledApps% | find "Word" >nul && Set "opt1=%on%" || Set "opt1=%off%"
Echo %InstalledApps% | find "Excel" >nul && Set "opt2=%on%" || Set "opt2=%off%"
Echo %InstalledApps% | find "Powerpoint" >nul && Set "opt3=%on%" || Set "opt3=%off%"
Echo %InstalledApps% | find "Access" >nul && Set "opt4=%on%" || Set "opt4=%off%"
Echo %InstalledApps% | find "Outlook" >nul && Set "opt5=%on%" || Set "opt5=%off%"
Echo %InstalledApps% | find "Onenote" >nul && Set "opt6=%on%" || Set "opt6=%off%"
Echo %InstalledApps% | find "Publisher" >nul && Set "opt7=%on%" || Set "opt7=%off%"
Echo %InstalledApps% | find "Teams" >nul && Set "opt8=%on%" || Set "opt8=%off%"
Echo %InstalledApps% | find "Onedrive" >nul && Set "opt9=%on%" || Set "opt9=%off%"
Echo %InstalledApps% | find "Bing" >nul && Set "optA=%on%" || Set "optA=%off%"
For %%L in (B C D E F) do Set "opt%%L=%off%"
Set "optP=%ProductID%"
If "%optP%" EQU "O365ProPlusRetail" (
	Set "optV=365"
	Set "Project=ProjectPro2024Retail"
	Set "Visio=VisioPro2024Retail"
	Set "optU=Current"
)
If "%optP%" EQU "O365BusinessRetail" (
	Set "optV=365"
	Set "Project=ProjectPro2024Retail"
	Set "Visio=VisioPro2024Retail"
	Set "optU=Current"
)
If "%optP%" EQU "ProPlus2024Volume" (
	Set "optV=2024"
	Set "Project=ProjectPro2024Volume"
	Set "Visio=VisioPro2024Volume"
	Set "optU=PerpetualVL2024"
)
If "%optP%" EQU "ProPlus2024Retail" (
	Set "optV=2024"
	Set "Project=ProjectPro2024Retail"
	Set "Visio=VisioPro2024Retail"
	Set "optU=Current"
)
If "%optP%" EQU "ProPlus2021Volume" (
	Set "optV=2021"
	Set "Project=ProjectPro2021Volume"
	Set "Visio=VisioPro2021Volume"
	Set "optU=PerpetualVL2021"
)
If "%optP%" EQU "ProPlus2021Retail" (
	Set "optV=2021"
	Set "Project=ProjectPro2021Retail"
	Set "Visio=VisioPro2021Retail"
	Set "optU=Current"
)
If "%optP%" EQU "ProPlus2019Volume" (
	Set "optV=2019"
	Set "Project=ProjectPro2019Volume"
	Set "Visio=VisioPro2019Volume"
	Set "optU=PerpetualVL2019"
)
If "%optP%" EQU "ProPlus2019Retail" (
	Set "optV=2019"
	Set "Project=ProjectPro2019Retail"
	Set "Visio=VisioPro2019Retail"
	Set "optU=Current"
)
If "%optP%" EQU "ProPlusRetail" (
	Set "optV=2016"
	Set "Project=ProjectProRetail"
	Set "Visio=VisioProRetail"
	Set "optU=Current"
)
If "%Architecture%"=="64-bit" (
	Set "optI=64-bit"
	Set "OfficeClientEdition=64"
)
If "%Architecture%"=="32-bit" (
	Set "optI=32-bit"
	Set "OfficeClientEdition=32"
)
Set "optL=%LanguageID%"
Set "optT=Install_Online"

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.InstallOfficeMENU
Set "OCS=AVLconfig.xml"
Set "AVLBackMenu=AVL.7.D.InstallOfficeMENU"
CLS
Echo ---------- AVL.7.D. Microsoft Office 2016, 2019, 2021, 2024, 365 ----------
Echo     OS Architecture: %Architecture%. OS Language ID: %LanguageID%. 
Echo     Current Edition: %OfficeVersion%.
Echo     Installed Apps : %InstalledApps%.
Echo ---------------------------------------------------------------------------
<NUL Set/P=[V] Office Version : & (Call :EchoColor "%optV%" %ContrastColor%) & Echo  .
<NUL Set/P=[P] Product ID     : & (Call :EchoColor "%optP%" %ContrastColor%) & Echo  .
<NUL Set/P=[U] Update Channel : & (Call :EchoColor "%optU%" %ContrastColor%) & Echo  .
<NUL Set/P=[I] Architecture   : & (Call :EchoColor "%optI%" %ContrastColor%) & Echo  .
<NUL Set/P=[L] Office Language: & (Call :EchoColor "%optL%" %ContrastColor%) & Echo  .
<NUL Set/P=[T] Deployment Type: & (If "%optT%"=="Uninstall" (Call :EchoColor "%optT%" 5e) Else (Call :EchoColor "%optT%"  %ContrastColor%) ) & Echo  .
<NUL Set/P=[1] & (If "%opt1%"=="%on%" (Call :EchoColor "%opt1%"  %ContrastColor%)  Else (<NUL Set/P="%opt1%")) & <NUL Set/P=Microsoft Word.             [2] & (If "%opt2%"=="%on%" (Call :EchoColor "%opt2%"  %ContrastColor%)  Else (<NUL Set/P="%opt2%")) & Echo Microsoft Excel.
<NUL Set/P=[3] & (If "%opt3%"=="%on%" (Call :EchoColor "%opt3%"  %ContrastColor%)  Else (<NUL Set/P="%opt3%")) & <NUL Set/P=Microsoft PowerPoint.       [4] & (If "%opt4%"=="%on%" (Call :EchoColor "%opt4%"  %ContrastColor%)  Else (<NUL Set/P="%opt4%")) & Echo Microsoft Access.
<NUL Set/P=[5] & (If "%opt5%"=="%on%" (Call :EchoColor "%opt5%"  %ContrastColor%)  Else (<NUL Set/P="%opt5%")) & <NUL Set/P=Microsoft Outlook.          [6] & (If "%opt6%"=="%on%" (Call :EchoColor "%opt6%"  %ContrastColor%)  Else (<NUL Set/P="%opt6%")) & Echo Microsoft OneNote.
<NUL Set/P=[7] & (If "%opt7%"=="%on%" (Call :EchoColor "%opt7%"  %ContrastColor%)  Else (<NUL Set/P="%opt7%")) & <NUL Set/P=Microsoft Publisher.        [8] & (If "%opt8%"=="%on%" (Call :EchoColor "%opt8%"  %ContrastColor%)  Else (<NUL Set/P="%opt8%")) & Echo Microsoft Teams.
<NUL Set/P=[9] & (If "%opt9%"=="%on%" (Call :EchoColor "%opt9%"  %ContrastColor%)  Else (<NUL Set/P="%opt9%")) & <NUL Set/P=Microsoft OneDrive.         [A] & (If "%optA%"=="%on%" (Call :EchoColor "%optA%"  %ContrastColor%)  Else (<NUL Set/P="%optA%")) & Echo Microsoft Bing.
<NUL Set/P=[B] & (If "%optB%"=="%on%" (Call :EchoColor "%optB%"  %ContrastColor%)  Else (<NUL Set/P="%optB%")) & <NUL Set/P=Microsoft Proofing Tools.   [C] & (If "%optC%"=="%on%" (Call :EchoColor "%optC%"  %ContrastColor%)  Else (<NUL Set/P="%optC%")) & Echo %Project%.
<NUL Set/P=[D] & (If "%optD%"=="%on%" (Call :EchoColor "%optD%"  %ContrastColor%)  Else (<NUL Set/P="%optD%")) & <NUL Set/P=Create Shortcut To Desktop. [E] & (If "%optE%"=="%on%" (Call :EchoColor "%optE%"  %ContrastColor%)  Else (<NUL Set/P="%optE%")) & Echo %Visio%.
<NUL Set/P=[G] Apply Recommended Configuration. [F] & (If "%optF%"=="%on%" (Call :EchoColor "%optF%"  %ContrastColor%)  Else (<NUL Set/P="%optF%")) & Echo Remove %ProductID%.          
Echo [Y] Apply (Yes) to All Options.      [N] Apply (No) to All Options.
Echo [M] Submit and Deploy.               [R] Remove All Visio and Project.    
Echo [0] Go to the previous Menu.         [X] Remove All Office-Visio-Project.
CHOICE /c 123456789ABCDEFGVPUILTYNMRX0 /n /m "-------------------- (^_^) Your Wishes Come True (^_^) --------------------"
 If %ErrorLevel%==1 (If "%opt1%"=="%on%" (Set "opt1=%off%") Else (Set "opt1=%on%")) & Goto AVL.7.D.InstallOfficeMENU
 If %ErrorLevel%==2 (If "%opt2%"=="%on%" (Set "opt2=%off%") Else (Set "opt2=%on%")) & Goto AVL.7.D.InstallOfficeMENU
 If %ErrorLevel%==3 (If "%opt3%"=="%on%" (Set "opt3=%off%") Else (Set "opt3=%on%")) & Goto AVL.7.D.InstallOfficeMENU
 If %ErrorLevel%==4 (If "%opt4%"=="%on%" (Set "opt4=%off%") Else (Set "opt4=%on%")) & Goto AVL.7.D.InstallOfficeMENU
 If %ErrorLevel%==5 (If "%opt5%"=="%on%" (Set "opt5=%off%") Else (Set "opt5=%on%")) & Goto AVL.7.D.InstallOfficeMENU
 If %ErrorLevel%==6 (If "%opt6%"=="%on%" (Set "opt6=%off%") Else (Set "opt6=%on%")) & Goto AVL.7.D.InstallOfficeMENU
 If %ErrorLevel%==7 (If "%opt7%"=="%on%" (Set "opt7=%off%") Else (Set "opt7=%on%")) & Goto AVL.7.D.InstallOfficeMENU
 If %ErrorLevel%==8 (If "%opt8%"=="%on%" (Set "opt8=%off%") Else (Set "opt8=%on%")) & Goto AVL.7.D.InstallOfficeMENU
 If %ErrorLevel%==9 (If "%opt9%"=="%on%" (Set "opt9=%off%") Else (Set "opt9=%on%")) & Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel%==10 (If "%optA%"=="%on%" (Set "optA=%off%") Else (Set "optA=%on%")) & Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel%==11 (If "%optB%"=="%on%" (Set "optB=%off%") Else (Set "optB=%on%")) & Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel%==12 (If "%optC%"=="%on%" (Set "optC=%off%") Else (Set "optC=%on%")) & Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel%==13 (If "%optD%"=="%on%" (Set "optD=%off%") Else (Set "optD=%on%")) & Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel%==14 (If "%optE%"=="%on%" (Set "optE=%off%") Else (Set "optE=%on%")) & Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel%==15 (If "%optF%"=="%on%" (Set "optF=%off%") Else (Set "optF=%on%")) & Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel%==16 Goto AVL.7.D.G
If %ErrorLevel%==17 Goto AVL.7.D.V
If %ErrorLevel%==18 Goto AVL.7.D.P
If %ErrorLevel%==19 Goto AVL.7.D.U
If %ErrorLevel%==20 Goto AVL.7.D.I
If %ErrorLevel%==21 Goto AVL.7.D.L
If %ErrorLevel%==22 Goto AVL.7.D.T 
If %ErrorLevel%==23 Goto AVL.7.D.Y
If %ErrorLevel%==24 Goto AVL.7.D.N
If %ErrorLevel%==25 Goto AVL.7.D.M
If %ErrorLevel%==26 Goto AVL.7.D.R
If %ErrorLevel%==27 Goto AVL.7.D.X
If %ErrorLevel%==28 Goto AVL.7.D.0

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.G
For /L %%i in (1,1,3) do Set opt%%i=%on%
For /L %%i in (4,1,9) do Set opt%%i=%off%
For %%L in (A B C D E F) do Set opt%%L=%off%
Set "optL=%LanguageID%"
Set "optT=Install_Online"
Set "optV=2024"
Set "optP=ProPlus2024Retail"
Set "Project=ProjectPro2024Retail"
Set "Visio=VisioPro2024Retail"
Set "optU=Current"
If "%Architecture%"=="64-bit" (
	Set "optI=64-bit"
	Set "OfficeClientEdition=64"
)
If "%Architecture%"=="32-bit" (
	Set "optI=32-bit"
	Set "OfficeClientEdition=32"
)
GoTo AVL.7.D.InstallOfficeMENU

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.X
CHOICE /c 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ /n /m "--- Remove All Office, Vision, Project Editions Immediately. Are you sure (Y For Yes, N For No) ? "
If %ErrorLevel% NEQ 35 Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel% EQU 35 Echo ----- Removing All
 >%OCS% Echo ^<Configuration^>
>>%OCS% Echo   ^<Remove All="true" /^>
>>%OCS% Echo ^</Configuration^>
Start "" /B "!ODTpath!" /configure "%OCS%"
Pause
GoTo AVL.7.D.InstallOfficeMENU

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.R
CHOICE /c 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ /n /m "--- Remove All Vision and Project Editions Immediately. Are you sure (Y For Yes, N For No) ? "
If %ErrorLevel% NEQ 35 Goto AVL.7.D.InstallOfficeMENU
If %ErrorLevel% EQU 35 Echo ----- Removing Visio and Project
 >%OCS% Echo ^<Configuration^>
>>%OCS% Echo   ^<Remove All="false"^>
>>%OCS% Echo     ^<Product ID="VisioProRetail" /^>
>>%OCS% Echo     ^<Product ID="VisioStdRetail" /^>
>>%OCS% Echo     ^<Product ID="VisioPro2024Retail" /^>
>>%OCS% Echo     ^<Product ID="VisioStd2024Retail" /^>
>>%OCS% Echo     ^<Product ID="VisioPro2019Retail" /^>
>>%OCS% Echo     ^<Product ID="VisioStd2019Retail" /^>
>>%OCS% Echo     ^<Product ID="VisioPro2016Retail" /^>
>>%OCS% Echo     ^<Product ID="VisioStd2016Retail" /^>
>>%OCS% Echo     ^<Product ID="ProjectProRetail" /^>
>>%OCS% Echo     ^<Product ID="ProjectStdRetail" /^>
>>%OCS% Echo     ^<Product ID="ProjectPro2024Retail" /^>
>>%OCS% Echo     ^<Product ID="ProjectStd2024Retail" /^>
>>%OCS% Echo     ^<Product ID="ProjectPro2019Retail" /^>
>>%OCS% Echo     ^<Product ID="ProjectStd2019Retail" /^>
>>%OCS% Echo     ^<Product ID="ProjectPro2016Retail" /^>
>>%OCS% Echo     ^<Product ID="ProjectStd2016Retail" /^>
>>%OCS% Echo     ^<Product ID="VisioPro2016Volume" /^>
>>%OCS% Echo     ^<Product ID="VisioStd2016Volume" /^>
>>%OCS% Echo     ^<Product ID="VisioPro2019Volume" /^>
>>%OCS% Echo     ^<Product ID="VisioStd2019Volume" /^>
>>%OCS% Echo     ^<Product ID="VisioPro2021Volume" /^>
>>%OCS% Echo     ^<Product ID="VisioStd2021Volume" /^>
>>%OCS% Echo     ^<Product ID="VisioPro2024Volume" /^>
>>%OCS% Echo     ^<Product ID="VisioStd2024Volume" /^>
>>%OCS% Echo     ^<Product ID="ProjectPro2016Volume" /^>
>>%OCS% Echo     ^<Product ID="ProjectStd2016Volume" /^>
>>%OCS% Echo     ^<Product ID="ProjectPro2019Volume" /^>
>>%OCS% Echo     ^<Product ID="ProjectStd2019Volume" /^>
>>%OCS% Echo     ^<Product ID="ProjectPro2021Volume" /^>
>>%OCS% Echo     ^<Product ID="ProjectStd2021Volume" /^>
>>%OCS% Echo     ^<Product ID="ProjectPro2024Volume" /^>
>>%OCS% Echo     ^<Product ID="ProjectStd2024Volume" /^>
>>%OCS% Echo   ^</Remove^>
>>%OCS% Echo ^</Configuration^>
Start "" /B "!ODTpath!" /configure "%OCS%"
Pause
Goto AVL.7.D.InstallOfficeMENU

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:EchoColor (Text, Color)
  MkDir "%Temp%\_%1" 1>NUL
  PushD "%Temp%\_%1"
  For /F %%a in ('Echo PROMPT $H ^| "CMD"') do Set "bs=%%a"
  <NUL Set /P="_" >"%1"
  FindStr /l /i /b /p /a:%2 /s /c:"_" "%1"
  <NUL Set /P=%bs%%bs%
  PushD "%~dp0"
  RmDir /s /q "%Temp%\_%1"
GoTo :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.V
If "%optV%"=="365" (
	Set "optV=2024"
	Set "optP=ProPlus2024Volume"
	Set "optU=PerpetualVL2024"
	Set "Project=ProjectPro2024Volume"
	Set "Visio=VisioPro2024Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optV%"=="2024" (
	Set "optV=2021"
	Set "optP=ProPlus2021Volume"
	Set "optU=PerpetualVL2021"
	Set "Project=ProjectPro2021Volume"
	Set "Visio=VisioPro2021Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optV%"=="2021" (
	Set "optV=2019"
	Set "optP=ProPlus2019Volume"
	Set "optU=PerpetualVL2019"
	Set "Project=ProjectPro2019Volume"
	Set "Visio=VisioPro2019Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optV%"=="2019" (
	Set "optV=2016"
	Set "optP=ProPlusRetail"
	Set "optU=Current"
	Set "Project=ProjectProRetail"
	Set "Visio=VisioProRetail"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optV%"=="2016" (
	Set "optV=365"
	Set "optP=O365ProPlusRetail"
	Set "optU=Current"
	Set "Project=ProjectPro2024Retail"
	Set "Visio=VisioPro2024Retail"
	GoTo AVL.7.D.InstallOfficeMENU
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.P
If "%optP%"=="O365ProPlusRetail" (
	Set "optP=O365BusinessRetail"
	Set "optU=Current"
	Set "Project=ProjectPro2024Retail"
	Set "Visio=VisioPro2024Retail"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="O365BusinessRetail" (
	Set "optP=O365ProPlusRetail"
	Set "optU=Current"
	Set "Project=ProjectPro2024Retail"
	Set "Visio=VisioPro2024Retail"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="ProPlus2024Volume" (
	Set "optP=ProPlus2024Retail"
	Set "optU=Current"
	Set "Project=ProjectPro2024Retail"
	Set "Visio=VisioPro2024Retail"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="ProPlus2024Retail" (
	Set "optP=Standard2024Volume"
	Set "optU=PerpetualVL2024"
	Set "Project=ProjectPro2024Volume"
	Set "Visio=VisioPro2024Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="Standard2024Volume" (
	Set "optP=ProPlus2024Volume"
	Set "optU=PerpetualVL2024"
	Set "Project=ProjectPro2024Volume"
	Set "Visio=VisioPro2024Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="ProPlus2021Volume" (
	Set "optP=ProPlus2021Retail"
	Set "optU=Current"
	Set "Project=ProjectPro2021Retail"
	Set "Visio=VisioPro2021Retail"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="ProPlus2021Retail" (
	Set "optP=Standard2021Volume"
	Set "optU=PerpetualVL2021"
	Set "Project=ProjectPro2021Volume"
	Set "Visio=VisioPro2021Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="Standard2021Volume" (
	Set "optP=Standard2021Retail"
	Set "optU=Current"
	Set "Project=ProjectPro2021Retail"
	Set "Visio=VisioPro2021Retail"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="Standard2021Retail" (
	Set "optP=ProPlus2021Volume"
	Set "optU=PerpetualVL2021"
	Set "Project=ProjectPro2021Volume"
	Set "Visio=VisioPro2021Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="ProPlus2019Volume" (
	Set "optP=ProPlus2019Retail"
	Set "optU=Current"
	Set "Project=ProjectPro2019Retail"
	Set "Visio=VisioPro2019Retail"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="ProPlus2019Retail" (
	Set "optP=Standard2019Volume"
	Set "optU=PerpetualVL2019"
	Set "Project=ProjectPro2019Volume"
	Set "Visio=VisioPro2019Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="Standard2019Volume" (
	Set "optP=Standard2019Retail"
	Set "optU=Current"
	Set "Project=ProjectPro2019Retail"
	Set "Visio=VisioPro2019Retail"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optP%"=="Standard2019Retail" (
	Set "optP=ProPlus2019Volume"
	Set "optU=PerpetualVL2019"
	Set "Project=ProjectPro2019Volume"
	Set "Visio=VisioPro2019Volume"
	GoTo AVL.7.D.InstallOfficeMENU
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.U
If "%optU%"=="Current" (
	Set "optU=BetaChannel"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optU%"=="BetaChannel" (
	Set "optU=Current"
	GoTo AVL.7.D.InstallOfficeMENU
)

:AVL.7.D.I
If "%optI%"=="64-bit" (
	Set "optI=32-bit"
	Set "OfficeClientEdition=32"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optI%"=="32-bit" (
	Set "optI=64-bit"
	Set "OfficeClientEdition=64"
	GoTo AVL.7.D.InstallOfficeMENU
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.L
If "%optL%"=="en-US" (
	Set "optL=vi-VN"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optL%"=="vi-VN" (
	Set "optL=ru-RU"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optL%"=="ru-RU" (
	Set "optL=zh-CN"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optL%"=="zh-CN" (
	Set "optL=%LanguageID%"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optL%"=="%LanguageID%" (
	Set "optL=en-US"
	GoTo AVL.7.D.InstallOfficeMENU
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.T
If "%optT%"=="Install_Online" (
	Set "optT=Download_Install"
	GoTo AVL.7.D.InstallOfficeMENU
)
If "%optT%"=="Download_Install" (
	Set "optT=Install_Online"
	GoTo AVL.7.D.InstallOfficeMENU
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.Y
For /L %%i in (1,1,9) do Set opt%%i=%on%
For %%L in (A B C D E F) do Set opt%%L=%on%
GoTo AVL.7.D.InstallOfficeMENU

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.N
For /L %%i in (1,1,9) do Set opt%%i=%off%
For %%L in (A B C D E F) do Set opt%%L=%off%
GoTo AVL.7.D.InstallOfficeMENU

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.M
cd /d "%~dp0"
If "%opt1%-%opt2%-%opt3%-%opt4%-%opt5%-%opt6%-%opt7%-%opt8%-%opt9%-%optA%-%optB%-%optC%-%optE%"=="%off%-%off%-%off%-%off%-%off%-%off%-%off%-%off%-%off%-%off%-%off%-%off%-%off%" (
	Echo There are no options at all ...
	Pause
 	GoTo AVL.7.D.InstallOfficeMENU
)
                                     >%OCS% Echo ^<Configuration^>
If "%optT%"=="Install_Online"       >>%OCS% Echo   ^<Add OfficeClientEdition="%OfficeClientEdition%" Channel="%optU%"^>
If "%optT%"=="Download_Install"     >>%OCS% Echo   ^<Add OfficeClientEdition="%OfficeClientEdition%" Channel="%optU%" MigrateArch="TRUE" SourcePath="%~dp0"^>
                                    >>%OCS% Echo     ^<Product ID="%optP%"^>
                                    >>%OCS% Echo       ^<Language ID="%optL%" Fallback="en-US" /^>
If "%opt1%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="Word" /^>
If "%opt2%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="Excel" /^>
If "%opt3%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="PowerPoint" /^>
If "%opt4%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="Access" /^>
If "%opt5%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="Outlook" /^>
If "%opt6%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="OneNote" /^>
If "%opt7%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="Publisher" /^>
If "%opt8%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="Teams" /^>
If "%opt9%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="OneDrive" /^>
                                    >>%OCS% Echo       ^<ExcludeApp ID="Lync" /^>
                                    >>%OCS% Echo       ^<ExcludeApp ID="Groove" /^>
If "%optA%"=="%off%"                >>%OCS% Echo       ^<ExcludeApp ID="Bing" /^>
                                    >>%OCS% Echo     ^</Product^>
If "%optB%"=="%on%"                 >>%OCS% Echo     ^<Product ID="ProofingTools"^>
If "%optB%"=="%on%"                 >>%OCS% Echo       ^<Language ID="%optL%" Fallback="en-US" /^>
If "%optB%"=="%on%"                 >>%OCS% Echo     ^</Product^>
If "%optC%"=="%on%"                 >>%OCS% Echo     ^<Product ID="%Project%"^>
If "%optC%"=="%on%"                 >>%OCS% Echo       ^<Language ID="%optL%" Fallback="en-US" /^>
If "%optC%"=="%on%"                 >>%OCS% Echo     ^</Product^>
If "%optE%"=="%on%"                 >>%OCS% Echo     ^<Product ID="%Visio%"^>
If "%optE%"=="%on%"                 >>%OCS% Echo       ^<Language ID="%optL%" Fallback="en-US" /^>
If "%optE%"=="%on%"                 >>%OCS% Echo     ^</Product^>
                                    >>%OCS% Echo     ^<Product ID="LanguagePack"^>
                                    >>%OCS% Echo       ^<Language ID="%optL%" /^>
                                    >>%OCS% Echo     ^</Product^>
                                    >>%OCS% Echo   ^</Add^>
                                    >>%OCS% Echo   ^<Updates Enabled="TRUE" /^>
                                    >>%OCS% Echo   ^<Display Level="Full" AcceptEULA="TRUE" /^>
                                    >>%OCS% Echo   ^<Property Name="ForceAppShutdown" Value="TRUE" /^>
If "%optD%"=="%on%"                 >>%OCS% Echo   ^<Extend CreateShortcuts="true" /^>
If "%optF%"=="%on%"                 >>%OCS% Echo   ^<Remove All="false" /^>
If "%optF%"=="%on%"                 >>%OCS% Echo   	^<Product ID="%ProductID%" /^>
If "%optF%"=="%on%"                 >>%OCS% Echo   ^</Remove^>
                                    >>%OCS% Echo ^</Configuration^>

If "%optT%"=="Install_Online" (
	Start "" /B "!ODTpath!" /configure "%OCS%"
	Pause
	Goto AVL.7.D.InstallOfficeMENU
)
If "%optT%"=="Download_Install" (
	Start "" /B "!ODTpath!" /download "%OCS%"
	Pause
	Goto AVL.7.D.InstallOfficeMENU
)
Goto AVL.7.D.InstallOfficeMENU

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.D.0
RmDir /s /q ".\Office" 2>NUL
DEL /f ".\AVLconfig.xml" 2>NUL
Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E
Set "AVLBackMenu=AVL.7.E"
Set "FileDel="
Set "FolderDel="
For /f "tokens=*" %%A in ('Powershell -Command "If (Get-AppxPackage *Microsoft.WindowsStore*) { Echo WindowsStoreStatus=Installed } else { Echo WindowsStoreStatus=Not_Exist }"') do Set %%A
cls
Echo ------- AVL.7.E. Add Micorosoft Store -------
Echo   Windows Store Status: %WindowsStoreStatus%
Echo   [1] Add Store To LTSB 2016 Auto
Echo   [2] Add Store To LTSB 2016 Manual
Echo   [3] Add Store To LTSC 2019 Auto
Echo   [4] Add Store To LTSC 2019 Manual
Echo   [5] Add Store To LTSC 2021 Auto
Echo   [6] Add Store To LTSC 2021 Manual
Echo   [7] Add Store To LTSC 2024 Auto
Echo   [8] Add Store To LTSC 2024 Manual
Echo   [9] Remove Store from Windows 10 - 11
Echo   [A] Add Store to Windows 10 - 11
Echo   [0] Go to the previous Menu
CHOICE /c 123456789A0 /n /m "----- (^_^) Your Wishes Come True (^_^) -----"
 If %ErrorLevel%==1 Goto AVL.7.E.1 
 If %ErrorLevel%==2 Goto AVL.7.E.2
 If %ErrorLevel%==3 Goto AVL.7.E.3
 If %ErrorLevel%==4 Goto AVL.7.E.4
 If %ErrorLevel%==5 Goto AVL.7.E.5
 If %ErrorLevel%==6 Goto AVL.7.E.6
 If %ErrorLevel%==7 Goto AVL.7.E.7
 If %ErrorLevel%==8 Goto AVL.7.E.8
 If %ErrorLevel%==9 Goto AVL.7.E.9
If %ErrorLevel%==10 Goto AVL.7.E.A
If %ErrorLevel%==11 Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.1
CLS
Echo ---------- AVL.7.E.1. Add Store To LTSB 2016 Auto ----------
Set "URL=https://github.com/kkkgo/LTSB-Add-MicrosoftStore/archive/refs/tags/2016.zip"
Set "File=2016.zip"
Set "FileDel=%File%"
Set "FolderDel=LTSB"
Call :AVLDownload
Powershell -command Expand-Archive -LiteralPath "%~dp0%File%" -DestinationPath "%~dp0"
For /d %%A in (LTSB*) do @Start "" /D"%%A" "Add-Store.cmd"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.2
CLS
Echo ---------- AVL.7.E.2. Add Store To LTSB 2016 Manual ----------
Start https://github.com/kkkgo/LTSB-Add-MicrosoftStore/releases
Echo https://github.com/kkkgo/LTSB-Add-MicrosoftStore/archive/refs/tags/2016.zip|clip
Echo Download link is sent to Clipboard. Download, unzip, run Add-Store.cmd
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.3
CLS
Echo ---------- AVL.7.E.3. Add Store To LTSC 2019 Auto ----------
Set "URL=https://github.com/kkkgo/LTSC-Add-MicrosoftStore/archive/refs/tags/2019.zip"
Set "File=2019.zip"
Set "FileDel=%File%"
Set "FolderDel=LTSC"
Call :AVLDownload
Powershell -command Expand-Archive -LiteralPath "%~dp0%File%" -DestinationPath "%~dp0"
For /d %%A in (LTSC*) do @Start "" /D"%%A" "Add-Store.cmd"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.4
CLS
Echo ---------- AVL.7.E.4. Add Store To LTSC 2019 Manual ----------
Start https://github.com/kkkgo/LTSC-Add-MicrosoftStore/releases
Echo https://github.com/kkkgo/LTSC-Add-MicrosoftStore/archive/refs/tags/2019.zip|clip
Echo Download link is sent to Clipboard. Download, unzip, run Add-Store.cmd
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.5
CLS
Echo ---------- AVL.7.E.5. Add Store To LTSC 2021 Auto ----------
Set "URL=https://github.com/kr0tchet/LTSC-Add-MicrosoftStore-2021/archive/refs/heads/master.zip"
Set "File=2021.zip"
Set "FileDel=%File%"
Set "FolderDel=LTSC"
Call :AVLDownload
Powershell -command Expand-Archive -LiteralPath "%~dp0%File%" -DestinationPath "%~dp0"
For /d %%A in (LTSC*) do @Start "" /D"%%A" "Add-Store.cmd"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.6
CLS
Echo ---------- AVL.7.E.6. Add Store To LTSC 2021 Manual ----------
Start https://github.com/megakarlach/LTSC-Add-MicrosoftStore-2021
Echo https://github.com/kr0tchet/LTSC-Add-MicrosoftStore-2021/archive/refs/heads/master.zip|clip
Echo Download link is sent to Clipboard. Download, unzip, run Add-Store.cmd
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.7
CLS
Echo ---------- AVL.7.E.7. Add Store To LTSC 2024 Auto ----------
Set "URL=https://github.com/minihub/LTSC-Add-MicrosoftStore/releases/download/LTSC-Add-MicrosoftStore-24H2/LTSC-Add-MicrosoftStore-24H2.zip"
Set "File=2024.zip"
Set "FileDel=%File%"
Set "FolderDel=LTSC"
Call :AVLDownload
Powershell -command Expand-Archive -LiteralPath "%~dp0%File%" -DestinationPath "%~dp0"
For /d %%A in (LTSC*) do @Start "" /D"%%A" "Add-Store.cmd"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.8
CLS
Echo ---------- AVL.7.E.8. Add Store To LTSC 2024 Manual ----------
Start https://github.com/minihub/LTSC-Add-MicrosoftStore/releases/tag/LTSC-Add-MicrosoftStore-24H2
Echo https://github.com/minihub/LTSC-Add-MicrosoftStore/releases/download/LTSC-Add-MicrosoftStore-24H2/LTSC-Add-MicrosoftStore-24H2.zip|clip
Echo Download link is sent to Clipboard. Download, unzip, run Add-Store.cmd
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.9
CLS
Echo ---------- AVL.7.E.9. Remove Store ----------
Powershell -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsStore* | Remove-AppxPackage"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.E.A
CLS
Echo ---------- AVL.7.E.A. Add Store ----------
Powershell -ExecutionPolicy Unrestricted -Command "& {Get-AppxPackage -allusers *WindowsStore* | reset-AppxPackage}"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F
Set "AVLBackMenu=AVL.7.F"
Set "FileDel="
Set "FolderDel="
cls
Echo ---------- AVL.7.F. Visual C++ Redistributable ----------
Echo   [1] Support For Visual Studio 2015, 2017, 2019, 2022
Echo   [2] Support For Visual Studio 2013
Echo   [3] Support For Visual Studio 2012
Echo   [4] Support For Visual Studio 2010
Echo   [5] Support For Visual Studio 2008
Echo   [6] Support For Visual Studio 2005
Echo   [7] Open download link
Echo   [8] Install All Visual C++ Redistributable Versions
Echo   [9] Check Visual C++ Redistributable Status 
Echo   [0] Go to the previous Menu
CHOICE /c 1234567890 /n /m "----------- (^_^) Your Wishes Come True (^_^) -----------"
 If %ErrorLevel%==1 Goto AVL.7.F.1
 If %ErrorLevel%==2 Goto AVL.7.F.2
 If %ErrorLevel%==3 Goto AVL.7.F.3
 If %ErrorLevel%==4 Goto AVL.7.F.4
 If %ErrorLevel%==5 Goto AVL.7.F.5
 If %ErrorLevel%==6 Goto AVL.7.F.6
 If %ErrorLevel%==7 Goto AVL.7.F.7
 If %ErrorLevel%==8 Goto AVL.7.F.8
 If %ErrorLevel%==9 Goto AVL.7.F.9
If %ErrorLevel%==10 Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.1
CLS
Echo ------------ AVL.7.F.1. Support For Visual Studio 2015, 2017, 2019, 2022 ------------
Del vcredist* >nul
Set "URL=https://aka.ms/vs/17/release/vc_redist.x86.exe"
Set "File=vcredist_2022_x86.exe"
Call :AVLDownload
Set "URL=https://aka.ms/vs/17/release/vc_redist.x64.exe"
Set "File=vcredist_2022_x64.exe"
Call :AVLDownload
Start /wait vcredist_2022_x86.exe /passive /norestart
Start /wait vcredist_2022_x64.exe /passive /norestart
Set "FileDel=vcredist*"
Set "FolderDel="
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.2
CLS
Echo ------------ AVL.7.F.2. Support For Visual Studio 2013 ------------
Del vcredist* >nul
Set "URL=https://aka.ms/highdpimfc2013x86enu"
Set "File=vcredist_2013_x86.exe"
Call :AVLDownload
Set "URL=https://aka.ms/highdpimfc2013x64enu"
Set "File=vcredist_2013_x64.exe"
Call :AVLDownload
Start /wait vcredist_2013_x86.exe /passive /norestart
Start /wait vcredist_2013_x64.exe /passive /norestart
Set "FileDel=vcredist*"
Set "FolderDel="
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.3
CLS
Echo ------------ AVL.7.F.3. Support For Visual Studio 2012 ------------
Del vcredist* >nul
Set "URL=https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe"
Set "File=vcredist_2012_x86.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"
Set "File=vcredist_2012_x64.exe"
Call :AVLDownload
Start /wait vcredist_2012_x86.exe /passive /norestart
Start /wait vcredist_2012_x64.exe /passive /norestart
Set "FileDel=vcredist*"
Set "FolderDel="
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.4
CLS
Echo ------------ AVL.7.F.4. Support For Visual Studio 2010 ------------
Del vcredist* >nul
Set "URL=https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe"
Set "File=vcredist_2010_x86.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe"
Set "File=vcredist_2010_x64.exe"
Call :AVLDownload
Start /wait vcredist_2010_x86.exe /passive /norestart
Start /wait vcredist_2010_x64.exe /passive /norestart
Set "FileDel=vcredist*"
Set "FolderDel="
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.5
CLS
Echo ------------ AVL.7.F.5. Support For Visual Studio 2008 ------------
Del vcredist* >nul
Set "URL=https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe"
Set "File=vcredist_2008_x86.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe"
Set "File=vcredist_2008_x64.exe"
Call :AVLDownload
Start /wait vcredist_2008_x86.exe /qb
Start /wait vcredist_2008_x64.exe /qb
Set "FileDel=vcredist*"
Set "FolderDel="
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.6
CLS
Echo ------------ AVL.7.F.6. Support For Visual Studio 2005 ------------
Del vcredist* >nul
Set "URL=https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE"
Set "File=vcredist_2005_x86.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE"
Set "File=vcredist_2005_x64.exe"
Call :AVLDownload
Start /wait vcredist_2005_x86.exe /q
Start /wait vcredist_2005_x64.exe /q
Set "FileDel=vcredist*"
Set "FolderDel="
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.7
Start "" "https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170&wt.mc_id=studentamb_203301#latest-microsoft-visual-c-redistributable-version"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.8
CLS
Echo ------------ AVL.7.F.8. Install All Visual C++ Redistributable Version ------------
Call :AVL.InstallAllVisualC
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.InstallAllVisualC
Del vcredist* >nul 2>&1
Set "URL=https://aka.ms/vs/17/release/vc_redist.x86.exe"
Set "File=vcredist_2022_x86.exe"
Call :AVLDownload
Set "URL=https://aka.ms/vs/17/release/vc_redist.x64.exe"
Set "File=vcredist_2022_x64.exe"
Call :AVLDownload
Set "URL=https://aka.ms/highdpimfc2013x86enu"
Set "File=vcredist_2013_x86.exe"
Call :AVLDownload
Set "URL=https://aka.ms/highdpimfc2013x64enu"
Set "File=vcredist_2013_x64.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe"
Set "File=vcredist_2012_x86.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"
Set "File=vcredist_2012_x64.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe"
Set "File=vcredist_2010_x86.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe"
Set "File=vcredist_2010_x64.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe"
Set "File=vcredist_2008_x86.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe"
Set "File=vcredist_2008_x64.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE"
Set "File=vcredist_2005_x86.exe"
Call :AVLDownload
Set "URL=https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE"
Set "File=vcredist_2005_x64.exe"
Call :AVLDownload
If exist "vcredist_2022_x86.exe" Start /wait vcredist_2022_x86.exe /passive /norestart
If exist "vcredist_2022_x64.exe" Start /wait vcredist_2022_x64.exe /passive /norestart
If exist "vcredist_2013_x86.exe" Start /wait vcredist_2013_x86.exe /passive /norestart
If exist "vcredist_2013_x64.exe" Start /wait vcredist_2013_x64.exe /passive /norestart
If exist "vcredist_2012_x86.exe" Start /wait vcredist_2012_x86.exe /passive /norestart
If exist "vcredist_2012_x64.exe" Start /wait vcredist_2012_x64.exe /passive /norestart
If exist "vcredist_2010_x86.exe" Start /wait vcredist_2010_x86.exe /passive /norestart
If exist "vcredist_2010_x64.exe" Start /wait vcredist_2010_x64.exe /passive /norestart
If exist "vcredist_2008_x86.exe" Start /wait vcredist_2008_x86.exe /qb
If exist "vcredist_2008_x64.exe" Start /wait vcredist_2008_x64.exe /qb
If exist "vcredist_2005_x86.exe" Start /wait vcredist_2005_x86.exe /q
If exist "vcredist_2005_x64.exe" Start /wait vcredist_2005_x64.exe /q
Set "FileDel=vcredist*"
Set "FolderDel="
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.F.9
cls
Echo ------------ AVL.7.F.9. Visual C++ Redistributable Versions are installed ------------
Powershell "Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like 'Microsoft Visual C++*' } | Select-Object Name, Version | Sort Name"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.G
CLS
Echo -------------- AVL.7.G. OBS Studio --------------
Set "URL=https://github.com/obsproject/obs-studio/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=1 delims=:" %%a in ('findstr "OBS-Studio-" a.txt') do Set t1=%%a
For /f "tokens=3 delims=-" %%a in ("%t1%") do Set t2=%%a
Del a.txt
Set "URL=https://github.com/obsproject/obs-studio/releases/download/%t2%/OBS-Studio-%t2%-Windows-x64-Installer.exe"
Set "File=OBSInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo Installing OBS Studio ...
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.H
cls
Echo -------------- AVL.7.H. Office Tool (Yerong) --------------
Set "URL=https://github.com/YerongAI/Office-Tool/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Del a.txt
Set "off_x64=https://github.com/YerongAI/Office-Tool/releases/download/%t1%/Office_Tool_with_runtime_%t1%_x64.zip"
Set "off_x86=https://github.com/YerongAI/Office-Tool/releases/download/%t1%/Office_Tool_with_runtime_%t1%_x86.zip"
If exist "%windir%\SysWOW64" (Set "URL=%off_x64%") else (Set "URL=%off_x86%")
Set "File=OfficeTool.zip"
Set "FileDel=%File%"
Set "FolderDel=OfficeTool"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo Open Office Tool instructions ...
Start "" "https://docs.google.com/document/u/3/d/e/2PACX-1vRgk8OqddgTZISRHIe6irhm2fcgRDxPA8m-hc-FpOzLIhWGNYlul85ZTtJEFS5L5YrMCKCFTCzAghYC/pub"
Echo Run Office Tool Plus ...
@Start "" /D"%~dp0OfficeTool\Office Tool" "Office Tool Plus.exe"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.I
CLS
Echo -------------- AVL.7.I. Open Hash Tab --------------
Set "URL=https://github.com/namazso/OpenHashTab/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set "URL64=https://github.com/namazso/OpenHashTab/releases/download/%t1%/OpenHashTab_Machine_x64.msi"
Set "URL86=https://github.com/namazso/OpenHashTab/releases/download/%t1%/OpenHashTab_Machine_x86.msi"
If exist "%windir%\SysWOW64" (Set "URL=%URL64%") else (Set "URL=%URL86%")
Set "File=OpenHashTab.msi"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
@Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.J
Echo -------------- AVL.7.J. Open WinPE AVLboot URL --------------
Start "" "%AVLboot%"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.K
cls
Echo ----- Check TeamViewerStatus
Set "link1=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
Set "link2=HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set "findstring=TeamViewer"
Call :SoftwareStatus
Set "TeamViewerStatus=%Result%"
Echo %Result%
Echo ----- Check AnyDeskStatus
Set "link1=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
Set "link2=HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set "findstring=AnyDesk"
Call :SoftwareStatus
Set "AnyDeskStatus=%Result%"
Echo %Result%
Echo ----- Check UltraViewerStatus
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "UltraViewer" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "UltraViewer" >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "UltraViewerStatus=%Result%"
Echo %Result%
Echo ----- Check RemoteDesktopStatus
dir /s /a "%LOCALAPPDATA%\Apps\Remote Desktop" >nul 2>&1
If %ErrorLevel%==0 (Set "RemoteDesktopStatus=Installed") ELSE (Set "RemoteDesktopStatus=Not_Exist")
Echo %RemoteDesktopStatus%
::------- 
Set "AVLBackMenu=AVL.7.K"
Set "FileDel="
Set "FolderDel="
cls
Echo ---------- AVL.7.K. Remote Desktop ----------
Echo   [1] Anydesk (%AnyDeskStatus%)
Echo   [2] TeamViewer (%TeamViewerStatus%)
Echo   [3] UltraViewer (%UltraViewerStatus%)
Echo   [4] Remote Desktop 365 (%RemoteDesktopStatus%)
Echo   [0] Go to the previous Menu
CHOICE /c 12340 /n /m "----- (^_^) Your Wishes Come True (^_^) -----"
If %ErrorLevel%==1 Goto AVL.7.K.1
If %ErrorLevel%==2 Goto AVL.7.K.2
If %ErrorLevel%==3 Goto AVL.7.K.3
If %ErrorLevel%==4 Goto AVL.7.K.4
If %ErrorLevel%==5 Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.K.1
CLS
Echo -------------- AVL.7.K.1. Anydesk --------------
Set "URL=https://download.anydesk.com/AnyDesk.exe"
Set "File=Anydesk.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.K.2
CLS
Echo -------------- AVL.7.K.2. TeamViewer --------------
Set "TeamViewer64=https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe"
Set "TeamViewer86=https://download.teamviewer.com/download/TeamViewer_Setup.exe"
If exist "%windir%\SysWOW64" (Set "URL=%TeamViewer64%") ELSE (Set "URL=%TeamViewer86%")
Set "File=TeamViewerSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.K.3
CLS
Echo -------------- AVL.7.K.3. UltraViewer --------------
Set "URL=https://www.ultraviewer.net/en/download.html")
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "(Select-String -Path a.txt -Pattern 'UltraViewer_setup_\d+\.\d+_en\.exe').Matches.Value"') do (Set "ultraviewer=%%A")
del a.txt
Set "URL=https://www.ultraviewer.net/en/%ultraviewer%"
Set "File=UltraViewerSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start "" "%File%" /SILENT
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.K.4
CLS
Echo -------------- AVL.7.K.4. Remote Desktop --------------
Set "URL=https://go.microsoft.com/fwlink/?linkid=2068602"
Set "File=RemoteDesktop.msi"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.L
CLS
Echo -------------- AVL.7.L. Revo Uninstaller --------------
:: Get RevoUninstaller URL from https://www.revouninstaller.com/products/revo-uninstaller-pro/
Set "RevoLicURL=https://www.dropbox.com/scl/fi/3khhymc1frsalcqm6azkg/revouninstallerpro5.lic?rlkey=rg144o7w97bzeicdl8pl0jwj1&st=47yaptkg&dl=1"
Set "RevoUninstallerURL=https://download.revouninstaller.com/download/RevoUninProSetup.exe"
If not exist "%ProgramData%\VS Revo Group" md "%ProgramData%\VS Revo Group"
If not exist "%ProgramData%\VS Revo Group\Revo Uninstaller Pro" md "%ProgramData%\VS Revo Group\Revo Uninstaller Pro"
Set "URL=%RevoUninstallerURL%"
Set "File=RevoUninProSetup.exe"
Set "FileDel=%File%"
Call :AVLDownload
Set "URL=%RevoLicURL%"
Set "File=revouninstallerpro5.lic"
Call :AVLDownload
move /y "%~dp0revouninstallerpro5.lic" "%ProgramData%\VS Revo Group\Revo Uninstaller Pro\revouninstallerpro5.lic" 
Echo Installing Revo Uninstaller ...
Start RevoUninProSetup.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.M
CLS
Echo -------------- AVL.7.M. Rufus --------------
Echo ----- Getting the latest Version
Set "URL=https://github.com/pbatard/rufus/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set t1=%t1:~1%
Set "URL=https://github.com/pbatard/rufus/releases/download/v%t1%/rufus-%t1%p.exe"
Set "File=Rufus.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.N
cls
Echo -------------- AVL.7.N. Shortcut (Video Editor) x64 --------------
Echo ----- Getting the latest Version
Set "URL=https://github.com/mltframework/shotcut/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set t2=%t1:v=%
Set t2=%t2:.=%
Set "URL=https://github.com/mltframework/shotcut/releases/download/%t1%/shotcut-win64-%t2%.exe"
del a.txt
Set "File=ShotcutInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
AVL.7.O
cls
Echo -------------- AVL.7.O. SpotX (Blocks Ads) --------------
Echo ----- Getting the latest Version
Set "URL=https://github.com/SpotX-Official/SpotX/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set "URL=https://github.com/SpotX-Official/SpotX/releases/download/%t1%/Install_New_theme.bat"
del a.txt
Set "File=InstallSpotX.bat"
Set "FileDel=%File%"
Set "FolderDel=SmartContextMenu"
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.P
CLS
Echo -------------- AVL.7.P. Telegram --------------
If EXIST "%Windir%\SysWOW64" (Set "URL=https://telegram.org/dl/desktop/win64") ELSE (Set "URL=https://telegram.org/dl/desktop/win")
Set "File=TelegramSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Q
cls
Echo ----- Check UnikeyStatus
tasklist | findstr /i "Unikey*" >nul 2>&1
If %ErrorLevel%==0 (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "UnikeyStatus=%Result%"
Echo %Result%
Echo ----- Check GoTiengVietStatus
tasklist | findstr /i "GoTiengViet*" >nul 2>&1
If %ErrorLevel%==0 (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "GoTiengVietStatus=%Result%"
Echo %Result%
Echo ----- Check EVKeyStatus
tasklist | findstr /i "EVkey*" >nul 2>&1
If %ErrorLevel%==0 (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "EVKeyStatus=%Result%"
Echo %Result%
Echo ----- Check OpenKeyStatus
tasklist | findstr /i "OpenKey*" >nul 2>&1
If %ErrorLevel%==0 (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "OpenKeyStatus=%Result%"
Echo %Result%
::-------
Set "AVLBackMenu=AVL.7.Q"
Set "FileDel="
Set "FolderDel="
cls
Echo ---- AVL.7.Q. Vietnamese Keyboard ---
Echo   [1] EVkey (%EVKeyStatus%)
Echo   [2] GoTiengViet (%GoTiengVietStatus%)
Echo   [3] OpenKey (%OpenKeyStatus%)
Echo   [4] Unikey (%UnikeyStatus%)
Echo   [5] Set Unikey to run at startup with admin right
Echo   [0] Go to the previous Menu                          
CHOICE /c 123450 /n /m "------ (^_^) Your Wishes (^_^) ------"
If %ErrorLevel%==1 Goto AVL.7.Q.1
If %ErrorLevel%==2 Goto AVL.7.Q.2
If %ErrorLevel%==3 Goto AVL.7.Q.3
If %ErrorLevel%==4 Goto AVL.7.Q.4
If %ErrorLevel%==5 Goto AVL.7.Q.5
If %ErrorLevel%==6 Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Q.1
CLS
Echo -------------- AVL.7.Q.1. EVKey --------------
Set "URL=https://github.com/lamquangminh/EVKey/releases/download/Release/EVKey.zip"
Set "File=EVKey.zip"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Extracting EVKey.zip
If not exist "%SystemDrive%\EVKey" md "%SystemDrive%\EVKey"
If not exist "%SystemDrive%\EVKey\EVKey*.exe" (Powershell -command Expand-Archive -LiteralPath "EVKey.zip" -DestinationPath "%SystemDrive%\EVKey")
Echo ----- Run EVKey
If EXIST "%SystemDrive%\EVKey\EVKey64.exe" (Start %SystemDrive%\EVKey\EVKey64.exe) ELSE (Start %SystemDrive%\EVKey\EVKey32.exe)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Q.2
CLS
Echo -------------- AVL.7.Q.2. GoTiengViet --------------
Set "URL=https://www.trankynam.com/gotv/downloads/GoTiengViet.zip"
Set "File=GoTiengViet.zip"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Extracting %File%"
Powershell -command Expand-Archive -LiteralPath "%File%" -DestinationPath "%SystemDrive%"
Echo ----- Run GoTiengViet
Start %SystemDrive%\GoTiengViet\GoTiengViet.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Q.3
CLS
Echo -------------- AVL.7.Q.3. OpenKey --------------
Set "URL=https://github.com/tuyenvm/OpenKey/releases/download/2.0.5/OpenKey64-Windows-2.0.5-RC.zip"
Set "File=OpenKey64.zip"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload OpenKey64.exe
Echo ----- Extracting %File%
If not exist "%SystemDrive%\OpenKey" md "%SystemDrive%\OpenKey"
If not exist "%SystemDrive%\OpenKey\OpenKey64.exe" (Powershell -command Expand-Archive -LiteralPath "OpenKey64.zip" -DestinationPath "%SystemDrive%\OpenKey")
Echo ----- Run EVKey
Start %SystemDrive%\OpenKey\OpenKey64.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Q.4
CLS
Echo -------------- AVL.7.Q.4 Unikey --------------
Call :AVL.InstallUnikey
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.InstallUnikey 
Echo ----- Finding the latest version
Set "URL=https://www.unikey.org/download.html"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
If "%Processor_Architecture%" EQU "AMD64" SET "SearchPattern=unikey.*?win64\.zip"
If "%Processor_Architecture%" EQU "x86" SET "SearchPattern=unikey.*?win32\.zip"
If "%Processor_Architecture%" EQU "ARM64" SET "SearchPattern=unikey.*?arm64\.zip"
For /f "delims=" %%A in ('powershell -NoProfile -Command "$match = Select-String -Path 'v.txt' -Pattern 'https://www.unikey.org/assets/release/%SearchPattern%' | Select-Object -First 1; if ($match) { $match.Matches[0].Value }"') do set "URL=%%A"
Del v.txt
Set "File=Unikey.zip"
Set "FileDel=%File%"
Set "FolderDel="
Echo The latest version: %URL%
Echo ----- Downloading Unikey Setup
Call :AVLDownload
Echo ----- Extracting %File% 
Powershell -command "Expand-Archive -LiteralPath '%~dp0!File!"' -DestinationPath '%SystemDrive%\Unikey' -Force"
If exist "%SystemDrive%\Unikey\UniKeyNT.exe" (Del %File%)
Echo ----- Setting Unikey to run at startup.
schtasks /Delete /TN "Start UniKey as Admin" /F 2>nul
schtasks /create /tn "Start UniKey as Admin" /tr "%SystemDrive%\Unikey\UniKeyNT.exe" /sc onlogon /rl highest /f /DELAY 0000:30
powershell -Command "$task = Get-ScheduledTask -TaskName 'Start UniKey as Admin'; $task.Settings.DisallowStartIfOnBatteries = $false; $task.Settings.StopIfGoingOnBatteries = $false; Set-ScheduledTask -InputObject $task"
Echo ----- Running Unikey as Administrator
tasklist | findstr /i "Unikey*" >nul 2>&1
If %errorlevel%==0 (taskkill /im Unikey* /f >nul 2>&1)
schtasks /Run /TN "Start UniKey as Admin"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Q.5
CLS
Echo -------------- AVL.7.Q.5. Set Unikey to run at startup with admin right --------------
Echo ---- Finding UniKeyNT.exe path
Set "UnikeyPath="
set /p "UnikeyPath=> Enter the path to UniKey (or press Enter to auto-detect): "
If exist "%UnikeyPath%" Call :AVL.7.Q.5.2

For %%A in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    	If exist "%%A:\" (
		set "CurrentDrive=%%A:"
		Call :AVL.7.Q.5.1
	)
)
if "!UnikeyPath!" EQU "" (Call :AVL.Finish "UniKeyNT.exe not found")
Call :AVL.7.Q.5.2

:AVL.7.Q.5.1
For /f "delims=" %%A in ('dir /s /b "%CurrentDrive%\UniKeyNT.exe" 2^>nul') do (
	Set "UnikeyPath=%%A"
	Goto :AVL.7.Q.5.2
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Q.5.2
Echo The selected Unikey path: %UnikeyPath%
Echo ----- Setting Unikey to run at startup with Administrator right.
schtasks /Delete /TN "Start UniKey as Admin" /F 2>nul
schtasks /create /tn "Start UniKey as Admin" /tr "%UnikeyPath%" /sc onlogon /rl highest /f /DELAY 0000:30
powershell -Command "$task = Get-ScheduledTask -TaskName 'Start UniKey as Admin'; $task.Settings.DisallowStartIfOnBatteries = $false; $task.Settings.StopIfGoingOnBatteries = $false; Set-ScheduledTask -InputObject $task"
Echo ----- Running Start-UniKey-as-Admin task.
tasklist | findstr /i "Unikey*" >nul 2>&1
If %errorlevel%==0 (taskkill /im Unikey* /f >nul 2>&1)
schtasks /Run /TN "Start UniKey as Admin" 
Echo Please turn off 'Auto-run Unikey at boot time' in App
Call :AVL.Finish "" 

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.R
CLS
Echo -------------- AVL.7.R Ventoy --------------
Echo ----- Getting the latest Version of Ventoy
Set "URL=https://github.com/ventoy/Ventoy/releases/latest"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" v.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set t1=%t1:~1%
Del v.txt
Set "URL=https://github.com/ventoy/Ventoy/releases/download/v%t1%/ventoy-%t1%-windows.zip
Set "File=ventoy.zip"
Set "FileDel=%File%"
Set "FolderDel=ventoy"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Running %File%
For /F %%b in ('dir /a:d /b "ventoy\ventoy*"') do (Start "" "ventoy\%%b\Ventoy2Disk.exe")
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S
Set "AVLBackMenu=AVL.7.S"
Set "FileDel="
Set "FolderDel="
cls
Echo ----------- AVL.7.S. VPN ----------
Echo   [1] CyberGhost 
Echo   [2] ExpressVPN 
Echo   [3] Hotspot Shield 
Echo   [4] IPVanish 
Echo   [5] NordVPN 
Echo   [6] PrivadoVPN 
Echo   [7] Private Internet Access 
Echo   [8] ProtonVPN 
Echo   [9] PureVPN 
Echo   [A] StrongVPN 
Echo   [B] Surfshark 
Echo   [C] TunnelBear  
Echo   [D] VeePN
Echo   [E] VyprVPN 
Echo   [F] Windscribe 
Echo   [G] ZoogVPN
Echo   [0] Go to the previous Menu                          
CHOICE /c 123456789ABCDEFG0 /n /m "----- (^_^) Your Wishes (^_^) -----"
Set /A Index=%ErrorLevel%-1
Set "List=123456789ABCDEFG0"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.7.S.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.0
Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.1
cls
Echo -------------- AVL.7.S.1. CyberGhost --------------
Set "URL=https://download.cyberghostvpn.com/windows/CyberGhostVPNSetup.exe"
Set "File=CyberGhostSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.2
cls
Echo -------------- AVL.7.S.2. ExpressVPN --------------
Set "URL=https://www.expressvpn.com/clients/windows/expressvpn_windows_12.98.0.2_release.exe"
Set "File=ExpressVpnSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.3
cls
Echo -------------- AVL.7.S.3. HotspotShield --------------
Set "URL=https://control.kochava.com/v1/cpi/click?campaign_id=kohotspot-shield-2oo5a11d43d86192b9&network_id=5798&device_id=device_id&site_id=1&aftr=%7B%22vh%22%3A%22ext53e731b0-0631-11f0-a561-1d14a8afbcd4%22%2C%22referrer%22%3A%22https%3A%2F%2Fsupport.hotspotshield.com%2F%22%2C%22af_medium%22%3A%22serp%22%2C%22af_source%22%3A%22bing%22%2C%22af_campaign%22%3A%22seo-organic%22%7D&aftr_source=%2Fapp%2Fhotspotshield&al_token=ijxX8lvA"
Set "URL=https://d26wo1m3adcxu5.cloudfront.net/HSS-773-ALTijxX8lvA.exe?ko_click_id=ko_ffeb67dd296e42348"
Set "File=ExpressVpnSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.4
cls
Echo -------------- AVL.7.S.4. IPVanish --------------
Set "URL=https://www.ipvanish.com/software/setup-prod-v2/ipvanish-setup.exe"
Set "File=ipvanishsetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.5
cls
Echo -------------- AVL.7.S.5. NordVPN --------------
Set "URL=https://downloads.nordcdn.com/apps/windows/NordVPN/latest/NordInstaller.exe"
Set "File=NordInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.6
cls
Echo -------------- AVL.7.S.6. PrivadoVPN --------------
Set "URL=https://privadovpn.com/apps/win/Setup_PrivadoVPN_latest.exe"
Set "File=PrivadoVPN.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.7
cls
Echo -------------- AVL.7.S.7. Private Internet Access --------------
Set "URL=https://installers.privateinternetaccess.com/download/pia-windows-x64-3.6.1-08339.exe"
Set "File=PIAsetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.8
cls
Echo -------------- AVL.7.S.8. Proton VPN --------------
Set "URL=https://vpn.protondownload.com/download/ProtonVPN_v3.5.3_x64.exe"
Set "File=ProtonVPN.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.9
cls
Echo -------------- AVL.7.S.9. PureVPN --------------
Set "URL=https://dzglif4kkvz04.cloudfront.net/windows-2.0/packages/production/purevpn_setup.exe"
Set "File=purevpnsetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.A
cls
Echo -------------- AVL.7.S.A. StrongVPN --------------
Set "URL=https://static.colomovers.com/win/StrongVPN-latest.exe"
Set "File=StrongVPN.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.B
cls
Echo -------------- AVL.7.S.B. Surfshark --------------
Set "URL=https://downloads.surfshark.com/windows/latest/SurfsharkSetup.exe"
Set "File=SurfsharkSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.C
cls
Echo -------------- AVL.7.S.C. TunnelBear --------------
Set "URL=https://tunnelbear.s3.amazonaws.com/downloads/pc/TunnelBear-Installer.exe"
Set "File=TunnelBear.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.D
cls
Echo -------------- AVL.7.S.D. VeePN --------------
Set "URL=https://download.veepn.com/windows/VeePNInstaller.exe"
Set "File=VeePNInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.E
cls
Echo -------------- AVL.7.S.E. VyprVPN --------------
Set "URL=https://downloads.vyprvpn.com/downloads/vyprvpn/desktop/windows/production/5.2.3.0/VyprVPN-5.2.3-installer.exe"
Set "File=VyprVPNInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.F
cls
Echo -------------- AVL.7.S.F. Windscribe --------------
Set "URL=https://windscribe.com/install/desktop/windows"
Set "File=Windscribe.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.S.G
cls
Echo -------------- AVL.7.S.G. ZoogVPN --------------
Set "URL=https://zoogvpn.com/downloads/desktop/windows/zoogvpn-v5.4.0.exe"
Set "File=zoogvpn.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.T
Set "FileDel="
Set "FolderDel="
Set "AVLBackMenu=AVL.7.T"
CLS
Echo ------- AVL.7.T. Website Browser  -------
Echo   [1] Google Chrome
Echo   [2] Mozilla Firefox
Echo   [3] Brave 
Echo   [4] Coccoc 
Echo   [5] Microsoft Edge 
Echo   [6] Opera 
Echo   [7] Portable Google Chrome
Echo   [0] Return to the previous menu
CHOICE /c 12345670 /n /m "--- (^_^) Your Wishes Come True (^_^) ---"
If %ErrorLevel%==1 Goto AVL.7.T.1
If %ErrorLevel%==2 Goto AVL.7.T.2
If %ErrorLevel%==3 Goto AVL.7.T.3
If %ErrorLevel%==4 Goto AVL.7.T.4
If %ErrorLevel%==5 Goto AVL.7.T.5
If %ErrorLevel%==6 Goto AVL.7.T.6
If %ErrorLevel%==7 Goto AVL.7.T.7
If %ErrorLevel%==8 Goto AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.T.1
CLS
Echo -------------- AVL.7.T.1 Google Chrome --------------
Set "URL=https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B933621DA-7106-97E1-9AFF-0ED1F3AFCDCF%7D%26lang%3Den%26browser%3D5%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-statsdef_1%26installdataindex%3Dempty/update2/installers/ChromeSetup.exe"
Set "File=ChromeSetup.exe"
Set "FileDel=%File%"
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.T.2
CLS
Echo -------------- AVL.7.T.2. Mozilla Firefox --------------
Set "URL32=https://download.mozilla.org/?product=firefox-latest-ssl&os=win&lang=en-US"
Set "URL64=https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US"
If /i "%PROCESSOR_ARCHITECTURE%" EQU "x86" (Set "URL=%URL32%") Else (Set "URL=%URL64%")
Set "File=FirefoxSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
%File% -ms -ma
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Firefox*.lnk" "%AllUsersProfile%\Desktop"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.T.3
CLS
Echo -------------- AVL.7.T.3. Brave Browser --------------
Set "URL=https://referrals.brave.com/latest/BraveBrowserSetup.exe"
Set "File=BraveBrowserSetup.exe"
Set "FileDel=%File%"
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Brave*.lnk" "%AllUsersProfile%\Desktop"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.T.4
CLS
Echo -------------- AVL.7.T.4. CocCoc --------------
Set "URL=https://files.coccoc.com/browser/download/vi?plat=win"
Set "File=CocCocSetup.exe"
Set "FileDel=%File%"
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.T.5
CLS
Echo -------------- AVL.7.T.5. Microsoft Edge --------------
Set "URL=https://c2rsetup.officeapps.live.com/c2r/downloadEdge.aspx?platform=Default&source=EdgeStablePage&Channel=Stable&language=en&brand=M100"
Set "File=MicrosoftEdgeSetup.exe"
Set "FileDel=%File%"
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.T.6
CLS
Echo -------------- AVL.7.T.6. Opera --------------
Set "URL=https://net.geo.opera.com/opera/stable/windows"
Set "File=OperaSetup.exe"
Set "FileDel=%File%"
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.T.7
CLS
Echo -------------- AVL.7.T.7. Portable Google Chrome with Extensions --------------
Set "URL=https://googlechromelabs.github.io/chrome-for-testing/#stable"
If exist "v.txt" Del "v.txt"
Set "File=V.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "$content = Get-Content V.txt -Raw; If ($content -match 'https://storage.googleapis.com/chrome-for-testing-public/[\d\.]+/win64/chrome-win64.zip') { $matches[0] }"') do Set "URL64=%%A"
Del V.txt
Set "URL32=!URL64:win64=win32!"
If exist "%windir%\SysWOW64" (Set "URL=!URL64!") Else (Set "URL=!URL32!")
Set "File=ChromeSetup.zip"
Set "FileDel=%File%"
Set "FolderDel="
If not exist "%File%" Call :AVLDownload
Echo ----- Extracting %File%
If not exist "%TEMP%\chrome-win*" (Powershell -command Expand-Archive -LiteralPath "%File%" -DestinationPath "%TEMP%")
Echo ----- Running %File%
If exist "%TEMP%\chrome-win*" (
	For /d %%A in ("%TEMP%\chrome-win*") do set "ChromePath=%%A"
	Start "" "!ChromePath!\chrome.exe" "https://chromewebstore.google.com/?utm_source=ext_app_menu"
)

If not exist "%PUBLIC%\Desktop\Portable Chrome.lnk" (
	powershell -Command "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('%PUBLIC%\Desktop\Portable Chrome.lnk'); $s.TargetPath = '!ChromePath!\chrome.exe'; $s.Save()" 
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.U
CLS
Echo -------------- AVL.7.U. Winget --------------
winget --version >nul 2>&1
If %ErrorLevel%==0 (
	Echo ----- Recommend some commands to install software:
	Echo winget install --id=AutoIt.AutoIt -e
	Echo winget install Google.Chrome
	Echo winget install Mozilla.Firefox
	Echo winget install Microsoft.Edge
	Echo winget install Brave.Brave
	Echo winget install Opera.Opera
	Echo winget install 7zip.7zip
	Echo winget install WinRAR.WinRAR
	Echo winget install VideoLAN.VLC
	Echo winget install Notepad++.Notepad++
	Echo winget install ShareX.ShareX
	Echo winget install qBittorrent.qBittorrent
	Echo winget install CrystalDewWorld.CrystalDiskInfo
	Echo winget install HWiNFO.HWiNFO
	Echo winget install Microsoft.PowerToys
	Echo winget install Discord.Discord
	Echo winget install Telegram.TelegramDesktop
	Echo winget install WhatsApp.WhatsApp
	Echo winget install Zoom.Zoom
	Echo winget install Skype.Skype
	Echo winget install Malwarebytes.Malwarebytes
	Echo winget install Avast.AvastFree
	Echo winget install AVG.AVG
	Echo winget install Git.Git
	Echo winget install Python.Python.3
	Echo winget install NodeJS.NodeJS
	Echo winget install Java.OpenJDK
	Echo winget install Microsoft.VisualStudioCode
	Echo winget install Docker.DockerDesktop
	Echo winget install Microsoft.WindowsTerminal
	Echo winget install VideoLAN.VLC                // VLC Media Player
	Echo winget install MPC-HC.MPC-HC               // Media Player Classic
	Echo winget install PotPlayer.PotPlayer         // PotPlayer
	Echo winget install KMPlayer.KMPlayer           // KMPlayer
	Echo winget install Kodi.Kodi                   // Kodi Media Center
	Echo winget install foobar2000.foobar2000       // Foobar2000
	Echo winget install Audacity.Audacity           // Audio Editor
	Echo winget install Spotify.Spotify             // Spotify
	Echo winget install MusicBee.MusicBee           // Music Player Manager
	Echo winget install HandBrake.HandBrake         // Video Converter
	Echo winget install OBSProject.OBSStudio        // Screen Recorder / Streaming
	Echo winget install NCHSoftware.VideoPad        // Video Editor (Free Edition)
	Echo winget install Gyan.FFmpeg                 // FFmpeg (Powerful media processing tool)
	Echo winget install Aegisub.Aegisub             // Subtitle Editor
	Echo winget install Plex.PlexMediaServer        // Media Server
	Echo winget install Netflix.Netflix             // Netflix App (If available)
	Echo Winget is already installed.
	Call :AVL.Finish ""
)
Set "URL=https://github.com/microsoft/winget-cli/releases/latest"
For /f "delims=" %%A in ('Powershell -Command "[System.Net.HttpWebRequest]::Create('%URL%').GetResponse().ResponseUri.AbsoluteUri"') do Set "URL=%%A"
For /f "tokens=7 Delims=/" %%A in ("%URL%") do Set "Version1=%%A"
For /f "delims=" %%A in ('Powershell -Command "$url='https://github.com/microsoft/winget-cli/releases/expanded_assets/%Version1%'; $html=(Invoke-WebRequest -Uri $url -UseBasicParsing).Links.href | Where-Object {$_ -match '.*\.msixbundle$'}; Echo $html"') do Set "URL=https://github.com%%A"
::Set "URL=https://github.com/microsoft/winget-cli/releases/download/%Version1%/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
Echo %url%
Set "File=DesktopAppInstaller.msixbundle"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing Winget
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.V
CLS
Echo -------------- AVL.7.V. Zalo --------------
Set "URL=https://zalo.me/download/zalo-pc?utm=90000"
For /f "delims=" %%A in ('powershell "(Invoke-WebRequest -Uri '%URL%' -MaximumRedirection 0 -ErrorAction Ignore).Headers.Location"') do Set "URL=%%A"
Set "File=ZaloSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Installing %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.X
CLS
Echo -------------- AVL.7.X. Powershell --------------
Set "URL=https://github.com/PowerShell/PowerShell/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set t1=%t1:~1%
Del a.txt
If exist "%windir%\SysWOW64" (
	Set URL=https://github.com/PowerShell/PowerShell/releases/download/v%t1%/PowerShell-%t1%-win-x64.exe
) Else (
	Set URL=https://github.com/PowerShell/PowerShell/releases/download/v%t1%/PowerShell-%t1%-win-x86.exe
)
Set "File=PowerShell_Setup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.7.Z
cls
Echo -------------- AVL.7.Z. Check Software Status --------------
Echo ----- Check HttpToolkitStatus
dir "%LOCALAPPDATA%\programs\httptoolkit" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "Toolkit">nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "Toolkit">nul 2>&1
If %ErrorLevel%==0 (Set "c3=1") ELSE (Set "c3=0")
If "%c1%%c2%%c3%" NEQ "000" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "HttpToolkitStatus=%Result%"
Echo %Result%
Echo ----- Check HWinfoStatus
Set "link1=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
Set "link2=HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set "findstring=HWiNFO"
Call :SoftwareStatus
Set "HWinfoStatus=%Result%"
Echo %Result%
Echo ----- Check OBSStudioStatus
Set "link1=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
Set "link2=HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set "findstring=OBS Studio"
Call :SoftwareStatus
Set "OBSStudioStatus=%Result%"
Echo %Result%
Echo ----- Check OpenHashTabStatus
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "OpenHashTab" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "OpenHashTab" >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "OpenHashTabStatus=%Result%"
Echo %Result%
Echo ----- Check RevoUninstallerStatus
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "Revo Uninstaller" >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
Reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "Revo Uninstaller" >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "RevoUninstallerStatus=%Result%"
Echo %Result%
Echo ----- Check TelegramStatus
If exist "%SystemDrive%\Users\%USERNAME%\AppData\Roaming\Telegram Desktop\Telegram.exe" (Set "c1=1") ELSE (Set "c1=0")
If exist "%SystemDrive%\Program Files\Telegram Desktop\Telegram.exe" (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "TelegramStatus=%Result%"
Echo %Result%
Echo ----- Check WindowsStoreStatus
For /f "tokens=*" %%A in ('Powershell -Command "If (Get-AppxPackage *Microsoft.WindowsStore*) { Echo Result=Installed } else { Echo Result=Not_Exist }"') do Set %%A
Set "WindowsStoreStatus=%Result%"
Echo %Result%
Echo ----- Check ZaloStatus
If exist "%SystemDrive%\Program Files\Zalo\Zalo.exe" (Set "c1=1") ELSE (Set "c1=0")
If exist "%SystemDrive%\Program Files (x86)\Zalo\Zalo.exe" (Set "c2=1") ELSE (Set "c2=0")
If exist "%LOCALAPPDATA%\Programs\Zalo\Zalo.exe" (Set "c3=1") ELSE (Set "c3=0")
If "%c1%%c2%%c3%" NEQ "000" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "ZaloStatus=%Result%"
Echo %Result%
Echo ----- Check WingetStatus
winget --version >nul 2>&1
If %ErrorLevel%==0 (Set "Result=Installed") Else (Set "Result=Not_Exist")
Set "WingetStatus=%Result%"
Echo %Result%
Goto :AVL.7.Menu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:SoftwareStatus
Reg query "%link1%\%findstring%" /s >nul 2>&1
If %ErrorLevel%==0 (Set "c1=1") ELSE (Set "c1=0")
Reg query "%link2%\%findstring%" /s >nul 2>&1
If %ErrorLevel%==0 (Set "c2=1") ELSE (Set "c2=0")
If "%c1%%c2%" NEQ "00" (Set "Result=Installed") Else (Set "Result=Not_Exist")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:RufusCheck
Set "RufusStatus=Not_Exist"
For /r %SystemDrive%\ %%F in (*rufus*) do (
	Set "RufusStatus=Installed"
	Goto :EoF
)
Goto :EoF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8
Set "AVLBackMenu=AVL.8"
Set "FileDel="
Set "FolderDel="
CLS
Echo ---------------- AVL.8. Automatic Process ---------------
Echo   [1] Automatic Windows installation by WinPE AVL
Echo   [2] Install WinPE ISO to Removable Disk.
Echo   [3] Install WinPE ISO to Hard Disk.
Echo   [4] Install Windows ISO to Removable Disk.
Echo   [5] Automatic Setup After Installation.
Echo   [6] Hide or Unhide a partition.
Echo   [7] Hide a Drive.
Echo   [8] Download WinPE AVLboot.
Echo   [9] Extract ISO to a Drive.
Echo   [A] Set Bootloader to a Drive.
Echo   [B] Add or Remove "Copy as path" in windows 10
Echo   [C] Create Unattend.xml 
Echo   [D] Preparation for an Automatic Windows Installation.
Echo   [E] Manage Boot Menu
Echo   [F] Manage Driver with a WIM file.
Echo   [G] Insert Driver from Folder to Windows in WinPE.
Echo   [H] Help (Automatic Windows Installation)
Echo   [I] Flash Disk Attributes Management
Echo   [0] Return to the previous Menu.
CHOICE /c 0123456789ABCDEFGHIZ /n /m "----------- (^_^) Your Wishes Come True (^_^) -----------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDEFGHIZ"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.8.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.I
cls
Echo ----- Getting Removable Disk information
Set "CheckUSB=False"
Set "IndexNumber="
For /f %%i in ('Powershell -Command "Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | Select-Object -First 1 -ExpandProperty DriveLetter"') do (
    Set "CheckUSB=True"
)
If "%CheckUSB%" EQU "False" (
	Echo No removable disk was found.
	Call :AVL.Finish ""	
)
For /f "usebackq delims=" %%i in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Select-Object -First 1 | Select-Object -ExpandProperty Number"`) do (set "TheFirstDisk=%%i")

PowerShell -NoProfile -Command "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Select-Object Number, FriendlyName, PartitionStyle, @{Name='Size(GB)';Expression={ [math]::Round($_.Size / 1GB, 2) }} | Format-Table -AutoSize"

Set /p "IndexNumber=> Please input the Disk number (press Enter to choose Disk %TheFirstDisk%): "

If "!IndexNumber!" EQU "" (Set "IndexNumber=%TheFirstDisk%")
Call :AVL_Numberic %IndexNumber%

:: Echo -----  Getting Disk information Number
Set "DiskNumberCheck=False"
For /f "delims=" %%i in ('Powershell -NoProfile -Command "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Select-Object -ExpandProperty number"') do (
	If %IndexNumber%==%%i Set "DiskNumberCheck=True"
)
If "%DiskNumberCheck%" EQU "False" ( 
	Echo Invalid input. Aborting...
	Call :AVL.Finish ""
)
:: Echo ----- Check HDD/SSD enclosure
For /f "delims=" %%A in ('Powershell -NoProfile -Command "[math]::Floor((Get-Disk -Number %IndexNumber%).Size/1MB)"') do set "DiskSize=%%A"
If %DiskSize% GTR 128000 (
	Echo The total capacity of the removable disk %IndexNumber% is %DiskSize% MB, greater than 128000 MB.
	Echo Warning: The removable disk might be an HDD/SSD enclosure.
	Call :AVL.continue
)
Echo.

:AVL.8.I.Menu
Set "AVLBackMenu=AVL.8.I.Menu"
cls
Echo ---- AVL.8.I. Flash Disk Attributes Management ----
Echo   [1] Set flash disk to readonly.
Echo   [2] Clear readonly attribute from flash disk.
Echo   [3] Display flash disk attributes.
Echo   [0] Return to the previous menu.
CHOICE /c 1230 /n /m "-------- (^_^) Your Wishes Come True (^_^) --------"
Set /A Index=%ErrorLevel%-1
Set "List=1230"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.8.I.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.I.0
Goto AVL.8

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.I.1
CLS
Echo ---- AVL.8.I.1. Set flash disk to readonly ----
powershell -Command "Set-Disk -Number 1 -IsReadOnly $true"
powershell -Command "Get-Disk -Number %IndexNumber% | Select-Object Number, FriendlyName, IsReadOnly, IsOffline, IsBoot, IsSystem, @{Name='TotalSize(GB)';Expression={[math]::Round($_.Size/1GB,2)}}, PartitionStyle"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.I.2
CLS
Echo ---- AVL.8.I.2. Clear readonly attribute from flash disk ----
powershell -Command "Set-Disk -Number 1 -IsReadOnly $false"
powershell -Command "Get-Disk -Number %IndexNumber% | Select-Object Number, FriendlyName, IsReadOnly, IsOffline, IsBoot, IsSystem, @{Name='TotalSize(GB)';Expression={[math]::Round($_.Size/1GB,2)}}, PartitionStyle"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.I.3
CLS
Echo ---- AVL.8.I.3. Display flash disk attributes ----
powershell -Command "Get-Disk -Number %IndexNumber% | Select-Object Number, FriendlyName, IsReadOnly, IsOffline, IsBoot, IsSystem, @{Name='TotalSize(GB)';Expression={[math]::Round($_.Size/1GB,2)}}, PartitionStyle"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.0
Goto AVL.MainMenu

:AVL.TurnOffBitlocker
manage-bde -status | findstr /ri /c:"Encryption Method:" | findstr /vi /c:"None" >nul && set "x=true" || set "x=false"
If "%x%" EQU "false" (
	Echo Bitlocker is OFF
	Goto :EOF
)
For /F "tokens=2" %%b in ('manage-bde -status ^| findstr /b /c:"Volume"') do (
	Echo Turn Off Bitlocker - Drive %%b
	manage-bde -off %%b 
	Echo ----------
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.1
Echo ---------- Run all processes above. Enter Y For Yes ----------
Echo ---- AVL.8.1. Automatic Windows installation by WinPE AVL ----
Echo   1. Turn off Bitlocker
Echo   2. Disable All SmartScreen settings
Echo   3. Export Network and SCSIAdapter Drivers
Echo   4. Exporting Wifi Profiles
Echo   5. Download AVL.wim
Echo   6. Create boot menu
CHOICE /c YABCDEFGHIJKLMNOPQRSTUVWXZ0123456789 /n /m "---- Run all processes above. Enter Y For Yes ----"
If %ErrorLevel% NEQ 1 Goto !AVLBackMenu! 
Echo.
Echo ----- AVL.8.1.1. Turn Off Bitlocker
Call :AVL.TurnOffBitlocker
Powershell "Get-BitLockerVolume | Select-Object VolumeType, MountPoint, CapacityGB, VolumeStatus, ProtectionStatus | Format-Table"
choice /T 5 /D Y /N > nul
Echo.
Echo ----- AVL.8.1.2. Disable All SmartScreen settings
Echo Disable All SmartScreen settings
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg.exe ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f
reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f
Echo.
Echo ----- AVL.8.1.3. Export Network and SCSIAdapter Drivers
If not exist Drivers md Drivers
Set "class=Net"
Echo Exporting Network driver
If not exist Drivers\%class% md Drivers\%class%
For /F "tokens=3" %%b in ('pnputil /enum-drivers /class "%class%" ^| findstr /b /c:"Published"') do pnputil /export-driver %%b Drivers\%class%
Set "class=SCSIAdapter"
Echo Exporting %class% driver...
If not exist Drivers\%class% md Drivers\%class%
For /F "tokens=3" %%b in ('pnputil /enum-drivers /class "%class%" ^| findstr /b /c:"Published"') do pnputil /export-driver %%b Drivers\%class%
Dir Drivers\Net
Dir Drivers\%class%
choice /T 5 /D Y /N > nul
Echo.
Echo ----- AVL.8.1.4. Exporting Wifi Profiles
(netsh wlan show interfaces | findstr /I "State.*connected" >nul) && (ping -n 1 1.1.1.1 | findstr /I "TTL=" >nul) && (Set WifiStatus=Online) || (Set WifiStatus=Offline)
If "%WifiStatus%" EQU "Online" (
	If not exist "WifiProfiles" mkdir "WifiProfiles"
	netsh wlan export profile key=clear folder=WifiProfiles
	Echo Exported to folder 'WifiProfiles'
) Else (
	Echo Wi-Fi is disconnected.
)
choice /T 5 /D Y /N > nul
Echo.
Echo ----- AVL.8.1.5. Download AVL.WIM
Set "URL=https://www.easyuefi.com/wintohdd/downloads/WinToHDD_Free.exe"
Set "File=WinToHDD_setup.exe"
Set "FileDel=%File%"
Call :AVLDownload
Start %File%
Start "" "https://glennsferryschools-my.sharepoint.com/:u:/g/personal/billgates_glennsferryschools_onmicrosoft_com/EdH1g0qXZslJpQw304L-RDEBEdFfBytRiu7laKGYc-4CmA"
Start "" "https://docs.google.com/document/u/1/d/e/2PACX-1vSQNUMSLfn-ajAaIqxspAAlIXisfZv_uYPzj6gA1_a-Io38OrC7B8VnvTDmLcWLSL94jkZDynvJWaeZ/pub"
Echo Free version off WintoHDD can install Windows Home. Pro version can install Windows Pro, Edu, Enterprise ...
Echo Download Activator to Activate WinToHDD pro. 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.DownloadTool
Echo ----- Download Tool
Set "URL=%ToolURL%"
Set "File=Tool.zip"
Set "FileDel=%File%"
Call :AVLDownload
Powershell -command Expand-Archive -LiteralPath "%File%"
Del %File%
If not exist "%~dp0Tool\7z.exe" (
	echo.
	Echo Failed to download Tool.
	Call :AVL.Finish ""
)
Echo Tool is available.
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.WarningDataLoss
Echo ----- Warning: DATA WILL BE LOST
Echo  ALL DATA ON THIS DRIVE WILL BE PERMANENTLY DESTROYED.
Echo  This action CANNOT be undone.
Set /p "confirm=> To proceed, type Y and press Enter: "
If /i "%confirm%" NEQ "Y" (
	Echo Action cancelled by user. Data is safe.
	Call :AVL.Finish ""
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckWinPEISO
Echo ----- Check ISO path
Set "ISOpath="
Set "T=0"
For %%i in ("%~dp0*.ISO") do (
	Set /a T+=1
	Set "ISOpath=%%~fi"
	Echo ISO !T! is found: "%%~fi"
	Set "ISONameArray[!T!]=%%~fi"
)
If "!ISOpath!" NEQ "" (
	Set /p ISOpath="> Please input ISO path (Press Enter to choose ISO %T%): "
) Else (
	Set /p ISOpath="> Please input ISO path: "
)
If DEFINED ISONameArray[!ISOpath!] (set ISOpath=!ISONameArray[%ISOpath%]!)
Set "ISOpath=!ISOpath:"=!"
if /i "!ISOpath:~-4!" NEQ ".ISO" (Call :AVL.Finish "Not ISO file")
If not exist "!ISOpath!" (Call :AVL.Finish "Path does not exist")
For %%A in ("!ISOpath!") Do Set "ISOsize=%%~zA"
For /F %%S IN ('Powershell -Command "[math]::Round(!ISOsize! / 1MB)"') DO SET "ISOsize=%%S"
set /a MinimumSize=ISOsize * 105 / 100
Echo.
Echo The selected ISO: "%ISOpath%"
Echo The capacity of ISO: %ISOsize% MB
Echo The minimum size for the boot partition: %MinimumSize% MB
Echo.
Call :AVL.CheckSum "!ISOpath!"
If "%CheckSumResult%" EQU "false" (Call :AVL.Continue)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.SetDiskStyle
Echo ----- Set Disk Style
Echo  [1] MBR (Boots in both UEFI and Legacy)
Echo  [2] GPT (Boot only in UEFI mode)
Echo  [0] Return to the previous menu.
CHOICE /c 120 /n /m "> Your Wishes: "
If %ErrorLevel%==1 (Set "BootPartitionStyle=MBR")
If %ErrorLevel%==2 (Set "BootPartitionStyle=GPT") 
If %ErrorLevel%==3 Goto !AVLBackMenu!
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.SetPartitionStyle
Echo ----- Set Partition Style
Echo  [1] FAT32 (Boots in both UEFI and Legacy)
Echo  [2] NTFS (Boots in Legacy mode, May boots in UEFI)
Echo  [0] Return to the previous menu.
CHOICE /c 120 /n /m "> Your Wishes: "
If %ErrorLevel%==1 (Set "PartitionStyle=FAT32")
If %ErrorLevel%==2 (Set "PartitionStyle=NTFS")
If %ErrorLevel%==3 Goto !AVLBackMenu!
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckRemovableDisk
Echo ----- Getting Removable Disk information
Set "CheckUSB=False"
Set "IndexNumber="
For /f %%i in ('Powershell -Command "Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | Select-Object -First 1 -ExpandProperty DriveLetter"') do (
    Set "CheckUSB=True"
)
If "%CheckUSB%" EQU "False" (
	Echo No removable disk was found.
	Call :AVL.Finish ""	
)
For /f "usebackq delims=" %%i in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Select-Object -First 1 | Select-Object -ExpandProperty Number"`) do (set "TheFirstDisk=%%i")

PowerShell -NoProfile -Command "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Select-Object Number, FriendlyName, PartitionStyle, @{Name='Size(GB)';Expression={ [math]::Round($_.Size / 1GB, 2) }} | Format-Table -AutoSize"

Set /p "IndexNumber=> Please input the Disk number (press Enter to choose Disk %TheFirstDisk%): "

If "!IndexNumber!" EQU "" (Set "IndexNumber=%TheFirstDisk%")
Call :AVL_Numberic %IndexNumber%

:: Echo -----  Getting Disk information Number
Set "DiskNumberCheck=False"
For /f "delims=" %%i in ('Powershell -NoProfile -Command "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Select-Object -ExpandProperty number"') do (
	If %IndexNumber%==%%i Set "DiskNumberCheck=True"
)
If "%DiskNumberCheck%" EQU "False" ( 
	Echo Invalid input. Aborting...
	Call :AVL.Finish ""
)
:: Echo ----- Check HDD/SSD enclosure
For /f "delims=" %%A in ('Powershell -NoProfile -Command "[math]::Floor((Get-Disk -Number %IndexNumber%).Size/1MB)"') do set "DiskSize=%%A"
If %DiskSize% GTR 128000 (
	Echo The total capacity of the removable disk %IndexNumber% is %DiskSize% MB, greater than 128000 MB.
	Echo Warning: The removable disk might be an HDD/SSD enclosure.
	Call :AVL.continue
)
Echo.
Call :AVL.CheckWinPEISO
Echo.
Echo ----- Check the capacity of the boot partition
Set "BootSize="
Echo The total capacity of the removable disk %IndexNumber%: %DiskSize% MB
Echo The minimum capacity required for the boot partition: %MinimumSize% MB
Set /p "BootSize=> Please input size for the boot partition in MB (press Enter to choose %MinimumSize%): "
If "!BootSize!" EQU "" (Set "BootSize=%MinimumSize%") 
Call :AVL_Numberic %BootSize%
If %DiskSize% LSS %BootSize% Set "BootSize=%DiskSize%"
If %BootSize% LSS %MinimumSize% Set "BootSize=%MinimumSize%"
If %DiskSize% LSS %MinimumSize% (
	Echo The total capacity of the Disk %IndexNumber% is not enough. Aborting...
	Call :AVL.Finish ""	
)
Echo.
Echo The selected capacity of the boot partition: %BootSize% MB
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.continue
Set /p "Ans1=> To continue, type Y and press Enter : "
If /i "%Ans1%" NEQ "y" (Call :AVL.Finish "")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.2
cls
Echo ------- AVL.8.2. Install WinPE to Removable Disk (USB flash drive) -------
Call :AVL.CheckRemovableDisk
Echo.
Call :AVL.SetDiskStyle
Echo.
Call :AVL.SetPartitionStyle
Echo.
Call :AVL.WarningDataLoss
Echo.
Echo ----- Beginning Automatic Disk Format and Partition Creation
Echo Please do not remove the Removable Disk !
(
    	Echo select disk %IndexNumber%
    	Echo clean
    	Echo convert %DiskStyle%
    	Echo create partition primary size=%BootSize%
	Echo select partition 1
    	Echo format fs=%PartitionStyle% quick label="USB_BOOT"
    	Echo assign
    	Echo active
    	Echo create partition primary
 	Echo select partition 2
   	Echo format fs=ntfs quick label="USB_DATA"
    	Echo assign
    	Echo exit
) | diskpart
PowerShell -NoProfile -Command "Get-Partition -DiskNumber %IndexNumber% | ForEach-Object { $vol = Get-Volume -Partition $_ -ErrorAction SilentlyContinue; [PSCustomObject]@{ PartitionNumber = $_.PartitionNumber; DriveLetter = $_.DriveLetter; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; FileSystem = $vol.FileSystem } } | Format-Table -AutoSize"
Echo.
If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
For /f "delims=" %%j in ('Powershell -NoProfile -Command "Get-Partition -DiskNumber %IndexNumber% | Where-Object { $_.PartitionNumber -eq 1 } | Select-Object -ExpandProperty DriveLetter"') do Set driveletter=%%j
Call :AVL.ExtractWinPEISO %driveletter%
Call :AVL.InstallBootLoader %driveletter%
Echo Installation complete.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckFlashDrive
Echo.
Echo Disk %DiskNumber% may be a USB flash drive, not an HDD/SSD.
Set /p "Answer=> To continue, type Y and press Enter : "
if /i "%Answer%" NEQ "Y" Goto !AVLBackMenu!
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.ShowPartition
:: Show partition
PowerShell -NoProfile -Command "Get-Partition -DiskNumber %DiskNumber% | ForEach-Object { $vol = Get-Volume -Partition $_ -ErrorAction SilentlyContinue; [PSCustomObject]@{ Partition_Number = $_.PartitionNumber; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; File_System = $vol.FileSystem; Drive_Letter = $_.DriveLetter} } | Format-Table -AutoSize"

:: Check Recommended Partition
Set "RecommendedPartition=1"
Set "HasOS=false"
Set "OsPartition="
For /f %%i in ('powershell -NoProfile -Command "Get-Partition -DiskNumber %DiskNumber% -ErrorAction SilentlyContinue | Where-Object { $_.IsBoot } | ForEach-Object { $_.PartitionNumber }"') do (
    	Set "HasOS=true"
    	Set "OsPartition=%%i"
)
If "%HasOS%" EQU "true" (
	Set /a RecommendedPartition=%OsPartition% + 1
) Else (
	Set "RecommendedPartition=1"
)
:: Input Recommended Partition
Set "SelectedPartition="
Echo The selected Disk Number : %DiskNumber%
Echo The recommended Partition: %RecommendedPartition%
Set /p "SelectedPartition=> Please input Partition Number (press Enter to choose Partition %RecommendedPartition%): "

If not defined SelectedPartition (
	Set "SelectedPartition=!RecommendedPartition!"
)
Call :AVL_Numberic %SelectedPartition%

Echo The selected partition: %SelectedPartition%

:: Check is OS partition
If "%SelectedPartition%" EQU "%OsPartition%" (Call :AVL.Finish "Partition %SelectedPartition% is System Drive")

:: Check partition is exist
set "PartitionExist=false"
For /f "delims=" %%i in ('powershell -NoProfile -Command "$result = [bool](Get-Partition -DiskNumber %DiskNumber% -PartitionNumber %SelectedPartition% -ErrorAction SilentlyContinue); $result.ToString().ToLower()"') do set "PartitionExist=%%i"
if "%PartitionExist%" EQU "false" (
    	Echo Error: Partition %SelectedPartition% was NOT found on Disk %DiskNumber%.
	Call :AVL.Finish ""	
)

For /f "delims=" %%i in ('powershell -NoProfile -Command "$p = Get-Partition -DiskNumber %DiskNumber% -PartitionNumber %SelectedPartition% -ErrorAction SilentlyContinue; if ($p) { [Math]::Round(($p.Size / 1MB), 0) }"') do set "SelectedPartitionSize=%%i"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL_Numberic
for /f "delims=0123456789" %%i in ("%1") do set "non_numeric=%%i"
if defined non_numeric (
	Echo Error: Not a valid number.
	Call :AVL.Finish ""
) 
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.3
cls
Echo ------- AVL.8.3. Install WinPE to Hard Disk -------
Echo -----  Getting Disk information
Set (DiskNumber=0)
Powershell -NoProfile -Command "Get-Disk | Select-Object Number, FriendlyName, @{Name='Size(GB)';Expression={[math]::Round($_.Size / 1GB, 0)}}, PartitionStyle | Format-Table"
Set /p "DiskNumber=> Please input Disk Number (press Enter to select Disk 0): "
If "%DiskNumber%"=="" (Set "DiskNumber=0")
Call :AVL_Numberic %DiskNumber%
:: Check Disk is available
Powershell -Command "if ((Get-Disk -Number %DiskNumber% -ErrorAction SilentlyContinue)) { exit 0 } else { exit 1 }"
if not %errorlevel%==0 (
	Echo Error: Disk %DiskNumber% does NOT exist!
	Call :AVL.Finish ""
)

:: Check Flash Drive 
For /f "delims=" %%A in ('Powershell -NoProfile -Command "[math]::Floor((Get-Disk -Number %DiskNumber%).Size/1MB)"') do set "DiskSize=%%A"
If %DiskSize% LSS 128000 (Call :AVL.CheckFlashDrive)
Echo.
Echo -----  Getting Partition information
:: Check Disk has partition
For /f %%G in ('Powershell -NoProfile -Command "$b=(Get-Partition -DiskNumber %DiskNumber% -ErrorAction SilentlyContinue | Get-Volume | Where-Object { -not [string]::IsNullOrWhiteSpace($_.DriveLetter) } | Measure-Object).Count -gt 0; $b.ToString().ToLower()"') do set "DiskHasPartition=%%G"
If "%DiskHasPartition%" EQU "false" (
	Echo No partitions were found on the selected disk %DiskNumber%	
	Set "SelectedPartition=Not_Available"
	Set "SelectedPartitionSize=Not_Available"
) Else (Call :AVL.ShowPartition)
Echo.
Echo ----- Download Tool
If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
Echo.
Call :AVL.CheckWinPEISO
Echo.
Echo ----- Show the Capacity of Disk, Partition
Echo The total capacity of the Selected Disk %DiskNumber%: %DiskSize% MB
Echo The total capacity of the Selected Partition %SelectedPartition%: %SelectedPartitionSize% MB
If "%DiskHasPartition%" EQU "false" (Goto AVL.8.3.3)
Echo.
Echo ----- Manage partitions %SelectedPartition% on Disk %DiskNumber%, Extract WinPE ISO, Set BootLoader
Echo   [1] Not format, Extract WinPE ISO to the Partition %SelectedPartition%, Set BootLoader
Echo   [2] Format Partition %SelectedPartition%, Extract WinPE ISO, Set BootLoader
Echo   [3] All data will be erased, Automatically manage partitions, Extract WinPE ISO, Set BootLoader
Echo   [4] Shrink Partition %SelectedPartition%, Create new partition, Extract WinPE ISO, Set BootLoader
Echo   [0] Return to the previous menu.
CHOICE /c 12340 /n /m "> Your Wishes: "
If %ErrorLevel%==1 Goto AVL.8.3.1
If %ErrorLevel%==2 Goto AVL.8.3.2
If %ErrorLevel%==3 Goto AVL.8.3.3
If %ErrorLevel%==4 Goto AVL.8.3.4
If %ErrorLevel%==5 Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.AssignDriveLetterToPartition
(
        Echo select disk %DiskNumber%
        Echo select partition %SelectedPartition%
        Echo assign
) | diskpart
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckPartitionHasDriveLetter
Echo ---- Check the Selected Partition has a Drive Letter
For /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-Partition -DiskNumber %DiskNumber% -PartitionNumber %SelectedPartition%).DriveLetter"') do set "SelectedDrive=%%i"
If not defined SelectedDrive (Call :AVL.AssignDriveLetterToPartition)
For /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-Partition -DiskNumber %DiskNumber% -PartitionNumber %SelectedPartition%).DriveLetter"') do set "SelectedDrive=%%i"
If not defined SelectedDrive (
	Echo Failed to assign a drive letter to this partition!
	Echo Installation complete.
	Call :AVL.Finish ""
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.3.1
Echo.
Echo ---- AVL.8.3.1. Not format, Extract WinPE ISO to the Partition %SelectedPartition%, Set BootLoader
Call :AVL.CheckPartitionHasDriveLetter
If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
Call :AVL.ExtractWinPEISO %SelectedDrive%
Call :AVL.InstallBootLoader %SelectedDrive%
If exist "%SelectedDrive%:\AVL_APP\APPS\icon\desktop\AVL.ico" (
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\%SelectedDrive%\DefaultIcon" /ve /d "%SelectedDrive%:\AVL_APP\APPS\icon\desktop\AVL.ico" /f
)
Echo Installation complete.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.3.2
Echo.
Echo ----- AVL.8.3.2. Format Partition %SelectedPartition%, Extract WinPE ISO, Set BootLoader
Echo.
Call :AVL.SetPartitionStyle
Echo.
Call :AVL.WarningDataLoss
Echo ----- Format %SelectedDrive%:
Echo The total capacity of the Drive %SelectedDrive% (Disk %DiskNumber%) is: %SelectedPartitionSize% MB
Format %SelectedDrive%: /FS:%PartitionStyle% /Q /V:Boot /Y
Echo.
If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
Call :AVL.ExtractWinPEISO %SelectedDrive%
Call :AVL.InstallBootLoader %SelectedDrive%
If exist "%SelectedDrive%:\AVL_APP\APPS\icon\desktop\AVL.ico" (
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\%SelectedDrive%\DefaultIcon" /ve /d "%SelectedDrive%:\AVL_APP\APPS\icon\desktop\AVL.ico" /f
)
Echo Installation complete.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.3.3
Echo.
Echo ----- AVL.8.3.3. New hard disk: All data will be erased, Automatically manage partitions, Extract WinPE ISO, Set BootLoader
Echo ----- Automatically manage partitions of Disk %DiskNumber%
::Check Check OS Disk Number
for /f "usebackq delims=" %%j in (`
  powershell -NoProfile -Command "$d=(Get-CimInstance Win32_OperatingSystem).SystemDrive.TrimEnd(':'); if((Get-Partition -DriveLetter $d).DiskNumber -eq [int]$env:DiskNumber){ 'true' } else { 'false' }"`
) do set "CheckOSDiskNumber=%%j"

If /i "%CheckOSDiskNumber%" EQU "true" (
	Echo Disk %DiskNumber% is system disk. Aborting...
	Echo Installation complete.
	Call :AVL.Finish ""
)
Echo The total capacity of the Disk %DiskNumber%: %DiskSize% MB
Echo The recommended size For the boot partition: %MinimumSize% MB
Set "BootSize="
Set /p "BootSize=> Please input the desired size for the boot partition (MB): "
If "%BootSize%"=="" (Set "BootSize=%MinimumSize%")
Call :AVL_Numberic %BootSize%
If %DiskSize% LSS %BootSize% (Set BootSize=%DiskSize%)
If %BootSize% LSS %MinimumSize% (Set BootSize=%MinimumSize%)
If %DiskSize% LSS %MinimumSize% (
	Echo The total capacity of the Disk is not enough. Aborting...
	Call :AVL.Finish ""	
)
Echo.
Echo The capacity of the selected boot partition is %BootSize%
Echo.
Call :AVL.SetDiskStyle
Echo.
Call :AVL.SetPartitionStyle
Echo.
Call :AVL.WarningDataLoss
Echo.
Echo ----- Manage Partition
(
    Echo select disk %DiskNumber%
    Echo clean
    Echo convert %DiskStyle%
    Echo create partition primary size=%BootSize%
    Echo select partition 1
    Echo format fs=%PartitionStyle% quick label="WinPE"
    Echo assign
    Echo active
    Echo create partition primary
    Echo select partition 2
    Echo format fs=ntfs quick label="DATA"
    Echo assign
    Echo exit
) | diskpart
Echo.
If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
For /f "delims=" %%j in ('Powershell -NoProfile -Command "Get-Partition -DiskNumber %DiskNumber% | Where-Object { $_.PartitionNumber -eq 1 } | Select-Object -ExpandProperty DriveLetter"') do Set driveletter=%%j
Call :AVL.ExtractWinPEISO %driveletter%
Call :AVL.InstallBootLoader %driveletter%
If exist "%driveletter%:\AVL_APP\APPS\icon\desktop\AVL.ico" (
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\%driveletter%\DefaultIcon" /ve /d "%driveletter%:\AVL_APP\APPS\icon\desktop\AVL.ico" /f
)
Echo Installation complete.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.3.4
Echo.
Echo ---- AVL.8.3.4. Shrink partition %SelectedPartition%, Create new partition, Extract WinPE ISO, Set BootLoader
Echo ---- Shrink partition %SelectedPartition%
Call :AVL.CheckPartitionHasDriveLetter
For /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-Volume -DriveLetter %SelectedDrive%).SizeRemaining"') do set "SizeRemaining=%%i"
For /f %%i in ('Powershell -NoProfile -Command "Write-Output ([math]::Round(%SizeRemaining%/1MB,0))"') do (Set "SizeRemaining=%%i")
Echo The total capacity of the Partition %SelectedPartition%: %SelectedPartitionSize% MB
Echo The remaining capacity of the Partition %SelectedPartition%: %SizeRemaining% MB
Echo The recommended size for the boot partition: %MinimumSize% MB
If %SizeRemaining% LSS %MinimumSize% (
	Echo The total capacity of the Drive is not enough. Aborting...
	Call :AVL.Finish ""	
)
Set "ShrinkSize="
Set /p "ShrinkSize=> Please input size to shrink (press Enter to choose recommended size above): "
If "%ShrinkSize%"=="" (Set "ShrinkSize=%MinimumSize%")
Call :AVL_Numberic %ShrinkSize%
If %SizeRemaining% LSS %ShrinkSize% (
	Echo The total capacity of the partition is not enough. Aborting...
	Call :AVL.Finish ""	
)
If %ShrinkSize% LSS %MinimumSize% (Set ShrinkSize=%MinimumSize%)
Echo.
Call :AVL.SetPartitionStyle
Echo.
Echo ----- Create new partition
(
        Echo select disk %DiskNumber%
        Echo select partition %SelectedPartition%
    	Echo shrink desired=%ShrinkSize%
    	Echo create partition primary
    	Echo format fs=%PartitionStyle% quick label="AVL9999"
    	Echo assign
	Echo exit
) | diskpart
set "TargetDrive="
For /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-Volume -FileSystemLabel 'AVL9999').DriveLetter"') do set "TargetDrive=%%i"
label %TargetDrive%: Boot
If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
Call :AVL.ExtractWinPEISO %TargetDrive%
Call :AVL.InstallBootLoader %TargetDrive%
Echo Installation complete.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.ExtractWinPEISO
Echo ----- Extract WinPE ISO
If exist "%ISOpath%" (
	"%~dp0Tool\7z.exe" x "%ISOpath%" -o%1:\
) ELse (
	Echo WinPE ISO is not available!
	Call :AVL.Finish ""	
)
Goto :EOF

:AVL.InstallBootLoader
Echo ----- Install GRUB4DOS to partition
If exist "%~dp0Tool\BOOTICE.exe" (
        Start "" "%~dp0Tool\BOOTICE.exe" /device=%1: /pbr /install /type=GRUB4DOS /force /quiet
	Echo Install successfully !
) ELse (
	Echo Failed to install !
	Call :AVL.Finish ""	
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.4
cls
Echo ------- AVL.8.4. Install Windows ISO to Removable Disk (USB flash drive) -------
Call :AVL.CheckRemovableDisk
Echo.
Call :AVL.WarningDataLoss
Echo.
Echo ----- Beginning Automatic Disk Format and Partition Creation
Echo Please do not remove the Removable Disk !
(
    	Echo select disk %IndexNumber%
    	Echo clean
    	Echo convert mbr
    	Echo create partition primary size=%BootSize%
	Echo select partition 1
   	Echo format fs=NTFS quick label="USB_WIN"
    	Echo assign
    	Echo active
    	Echo create partition primary
 	Echo select partition 2
   	Echo format fs=NTFS quick label="USB_DATA"
    	Echo assign
    	Echo exit
) | diskpart
PowerShell -NoProfile -Command "Get-Partition -DiskNumber %IndexNumber% | ForEach-Object { $vol = Get-Volume -Partition $_ -ErrorAction SilentlyContinue; [PSCustomObject]@{ PartitionNumber = $_.PartitionNumber; DriveLetter = $_.DriveLetter; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; FileSystem = $vol.FileSystem } } | Format-Table -AutoSize"
Echo.
If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
For /f "delims=" %%j in ('Powershell -NoProfile -Command "Get-Partition -DiskNumber %IndexNumber% | Where-Object { $_.PartitionNumber -eq 1 } | Select-Object -ExpandProperty DriveLetter"') do Set driveletter=%%j
Call :AVL.ExtractWinPEISO %driveletter%
Call :AVL.InstallBootLoader %driveletter%
Echo Installation complete.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.5
cls
Echo --------- AVL.8.5. Automatic Setup After Installation ---------
Echo    1. Turn off Bitlocker
Echo    2. Show ThisPC icon, Import Wifi Profiles
Echo    3. Set Date Format to YYYY-MM-DD 
Echo    4. Set TimeZone GMT+7
Echo    5. Classic Context Menu
Echo    6. Turn Off News And Interests 
Echo    7. Install WinRar
Echo    8. Install Unikey
Echo    9. Install Visual C++ Runtime All Versions
CHOICE /c YABCDEFGHIJKLMNOPQRSTUVWXZ0123456789 /n /m "----------- Run all processes above. Press Y For Yes ----------"
If %ErrorLevel% NEQ 1 Goto !AVLBackMenu! 

Echo ----- AVL.8.5.1. Turn off Bitlocker
Call :AVL.TurnOffBitlocker
Echo ----- AVL.8.5.2. Show ThisPC icon on Desktop
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
Echo ----- Unhide file extension
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
Echo ----- Import Wifi Profiles
If exist "Wifi" (
	For /F %%b in ('Dir /b WifiProfiles') do (netsh wlan add profile filename="WifiProfiles\%%b")
)
Echo ----- AVL.8.5.3. Set Date Format to YYYY-MM-DD
Reg add "HKEY_CURRENT_USER\Control Panel\International" /v sShortDate /t REG_SZ /d yyyy-MM-dd /f
Reg add "HKEY_CURRENT_USER\Control Panel\International" /v sShortTime /t REG_SZ /d "hh:mm tt" /f
Echo ----- AVL.8.5.4. Set TimeZone GMT+7
tzutil /s "SE Asia Standard Time"
Rem ---- Sync Time Immediately 
net Start w32time
w32tm /resync
net stop w32time
Echo ----- AVL.8.5.5. Classic Context Menu
Reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
Echo ----- AVL.8.5.6. Turn Off News And Interests
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
Reg add "HKLM\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
Echo ----- Reset Explorer
taskkill /f /im explorer.exe
Start explorer.exe
Echo ----- AVL.8.5.7. Install WinRar
Call :AVL.InstallWinRar 
choice /T 5 /D Y /N > nul
Echo.
Echo ----- AVL.8.5.8. Install Unikey
Call :AVL.InstallUnikey
choice /T 5 /D Y /N > nul
Del winrar_setup.exe
Del Unikey.zip
Echo.
Echo ----- AVL.8.5.9. Visual C++ Runtime All Versions
Call :AVL.InstallAllVisualC
Call :AVL.Finish ""	

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.6
cls
Echo ------- AVL.8.6. Hide or Unhide a partition -------
Echo -----  Getting Disk information
Set (DiskNumber=0)
Powershell -NoProfile -Command "Get-Disk | Select-Object Number, FriendlyName, @{Name='Size(GB)';Expression={[math]::Round($_.Size / 1GB, 0)}}, PartitionStyle | Format-Table"
Set /p "DiskNumber=> Please input Disk Number (press Enter to select Disk 0): "
If "%DiskNumber%"=="" (Set "DiskNumber=0")

:: Check Disk is available
Powershell -Command "if ((Get-Disk -Number %DiskNumber% -ErrorAction SilentlyContinue)) { exit 0 } else { exit 1 }"
if not %errorlevel%==0 (Call :AVL.Finish "Error: Disk %DiskNumber% does NOT exist")
Echo.
Echo -----  Getting Partition information
:: Check Disk has partition
For /f %%G in ('Powershell -NoProfile -Command "$b=(Get-Partition -DiskNumber %DiskNumber% -ErrorAction SilentlyContinue | Get-Volume | Where-Object { -not [string]::IsNullOrWhiteSpace($_.DriveLetter) } | Measure-Object).Count -gt 0; $b.ToString().ToLower()"') do set "DiskHasPartition=%%G"
If "%DiskHasPartition%" EQU "false" (Call :AVL.Finish "No partitions were found on the selected disk %DiskNumber%")

:: Show partition
PowerShell -NoProfile -Command "Get-Partition -DiskNumber %DiskNumber% | ForEach-Object { $vol = Get-Volume -Partition $_ -ErrorAction SilentlyContinue; [PSCustomObject]@{ Partition_Number = $_.PartitionNumber; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; File_System = $vol.FileSystem; Drive_Letter = $_.DriveLetter} } | Format-Table -AutoSize"

:: Check OS Partition
Set "HasOS=false"
Set "OsPartition="
For /f %%i in ('powershell -NoProfile -Command "Get-Partition -DiskNumber %DiskNumber% -ErrorAction SilentlyContinue | Where-Object { $_.IsBoot } | ForEach-Object { $_.PartitionNumber }"') do (
    	Set "HasOS=true"
    	Set "OsPartition=%%i"
)

:: Input Partition
Echo The selected Disk Number : %DiskNumber%
Set /p "SelectedPartition=> Please input Partition Number: "
If "!SelectedPartition!" EQU "" (Call :AVL.Finish "Input invalid")

:: Check is OS partition
If "%SelectedPartition%" EQU "%OsPartition%" (Call :AVL.Finish "Partition %SelectedPartition% is System Drive")

:: Check partition is exist
set "PartitionExist=false"
For /f "delims=" %%i in ('powershell -NoProfile -Command "$result = [bool](Get-Partition -DiskNumber %DiskNumber% -PartitionNumber %SelectedPartition% -ErrorAction SilentlyContinue); $result.ToString().ToLower()"') do set "PartitionExist=%%i"
if not "%PartitionExist%" EQU "true" (Call :AVL.Finish "Error: Partition #%SelectedPartition% was NOT found on Disk %DiskNumber%")
For /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-Partition -DiskNumber %DiskNumber% -PartitionNumber %SelectedPartition%).DriveLetter"') do set "SelectedDrive=%%i"
Echo.
Echo ------- AVL.8.6. Hide or Unhide a partition -------
Echo   [1]. Hide partition %SelectedPartition% (Disk %DiskNumber%)
Echo   [2]. UnHide partition %SelectedPartition% (Disk %DiskNumber%)
Echo   [0]. Return to the previous menu
CHOICE /c 120 /n /m "> Your wishes ? "
If %ErrorLevel%==1 Goto AVL.8.6.1 
If %ErrorLevel%==2 Goto AVL.8.6.2
If %ErrorLevel%==3 Goto !AVLBackMenu! 

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.6.1
Echo ------- AVL.8.6.1. Hide the partition %SelectedPartition% -------
(
	Echo select volume %SelectedDrive%
	Echo attributes volume set hidden
	Echo attributes volume set nodefaultdriveletter
	Echo remove
	Echo exit
) | diskpart
If exist "%SelectedDrive%" (Powershell -NoProfile -Command "Get-Partition -DriveLetter %SelectedDrive% | Remove-PartitionAccessPath -AccessPath '%SelectedDrive%:\'")
Call :AVL.Finish ""

:AVL.8.6.2
Echo ------- AVL.8.6.2. Unhide the partition %SelectedPartition% -------
::(
::    Echo select disk %DiskNumber%
::    Echo select partition %SelectedPartition%
::    Echo assign
::    Echo exit
::) | diskpart

Powershell -NoProfile -Command "Get-Partition -DiskNumber %DiskNumber% -PartitionNumber %SelectedPartition% | Add-PartitionAccessPath -AssignDriveLetter"

Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.7
Cls
Echo ------- AVL.8.7. Hide a Drive ------
PowerShell -NoProfile -Command "Get-Partition | ForEach-Object { $d = Get-Disk -Number $_.DiskNumber -EA SilentlyContinue; $v = Get-Volume -Partition $_ -EA SilentlyContinue; $blStatus = 'N/A'; if ($_.DriveLetter) { $blv = Get-BitLockerVolume -MountPoint ($_.DriveLetter + ':') -EA SilentlyContinue; if ($blv) { $blStatus = $blv.VolumeStatus; if ($blv.VolumeStatus -like '*InProgress') { $blStatus = \"$($blv.VolumeStatus) ($($blv.EncryptionPercentage)%%)\" } } }; [PSCustomObject]@{ Disk = $_.DiskNumber; Partition = $_.PartitionNumber; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; Style = $d.PartitionStyle; FileSystem = $v.FileSystem; BitLocker = $blStatus; Drive = $_.DriveLetter } } | Sort-Object Disk, Partition | Format-Table -AutoSize"

Set "SelectedDrive="
Set /p "SelectedDrive=> Please input Driver Letter: "
If "%SelectedDrive%"=="" Goto !AVLBackMenu!
If not exist "%SelectedDrive%:" (Call :AVL.Finish "Drive %SelectedDrive%: does not exist")
(
	Echo select volume %SelectedDrive%
	Echo remove
	Echo exit
) | diskpart
If exist "%SelectedDrive%" (Powershell -NoProfile -Command "Get-Partition -DriveLetter %SelectedDrive% | Remove-PartitionAccessPath -AccessPath '%SelectedDrive%:\'")
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.8
Start "" "%AVLboot%"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.9
cls
Echo ------- AVL.8.9. Extract ISO to a Drive -------
PowerShell -NoProfile -Command "Get-Partition | ForEach-Object { $d = Get-Disk -Number $_.DiskNumber -EA SilentlyContinue; $v = Get-Volume -Partition $_ -EA SilentlyContinue; $blStatus = 'N/A'; if ($_.DriveLetter) { $blv = Get-BitLockerVolume -MountPoint ($_.DriveLetter + ':') -EA SilentlyContinue; if ($blv) { $blStatus = $blv.VolumeStatus; if ($blv.VolumeStatus -like '*InProgress') { $blStatus = \"$($blv.VolumeStatus) ($($blv.EncryptionPercentage)%%)\" } } }; [PSCustomObject]@{ Disk = $_.DiskNumber; Partition = $_.PartitionNumber; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; Style = $d.PartitionStyle; FileSystem = $v.FileSystem; BitLocker = $blStatus; Drive = $_.DriveLetter } } | Sort-Object Disk, Partition | Format-Table -AutoSize"

Set "SelectedDrive="
Set /p "SelectedDrive=> Please input Driver Letter: "
If "%SelectedDrive%"=="" Goto !AVLBackMenu!

If not exist "%SelectedDrive%:" (Call :AVL.Finish "Drive %SelectedDrive%: does not exist")

If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
Echo.
Call :AVL.CheckWinPEISO
Call :AVL.Continue
Call :AVL.ExtractWinPEISO %SelectedDrive%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.A
cls
Echo ------- AVL.8.A. Set Bootloader to a Drive -------
PowerShell -NoProfile -Command "Get-Partition | ForEach-Object { $d = Get-Disk -Number $_.DiskNumber -EA SilentlyContinue; $v = Get-Volume -Partition $_ -EA SilentlyContinue; $blStatus = 'N/A'; if ($_.DriveLetter) { $blv = Get-BitLockerVolume -MountPoint ($_.DriveLetter + ':') -EA SilentlyContinue; if ($blv) { $blStatus = $blv.VolumeStatus; if ($blv.VolumeStatus -like '*InProgress') { $blStatus = \"$($blv.VolumeStatus) ($($blv.EncryptionPercentage)%%)\" } } }; [PSCustomObject]@{ Disk = $_.DiskNumber; Partition = $_.PartitionNumber; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; Style = $d.PartitionStyle; FileSystem = $v.FileSystem; BitLocker = $blStatus; Drive = $_.DriveLetter } } | Sort-Object Disk, Partition | Format-Table -AutoSize"
Set "SelectedDrive="
Set /p "SelectedDrive=> Please input Driver Letter: "
If "!SelectedDrive!" equ "" Goto !AVLBackMenu!
If not exist "!SelectedDrive!:" (Call :AVL.Finish "Drive !SelectedDrive! does not exist")
If not exist "%~dp0Tool\bootice.exe" (Call :AVL.DownloadTool)
Call :AVL.InstallBootLoader %SelectedDrive%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.B
Set "AVLBackMenu=AVL.8.B"
cls
Echo ----- AVL.8.B. Add or Remove "Copy as path" in windows 10 -----
Echo     [1] Add "Copy as path" to context menu in windows 10
Echo     [2] Remove "Copy as path" from context menu in windows 10
Echo     [0] Exit
CHOICE /c 120 /n /m "-------------- (^_^) Your Wishes Come True (^_^) --------------"
If %ErrorLevel% equ 1 Goto :AVL.8.B.1
If %ErrorLevel% equ 2 Goto :AVL.8.B.2
If %ErrorLevel% equ 3 Goto :AVL.8

:AVL.8.B.1
cls
Echo ----- AVL.8.B.1. Add "Copy as path" to context menu in windows 10 -----
:: For files
reg add "HKCR\*\shell\CopyAsPath" /ve /d "Copy as path" /f
reg add "HKCR\*\shell\CopyAsPath" /v Icon /d "imageres.dll,-5302" /f
reg add "HKCR\*\shell\CopyAsPath\command" /ve /d "cmd /c echo %%1| clip" /f
:: For folders
reg add "HKCR\Directory\shell\CopyAsPath" /ve /d "Copy as path" /f
reg add "HKCR\Directory\shell\CopyAsPath" /v Icon /d "imageres.dll,-5302" /f
reg add "HKCR\Directory\shell\CopyAsPath\command" /ve /d "cmd /c echo %%1| clip" /f
echo "Copy as path" has been added to right-click menu for files and folders.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.B.2
cls
Echo ----- AVL.8.B.2. Remove "Copy as path" from context menu in windows 10 -----
:: For files
reg delete "HKCR\*\shell\CopyAsPath" /f
:: For folders
reg delete "HKCR\Directory\shell\CopyAsPath" /f
echo "Copy as path" has been removed from right-click menu for files and folders.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.C
cls 
Echo ------- AVL.8.C. Create Unattend.xml (Does not work for Windows 11 version 24H2 and later version) -------
Echo ---- Ask for processor architecture
set "ProcArch=%PROCESSOR_ARCHITECTURE%"
set /p "ProcArch=> Input Processor Architecture (AMD64 or X86), press Enter for %ProcArch%: "
Echo ---- Ask for UserName (simple, no spaces)
set "UserName=PITVN"
set /p "UserName=> Input local account username, press Enter for %UserName%: "
set "CleanName="
for /l %%i in (0,1,127) do (
    set "ch=!UserName:~%%i,1!"
    if "!ch!"=="" goto BreakLoop123
    for %%A in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 0 1 2 3 4 5 6 7 8 9 _) do (
        if /i "!ch!"=="%%A" set "CleanName=!CleanName!!ch!"
    )
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:BreakLoop123
if not "!UserName!"=="!CleanName!" (set "UserName=!CleanName!")
Echo.
Echo ---- Generate unattend.xml
(
echo ^<?xml version="1.0" encoding="utf-8"?^>
echo ^<unattend xmlns="urn:schemas-microsoft-com:unattend"^>
echo     ^<settings pass="oobeSystem"^>
echo         ^<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="%ProcArch%" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"^>
echo             ^<SetupUILanguage^>
echo                 ^<UILanguage^>en-US^</UILanguage^>
echo             ^</SetupUILanguage^>
echo             ^<InputLocale^>0409:00000409^</InputLocale^>
echo             ^<SystemLocale^>en-US^</SystemLocale^>
echo             ^<UILanguage^>en-US^</UILanguage^>
echo             ^<UserLocale^>en-US^</UserLocale^>
echo.
echo             ^<OOBE^>
echo                 ^<HideEULAPage^>true^</HideEULAPage^>
echo                 ^<HideOEMRegistrationScreen^>true^</HideOEMRegistrationScreen^>
echo                 ^<HideOnlineAccountScreens^>true^</HideOnlineAccountScreens^>
echo                 ^<HideWirelessSetupInOOBE^>true^</HideWirelessSetupInOOBE^>
echo                 ^<NetworkLocation^>Home^</NetworkLocation^>
echo                 ^<ProtectYourPC^>1^</ProtectYourPC^>
echo             ^</OOBE^>
echo.
echo             ^<UserAccounts^>
echo                 ^<LocalAccounts^>
echo                     ^<LocalAccount wcm:action="add"^>
echo                         ^<Name^>%UserName%^</Name^>
echo                         ^<Group^>Administrators^</Group^>
echo                         ^<Password^>
echo                             ^<Value^>^</Value^>
echo                             ^<PlainText^>true^</PlainText^>
echo                         ^</Password^>
echo                     ^</LocalAccount^>
echo                 ^</LocalAccounts^>
echo             ^</UserAccounts^>
echo.
echo             ^<AutoLogon^>
echo                 ^<Password^>
echo                     ^<Value^>^</Value^>
echo                     ^<PlainText^>true^</PlainText^>
echo                 ^</Password^>
echo                 ^<Enabled^>true^</Enabled^>
echo                 ^<Username^>%UserName%^</Username^>
echo                 ^<LogonCount^>1^</LogonCount^>
echo             ^</AutoLogon^>
echo.
echo             ^<FirstLogonCommands^>
echo                 ^<SynchronousCommand wcm:action="add"^>
echo                     ^<Order^>1^</Order^>
echo                     ^<CommandLine^>cmd /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v SkipUserOOBE /t REG_DWORD /d 1 /f^</CommandLine^>
echo                     ^<Description^>Disable extra OOBE prompts^</Description^>
echo                 ^</SynchronousCommand^>
echo             ^</FirstLogonCommands^>
echo.
echo         ^</component^>
echo     ^</settings^>
echo ^</unattend^>
) > unattend.xml

echo.
If exist "%~dp0unattend.xml" (
	echo ----- Finished creating Unattend.xml :
	echo Location : %~dp0unattend.xml
	echo Processor: %ProcArch%
	echo Username : %UserName%
	Set "ans="
	Set /p "ans=> To open Unattend.xml, type Y and press Enter: "
) Else (
	Echo Fail to create Unattend.xml
)
If /i "!ans!" equ "y" (start notepad unattend.xml)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckSum
Echo ----- Select checksum: [1].MD5    [2].SHA1    [3].SHA256
Set "ALG="
Set /p "ALG=> Select an option (Press Enter to skip): "
If "!ALG!" EQU "" (Goto :EOF)
If "!ALG!" NEQ "1" If "!ALG!" NEQ "2" If "!ALG!" NEQ "3" (
	Echo Input invalid
	Goto :EOF
)
If "!ALG!" EQU "1" Set "ALG=MD5"
If "!ALG!" EQU "2" Set "ALG=SHA1"
If "!ALG!" EQU "3" Set "ALG=SHA256"
Set "CheckSumResult=true"
Set "SelectedCheckSum="
Set "ActualCheckSum="
Set "CheckFile=%1"
Set "CheckFile=!CheckFile:"=!"
Set /p "SelectedCheckSum=> Please input %ALG% checksum: "
If "!SelectedCheckSum!" EQU "" (Goto :EOF)
for /f %%H in ('powershell -NoProfile -Command "Get-FileHash -Path '!CheckFile!' -Algorithm %ALG% | ForEach-Object { $_.Hash.ToUpper() }"') do set "ActualCheckSum=%%H"
Echo Actual %ALG% Checksum: %ActualCheckSum%
if /I "%SelectedCheckSum%"=="%ActualCheckSum%" (
	Echo Result: %ALG% checksum matches.
) Else (
	Echo Result: %ALG% does not match. File may be corrupted, please download it again.	
	Set "CheckSumResult=false"
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.FindProEdition 
Set "Found=Not_Found"
Set "target=%1"
Set "target=%target:"=%"
for /L %%i in (1,1,%count%) do (
    	if /i "!AllName[%%i]!" EQU "%target%" (
		Set "Found=%%i"
		Call :AVL.FindProEdition.1
	)
)
Goto :EOF

:AVL.FindProEdition.1
Set "RecommendedIndex=!IndexArray[%Found%]!"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.D
CLS
Echo ------- AVL.8.D. Preparation for an Automatic Windows Installation in WinPE -------
Echo ----- Select Windows Source: [1].ISO      [2].WIM       [3].ESD       [4].SWM
Set "WinSource="
Set /p "WinSource=> Input windows source number (press Enter to choose 1): "
If "!WinSource!" EQU "" Set "WinSource=ISO"
If "!WinSource!" EQU "1" Set "WinSource=ISO"
If "!WinSource!" EQU "2" Set "WinSource=WIM"
If "!WinSource!" EQU "3" Set "WinSource=ESD"
If "!WinSource!" EQU "4" Set "WinSource=SWM"
if not "!WinSource!"=="ISO" if not "!WinSource!"=="WIM" if not "!WinSource!"=="ESD" if not "!WinSource!"=="SWM" (
	Call :AVL.Finish "Input invalid"
)
Echo.
Echo ----- Input !WinSource! path 
Set "WinSourcePath="
Set "T=0"
For %%i in ("%~dp0*.!WinSource!") do (
	Set /a T+=1
	Set "WinSourcePath=%%~fi"
	Echo !WinSource! !T! is found: "%%~fi"
	Set "WinSourceNameArray[!T!]=%%~fi"
)
If "!WinSourcePath!" NEQ "" (
	Set /p WinSourcePath="> Please input !WinSource! path (Press Enter to choose !WinSource! %T%): "
) Else (
	Set /p WinSourcePath="> Please input !WinSource! path: "
)
If DEFINED WinSourceNameArray[!WinSourcePath!] (set WinSourcePath=!WinSourceNameArray[%WinSourcePath%]!)
Set "WinSourcePath=!WinSourcePath:"=!"
if /i "!WinSourcePath:~-4!" NEQ ".!WinSource!" (Call :AVL.Finish "Not !WinSource! file")
If not exist "!WinSourcePath!" (Call :AVL.Finish "Path does not exist")
Call :AVL.GetDiskAndPartitionOfPath "!WinSourcePath!"
Set "WinSourceDisk=!DiskResult!"
Set "WinSourcePartition=!PartitionResult!"
Set "WinSourcePathNoDrive=!PathNoDriveResult!"
For %%A in ("!WinSourcePath!") do (set WinSourceSize=%%~zA)
For /F %%S IN ('Powershell -Command "[math]::Round(!WinSourceSize! / 1MB)"') DO SET "WinSourceSize=%%S"
Echo.
Echo The selected !WinSource!: "!WinSourcePath!"
Echo The capacity of !WinSource!: !WinSourceSize! MB
Echo.
Call :AVL.CheckSum "!WinSourcePath!"
If "!CheckSumResult!" EQU "false" (Call :AVL.Continue)
If "!WinSource!" EQU "ISO" (Call :AVL.CheckISO) Else (Set "WimPath=!WinSourcePath!")
Echo.
Echo ----- Select Index Number (Windows Edition)
Call :ListAllIndexImages
Call :AVL.FindProEdition "Windows 11 Pro"
If "!Found!" EQU "Not_Found" (Call :AVL.FindProEdition "Windows 10 Pro")
Set "WimIndex=!RecommendedIndex!"
If "%RecommendedIndex%"=="Not_Found" (
	Set "WimIndex=1"
)
Set /p "WimIndex=> Input index number (press Enter to choose index !WimIndex!): "

Set "found="
For %%i in (!AllIndex!) do (
    if "%%i" EQU "!WimIndex!" set "found=true"
)
If "!found!" NEQ "true" (Call :AVL.Finish "Invalid index number")
Echo The selected index number: !WimIndex! 
Echo The selected edition: !AllName[%WimIndex%]!

If "!CheckMountISO!" EQU "true" (
	Powershell -Command "Dismount-DiskImage -ImagePath '!WinSourcePath!' | Out-Null"
	If not exist "!MountDrive!" (Echo UnMounted ISO from !MountDrive!)
)

Echo.
Call :AVL.PartitionNumber
Set "Ans2="
Set /p "Ans2=> Do you accept the recommended partitions above (press Enter for accept)? "
If /i "!Ans2!" NEQ "" (
	Set /p "RecommendedDisk=> Input Disk Number: "
	Set /p "RecommendedEFIPart=> Input EFI Partition Number: "
	Set /p "RecommendedOSPart=> Input OS Partition Number: "
	Call :AVL.CheckDiskPartition
)
If "%ISODisk%%PartitionResult%" EQU "%RecommendedDisk%%RecommendedOSPart%" (
	Echo Error: File !WinSource! is in the OS partition.
	Call :AVL.Finish ""
)
Echo.
Echo ----- Automatically Format partitions in WinPE
Echo Warning: All data on EFI and OS partition will be Permanently Erased in WinPE.
Set "AutoFormat=false"
Set "Ans1="
Set /p "Ans1=> To auto-format partitions (Press Enter for Yes): "
If "!Ans1!" equ "" (Set "AutoFormat=true")
If /i "!Ans1!" equ "y" (Set "AutoFormat=true")
Echo AutoFormat=!AutoFormat!
Echo.
Echo ----- Manage driver for Windows
Set "Generation="
Set "CPUName="
For /f "delims=" %%a in ('powershell "(Get-CimInstance -ClassName Win32_Processor).Name"') do (Set "CPUName=%%a")
For /f "delims=" %%a in ('powershell -NoProfile -Command "$cpu = Get-CimInstance Win32_Processor; if ($cpu.Name -match '(\d+)(th|st|nd|rd)') { Write-Host $matches[0] } else { Write-Host 'NotAvailable' }"') do (Set "Generation=%%a")
set "GenerationNo=!Generation:~0,-2!"
for /f "delims=0123456789" %%i in ("!GenerationNo!") do set "non_numeric=%%i"
if not defined non_numeric (
	Echo CPU: !CPUName!
	If !GenerationNo! GTR 10 Echo %Generation% generation needs Intel RST VMD driver
	If !GenerationNo! LSS 11 Echo %Generation% generation may not need Intel RST VMD driver
)

Set "Drivers="
Set /p "Drivers=> Input driver path (press Enter to continue): "
Call :AVL.CheckDriverInput
Echo.
Echo ----- Manage Unattended file for Windows
Set "UnattendedFile="
Set /p "UnattendedFile=> Input Unattended File path (press Enter to continue): "
Call :AVL.CheckUnattendedFileInput
Echo.
Echo ----- Bypass Windows 11 requirements
Set "Ans9="
Set "AutoBypassWindows11=false"
Set /p "Ans9=> To bypass Windows 11 requirements (press Y for Yes): "
If /i "!Ans9!" equ "y" (Set "AutoBypassWindows11=true")
Echo AutoBypassWindows11=!AutoBypassWindows11!
Echo.
Echo ----- Bypass login Microsoft account
Set "Ans8="
Set "AutoBypassNRO=true"
Set /p "Ans8=> To bypass login (press Enter for Yes): "
If /i "!Ans8!" neq "y" (Set "AutoBypassNRO=false")
If /i "!Ans8!" equ "" (Set "AutoBypassNRO=true")
Echo AutoBypassNRO=!AutoBypassNRO!
Echo.
Echo ----- Automatically find other Windows OS and add to boot menu
Set "AutoOtherWindowsBootMenu=false"
Set "Ans7="
Set /p "Ans7=> To create boot menu for other Windows OS, press Y for Yes: "
If /i "!Ans7!" equ "y" (Set "AutoOtherWindowsBootMenu=true")
Echo AutoOtherWindowsBootMenu=!AutoOtherWindowsBootMenu!
Echo.	
Echo ----- Automatically add WinPE to boot menu
Set "AutoWinpeBootMenu=false"
Set "Ans7="
Set /p "Ans7=> To create WinPE boot menu, press Enter for Yes: "
If "!Ans7!" equ "" (Set "AutoWinpeBootMenu=true") Else (
	If /i "!Ans7!" equ "y" (Set "AutoWinpeBootMenu=true")
)
Echo AutoWinpeBootMenu=!AutoWinpeBootMenu!
If "!AutoWinpeBootMenu!" equ "false" (
	Set "BootWimDisk="
	Set "BootWimPartition="
	Set "BootWimPathNoDrive="
	Set "BootSdiPathNoDrive="
) ELse (
	Call :AVL.CheckWimPath
	Call :AVL.GetDiskAndPartitionOfPath "!BootWimPath!"
	Set "BootWimDisk=!DiskResult!"
	Set "BootWimPartition=!PartitionResult!"
	Set "BootWimPathNoDrive=!PathNoDriveResult!"
	Call :AVL.CheckSdiPath
)
Echo.	
Echo ----- Automatically restart WinPE after Windows installation
Set "AutoRestart=false"
Set "Ans0="
Set /p "Ans0=> To auto-restart WinPE after install windows, press Enter for Yes: "
If "!Ans0!" equ "" (Set "AutoRestart=true") Else (
	If /i "!Ans0!" equ "y" (Set "AutoRestart=true")
)
Echo AutoRestart=!AutoRestart!
Echo.	
Echo ----- Exporting Configuration
Echo   [1] AVLWindowsAuto.txt
Echo   [2] WinNTsetupAuto.txt
Echo   [3] AVLWindowsAuto.txt ^& WinNTsetupAuto.txt
Set "ExportFile=AVLWindowsAuto.txt"
Set "Ans6="
Set /p "Ans6=> Select an option (press Enter to choose 1): "
If "!Ans6!" equ "2" (Set "ExportFile=WinNTsetupAuto.txt")
(
	Echo WinSource=!WinSource!
	Echo WinSourceDisk=!WinSourceDisk!
	Echo WinSourcePartition=!WinSourcePartition!
     	Echo WinSourcePathNoDrive=!WinSourcePathNoDrive!
   	Echo WimIndex=!WimIndex!
    	Echo WimName=!AllName[%WimIndex%]!
    	Echo FirmwareType=!FirmwareType!
    	Echo RecommendedDisk=!RecommendedDisk!
    	Echo RecommendedEFIPart=!RecommendedEFIPart!
    	Echo RecommendedOSPart=!RecommendedOSPart!
    	Echo AutoFormat=!AutoFormat!
    	Echo DriversDisk=!DriversDisk!
    	Echo DriversPartition=!DriversPartition!
    	Echo DriversPathNoDrive=!DriversPathNoDrive!
    	Echo UnattendedFileDisk=!UnattendedFileDisk!
    	Echo UnattendedFilePartition=!UnattendedFilePartition!
    	Echo UnattendedFilePathNoDrive=!UnattendedFilePathNoDrive!
	Echo AutoBypassWindows11=!AutoBypassWindows11!
	Echo AutoBypassNRO=!AutoBypassNRO!
 	Echo AutoOtherWindowsBootMenu=!AutoOtherWindowsBootMenu!
   	Echo AutoWinpeBootMenu=!AutoWinpeBootMenu!
	Echo BootWimDisk=!BootWimDisk!
	Echo BootWimPartition=!BootWimPartition!
	Echo BootWimPathNoDrive=!BootWimPathNoDrive!
	Echo BootSdiPathNoDrive=!BootSdiPathNoDrive!
	Echo AutoRestart=!AutoRestart!
)>!ExportFile! 
If "!Ans6!" equ "3" (Copy /y AVLWindowsAuto.txt WinNTsetupAuto.txt)
Set "ans2="
Set /p "ans2=> To open !ExportFile!, type Y and press Enter: "
If /i "!ans2!" EQU "y" (Start notepad !ExportFile!)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckISO
Echo.
Echo ----- Mount ISO
Set "MountDrive="
Set "CheckMountISO=false"
For /f "tokens=*" %%I in ('Powershell -Command "(Get-DiskImage -ImagePath '!WinSourcePath!' | Get-Volume).DriveLetter"') do (Set "MountDrive=%%I:")

If "!MountDrive!" EQU "" (
	For /f "tokens=*" %%I in ('PowerShell -Command "$mount = Mount-DiskImage -ImagePath '!WinSourcePath!' -PassThru; $timeout = 30; $timer = [System.Diagnostics.Stopwatch]::StartNew(); do { $vol = $mount | Get-Volume; if ($vol.DriveLetter) { $vol.DriveLetter; break }; Start-Sleep 1 } while ($timer.Elapsed.TotalSeconds -lt $timeout); if (-not $vol -or -not $vol.DriveLetter) { Write-Error 'Mount timed out after $timeout seconds.'; exit 1 }"') do (set "MountDrive=%%I:")
	Set "CheckMountISO=true"
)

If not exist "%MountDrive%" (Call :AVL.Finish "Failed to mount ISO")
Echo Mounted ISO to %MountDrive%
Set "RecommendedIndex=Not_Found"
Set "WimPath="
If exist "!MountDrive!\sources\install.wim" (Set "WimPath=!MountDrive!\sources\install.wim")
If exist "!MountDrive!\sources\install.esd" (Set "WimPath=!MountDrive!\sources\install.esd")
If exist "!MountDrive!\sources\install.swm" (Set "WimPath=!MountDrive!\sources\install.swm")
If "!WimPath!" equ "" (
	Echo WIM, ESD, SWM not found in ISO.
	Call :AVL.Finish ""
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckUnattendedFileInput
If "!UnattendedFile!" EQU "" (
	Echo Unattended File is not found.
	Set "UnattendedFileDisk="
	Set "UnattendedFilePartition="
	Set "UnattendedFilePathNoDrive="
	Goto :EOF
)
Set "UnattendedFile=!UnattendedFile:"=!"
if /i "%UnattendedFile:~-4%" NEQ ".xml" (Call :AVL.Finish "Not xml file")
Echo Unattended File path is valid: "!UnattendedFile!"
Call :AVL.GetDiskAndPartitionOfPath "!UnattendedFile!"
Set "UnattendedFileDisk=!DiskResult!"
Set "UnattendedFilePartition=!PartitionResult!"
Set "UnattendedFilePathNoDrive=!PathNoDriveResult!"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckDriverInput
If "!Drivers!" EQU "" (
	Echo Driver path is not found.
	Set "DriversDisk="
	Set "DriversPartition="
	Set "DriversPathNoDrive="
	Goto :EOF
)
Set "Drivers=!Drivers:"=!"
Echo Driver path is valid: "!Drivers!"
Call :AVL.GetDiskAndPartitionOfPath "!Drivers!"
Set "DriversDisk=!DiskResult!"
Set "DriversPartition=!PartitionResult!"
Set "DriversPathNoDrive=!PathNoDriveResult!"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckWimPath
Echo ----- Check Wim path
Set "BootWimPath="
Set "T=0"
For %%i in ("%~dp0*.wim") do (
	Set /a T+=1
	Set "BootWimPath=%%~fi"
	Echo Wim !T! is found: "%%~fi"
	Set "WimNoArr[!T!]=!T!"
	Set "WimNameArr[!T!]=%%~fi"
)
If "!BootWimPath!" NEQ "" (
	Set /p BootWimPath="> Please input Wim path (Press Enter to choose Wim %T%): "
) Else (
	Set /p BootWimPath="> Please input Wim path: "
)
If DEFINED WimNameArr[%BootWimPath%] set BootWimPath=!WimNameArr[%BootWimPath%]!
Set "BootWimPath=!BootWimPath:"=!"
if /i "%BootWimPath:~-4%" NEQ ".wim" (Call :AVL.Finish "Not Wim file")
If not exist "!BootWimPath!" (Call :AVL.Finish "Input invalid")
For /f "delims=" %%i in ("!BootWimPath!") do (
	set "BootWimPathNoFile=%%~dpi"
	set "BootWimDrive=%%~di"
)
Echo The selected WIM path: "!BootWimPath!"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckSdiPath
Set "BootSdiPath="
For /f "delims=" %%a in ('dir /s /b "!BootWimDrive!\boot.sdi" 2^>nul') do Set "BootSdiPath=%%a"
If "!BootSdiPath!" NEQ "" (
	Echo The selected SDI path: "!BootSdiPath!"
	For /f "delims=" %%i in ("!BootSdiPath!") do set "BootSdiPathNoDrive=%%~pnxi"
	Goto :EOF
)

For /f "delims=" %%a in ('dir /s /b "!SystemDrive!\boot.sdi" 2^>nul') do Set "BootSdiPath=%%a"
If "!BootSdiPath!" EQU "" (Call :AVL.Finish "Boot SDI file not found")
If not exist "!BootWimPathNoFile!boot.sdi" COPY /Y "!BootSdiPath!" "!BootWimPathNoFile!boot.sdi" >nul
Set "BootSdiPath=!BootWimPathNoFile!boot.sdi"
Echo The selected SDI path: "!BootSdiPath!"
For /f "delims=" %%i in ("!BootSdiPath!") do set "BootSdiPathNoDrive=%%~pnxi"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.GetDrive
Set "GetDrive="
For /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-Partition -DiskNumber %1 -PartitionNumber %2).DriveLetter"') do set "GetDrive=%%i:"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E
Set "AVLBackMenu=AVL.8.E.MainMenu"
Reg Query "HKLM\System\CurrentControlSet\Control\MiniNT" >nul 2>&1
If %ErrorLevel% EQU 0 (
	Set "OS=WinPE"
	Call :AVL.8.E.FindEFIpartition
	Set "BCDcommand=BCDedit /store "!BcdPath!""
	!BCDcommand! /enum {fwbootmgr} >nul 2>&1 && (Set "FirmwareType=UEFI") || (Set "FirmwareType=BIOS")
) Else (
	Set "OS=Windows"
	Set "BCDcommand=BCDedit"
	BCDedit /enum {fwbootmgr} >nul 2>&1 && (Set "FirmwareType=UEFI") || (Set "FirmwareType=BIOS")
)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.MainMenu
cls
Echo --------- AVL.8.E. Manage Boot Menu ---------
Echo   Current OS: %OS%.
Echo   [1] Create boot entry for WinPE.
Echo   [2] Create boot entry for Windows.
Echo   [3] Remove all WinPE boot entries.
Echo   [4] Remove a boot entry.
Echo   [5] Set Default OS for boot menu.
Echo   [6] Change Description of boot entry.
Echo   [7] Change TimeOut for boot menu.
Echo   [8] Change BootMenuPolicy for boot entry.
Echo   [9] Change DisplayOrder for boot menu.
Echo   [B] Restart PC to BIOS.
Echo   [R] Restart PC.
Echo   [S] Shutdown.
Echo   [0] Return to the previous menu.
CHOICE /c 123456789BRS0 /n /m "---------- (^_^) Your Wishes (^_^) ----------"
If "!ErrorLevel!" equ "1" (Goto :AVL.8.E.1)
If "!ErrorLevel!" equ "2" (Goto :AVL.8.E.2)
If "!ErrorLevel!" equ "3" (Goto :AVL.8.E.3)	
If "!ErrorLevel!" equ "4" (Goto :AVL.8.E.4)	
If "!ErrorLevel!" equ "5" (Goto :AVL.8.E.5)	
If "!ErrorLevel!" equ "6" (Goto :AVL.8.E.6)	
If "!ErrorLevel!" equ "7" (Goto :AVL.8.E.7)	
If "!ErrorLevel!" equ "8" (Goto :AVL.8.E.8)	
If "!ErrorLevel!" equ "9" (Goto :AVL.8.E.9)	
If "!ErrorLevel!" equ "10" (Shutdown /r /fw /t 5 && exit)
If "!ErrorLevel!" equ "11" (Shutdown /r /t 5 && exit)
If "!ErrorLevel!" equ "12" (Shutdown /s /t 5 && exit)
If "!ErrorLevel!" equ "13" (Goto :AVL.8)	

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.1
cls
Echo ----- AVL.8.E.1. Create boot entry for WinPE -----
Echo   Current OS: %OS%
Echo   [1] Create one-time boot entry
Echo   [2] Create permanent boot entry
Echo   [0] Return to the previous menu
CHOICE /c 120 /n /m "> Your Wishes: "
If "!ErrorLevel!" equ "1" (Set "Bootstyle=OneTime")
If "!ErrorLevel!" equ "2" (Set "Bootstyle=Always")
If "!ErrorLevel!" equ "3" (Goto :AVL.8.E.MainMenu)

Call :AVL.8.E.CheckWimPathForBootMenu
echo ----- Creating ramdisk configuration
!BCDcommand! /create {ramdiskoptions} /d "Ramdisk Options" >nul
!BCDcommand! /set {ramdiskoptions} ramdisksdidevice partition=!BootWimPath:~0,2! >nul
!BCDcommand! /set {ramdiskoptions} ramdisksdipath "!BootSdiPath:~2!" >nul

echo ----- Creating WinPE boot entry
for /f "tokens=2 delims={}" %%a in ('!BCDcommand! /create /d "WinPE %Random%" /application osloader') do (
    set "GUID={%%a}"
)

echo ----- Configure the WinPE boot entry
!BCDcommand! /set %GUID% device "ramdisk=[!BootWimPath:~0,2!]!BootWimPath:~2!,{ramdiskoptions}" >nul
If "!FirmwareType!" equ "UEFI" (
	!BCDcommand! /set %GUID% path "\windows\system32\boot\winload.efi" >nul
) Else (
	!BCDcommand! /set %GUID% path "\windows\system32\winload.exe" >nul
)

echo ----- Configuring boot parameters
!BCDcommand! /set %GUID% osdevice "ramdisk=[!BootWimPath:~0,2!]!BootWimPath:~2!,{ramdiskoptions}" >nul
!BCDcommand! /set %GUID% systemroot \windows >nul
!BCDcommand! /set %GUID% winpe yes >nul
!BCDcommand! /set %GUID% detecthal yes >nul

If /i "!Bootstyle!" equ "Always" (
	Echo ----- Creating boot menu for WinPE
	!BCDcommand! /displayorder %GUID% /addlast
	!BCDcommand! /timeout 10 >nul
	!BCDcommand! /set {default} bootmenupolicy standard >nul
) Else (
	echo ----- Create One-Time Boot
	!BCDcommand! /bootsequence %GUID% /addfirst
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.2
cls
Echo ----- AVL.8.E.2. Create boot entry for Windows -----
Echo   Current OS: %OS%
Echo   [1] Create one-time boot entry
Echo   [2] Create permanent boot entry
Echo   [0] Return to the previous menu
CHOICE /c 120 /n /m "> Your Wishes: "
If "!ErrorLevel!" equ "1" (Set "Bootstyle=OneTime")
If "!ErrorLevel!" equ "2" (Set "Bootstyle=Always")
If "!ErrorLevel!" equ "3" (Goto :AVL.8.E.MainMenu)

For /f "tokens=*" %%d in ('fsutil fsinfo drives') Do (Set "DriveList=%%d")
Set "DriveList=!DriveList:Drives: =!"
Set "DriveList=!DriveList:\=!"
If "%OS%" equ "WinPE" (Set "DriveList=!DriveList:%SystemDrive% =!")
For %%d in (%DriveList%) Do (
    	If Exist "%%d\Windows\System32" (
		Set "WindowsDrive=%%d"
		Echo Windows OS was found at %%d
   	)
)
set /p "WindowsDrive=> Please input drive letter of Windows (press Enter to choose !WindowsDrive!)? "
set "WindowsDrive=!WindowsDrive:~0,1!
If not exist "!WindowsDrive!:" (
	Echo !WindowsDrive!: not exist.
	Pause
	Goto :AVL.8.E.MainMenu
)
set "WindowsDescription=Windows"
set /p "WindowsDescription=> Please input description of Windows (press Enter to choose Windows)? "
Set "GUID1="
For /f "tokens=2 delims={}" %%a in ('!BCDcommand! /create /d "!WindowsDescription!" /application osloader') do set "GUID1={%%a}"

if not defined GUID1 (
	echo Failed to create boot entry.
	Pause
	Goto :AVL.8.E.MainMenu
)
!BCDcommand! /set %GUID1% device partition=!WindowsDrive!: >nul
!BCDcommand! /set %GUID1% osdevice partition=!WindowsDrive!:  >nul
!BCDcommand! /set %GUID1% path \Windows\System32\winload.efi  >nul
!BCDcommand! /set %GUID1% systemroot \Windows >nul
!BCDcommand! /set %GUID1% description "!WindowsDescription!" >nul
If /i "!Bootstyle!" equ "Always" (
	Echo ----- Creating boot menu 
	!BCDcommand! /displayorder %GUID1% /addlast
	!BCDcommand! /timeout 10 >nul
	!BCDcommand! /set {default} bootmenupolicy standard >nul
) Else (
	echo ----- Create One-Time Boot
	!BCDcommand! /bootsequence %GUID1% /addfirst
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.3
cls
Echo ----- AVL.8.E.3. Remove all WinPE boot entries -----
Set "BootEntry=false"
For /f "delims=" %%a in ('!BCDcommand! /enum ^| findstr /i "ramdisk"') do Set "BootEntry=true"
If "!BootEntry!" equ "false" (
	Echo WinPE boot entry is not found.
	Pause
	Goto :AVL.8.E.MainMenu
)
Echo WinPE boot entry was found.
Echo.
Set "GUID2="
For /f "tokens=2" %%a in ('!BCDcommand! /enum ^| findstr /r "identifier.*{.*}"') do (
	Set "GUID2=%%a"
	Set "Desc="
	For /f "tokens=1,*" %%b in ('!BCDcommand! /enum !GUID2! 2^>nul ^| findstr /r "^description"') do (Set "Desc=%%c")
	!BCDcommand! /enum !GUID2! | findstr /i "ramdisk" >nul 2>&1
	If !errorlevel! equ 0 (echo !GUID2! - !Desc!)
)
Echo.
Set "ans1=Y"
Set /p "ans1=> To remove all WinPe boot entries (press Enter for Yes): "
If "!ans1!" equ "" (Set "ans1=y")
If /i "!ans1!" neq "y" (Goto :AVL.8.E.MainMenu)

For /f "tokens=2" %%a in ('!BCDcommand! /enum ^| findstr /r "identifier.*{.*}"') do (
    Set "GUID1=%%a"
    !BCDcommand! /enum !GUID1! | findstr /i "ramdisk" >nul 2>&1
    If !errorlevel! equ 0 (
        Echo WinPE was found at: !GUID1!
        !BCDcommand! /delete !GUID1! /f && (Echo Delete successfully.) || (Echo Fail to delete.)
    )
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.4
cls
Echo ----- AVL.8.E.4. Remove one boot entries -----
!BCDcommand! /enum 
Echo.
Set "t=0"
For /f "tokens=2" %%a in ('!BCDcommand! /enum ^| findstr /r "bootsequence"') do (
	Set /a t+=1
	Echo Identifier [!t!] is found: %%a - One time boot entry
	Set "DescArray[!T!]=%%a"
)
Set "GUID2="
For /f "tokens=2" %%a in ('!BCDcommand! /enum ^| findstr /r "identifier.*{.*}"') do (
	If "%%a" neq "{bootmgr}" (
		Set /a t+=1
		Set "GUID2=%%a"
		Set "Desc="
		For /f "tokens=1,*" %%b in ('!BCDcommand! /enum !GUID2! 2^>nul ^| findstr /r "description"') do (Set "Desc=%%c")
		Set "DescArray[!T!]=!GUID2!"
		echo Identifier [!t!] is found: !GUID2! - !Desc!
	)
)
Echo.
If "!GUID2!" NEQ "" (
	Set /p GUID2="> Input identifier to delete (Press Enter to choose !t!): "
) Else (
	Echo !GUID2! not found.
	Set /p GUID2="> Input identifier to delete: "
)
If DEFINED DescArray[!GUID2!] (set GUID2=!DescArray[%GUID2%]!)
if not defined GUID2 (
	Echo Input invalid.
	Pause
	Goto :AVL.8.E.MainMenu
)
!BCDcommand! /enum !GUID2! >nul 2>&1
if %errorlevel% equ 0 (
	echo The selected identifier: !GUID2!
	!BCDcommand! /delete !GUID2! && (Echo Delete successfully.) || (Echo Fail to delete.)
) Else (
	echo !GUID2! is not found. 
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.5
cls
Echo ----- AVL.8.E.5. Set default OS for boot menu -----
!BCDcommand! /enum
Echo.
Set "T=0"
Set "GUID2="
Set "DefaultOS="
For /f "tokens=2" %%a in ('!BCDcommand! /enum ^| findstr /r "identifier.*{.*}"') do (
	If "%%a" neq "{bootmgr}" (
		Set /a t+=1
		Set "GUID2=%%a"
		Set "Desc="
		For /f "tokens=1,*" %%b in ('!BCDcommand! /enum !GUID2! 2^>nul ^| findstr /r "description"') do (Set "Desc=%%c")
		Set "DescArray[!T!]=!GUID2!"
		echo Identifier !T! is found: !GUID2! - !Desc!
		If "{default}" equ "!GUID2!" (Set "DefaultOS=Identifier !T! - !GUID2! - !Desc!" )
	)
)
Echo.
If "!DefaultOS!" equ "" (
	For /f "tokens=2" %%a in ('!BCDcommand! /enum {bootmgr} ^| findstr /r "default"') do (Set "DefaultOS=%%a")
)
Echo Default OS: !DefaultOS!
If "!GUID2!" NEQ "" (
	Set /p GUID2="> Input identifier to set default OS (Press Enter to choose !T!): "
) Else (
	Echo !GUID2! not found.
	Set /p GUID2="> Input identifier to set default OS: "
)
If DEFINED DescArray[!GUID2!] (set GUID2=!DescArray[%GUID2%]!)
if not defined GUID2 (
	Echo Input invalid.
	Pause
	Goto :AVL.8.E.MainMenu
)

!BCDcommand! /enum %GUID2% >nul 2>&1
if %errorlevel% equ 0 (
	echo %GUID2% is found.
	!BCDcommand! /default %GUID2% && (Echo Set default successfully.) || (Echo Fail to set default.)
) Else (
	echo Invalid or not found: %GUID2%
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.6
cls
Echo ----- AVL.8.E.6. Change description of boot entry -----
!BCDcommand! /enum
Echo.
Set "T=0"
Set "GUID2="
For /f "tokens=2" %%a in ('!BCDcommand! /enum ^| findstr /r "identifier.*{.*}"') do (
	If "%%a" neq "{bootmgr}" (
		Set /a t+=1
		Set "GUID2=%%a"
		Set "Desc="
		For /f "tokens=1,*" %%b in ('!BCDcommand! /enum !GUID2! 2^>nul ^| findstr /r "description"') do (Set "Desc=%%c")
		Set "DescArray[!T!]=!GUID2!"
		echo Identifier !t! is found: !GUID2! - !Desc!
	)
)
Echo.
If "!GUID2!" NEQ "" (
	Set /p GUID2="> Input identifier to set default OS (Press Enter to choose !t!): "
) Else (
	Echo !GUID2! not found.
	Set /p GUID2="> Input identifier to delete: "
)
If DEFINED DescArray[!GUID2!] (set GUID2=!DescArray[%GUID2%]!)
if not defined GUID2 (
	Echo Input invalid.
	Pause
	Goto :AVL.8.E.MainMenu
)

Set "NewDescription="
Set /p "NewDescription=> Input new description to change: " 
if not defined NewDescription (
	Echo Input invalid.
	Pause
	Goto :AVL.8.E.MainMenu
)

!BCDcommand! /enum %GUID2% >nul 2>&1
if %errorlevel% equ 0 (
	echo %GUID2% is found.
	!BCDcommand! /set !GUID2! description "!NewDescription!" && (Echo Set default successfully.) || (Echo Fail to set default.)
) Else (
	echo Invalid or not found: %GUID2%
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.7
cls
Echo ----- AVL.8.E.7. Change timeout for boot menu -----
!BCDcommand! /enum {bootmgr}
Echo.
Set “TimeOut1=10”
for /f "tokens=2 delims= " %%a in ('!BCDcommand! /enum {bootmgr} ^| findstr /i "timeout"') do (Set "TimeOut1=%%a")
Echo Current timeout: !TimeOut1! seconds
Set /p "TimeOut1=> Input seconds to change timeout: " 
if not defined TimeOut1 (Goto :AVL.8.E.MainMenu)
!BCDcommand! /timeout !TimeOut1! && (Echo Set timeout successfully.) || (Echo Fail to set timeout.)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.8
cls
Echo ----- AVL.8.E.8. Change Boot-Menu-Policy for boot entry -----
!BCDcommand! /enum {default}
Echo.
Echo ----- Select Boot-Menu-Policy of default boot entry
Echo    [1] Standard (the modern graphical boot menu).
Echo    [2] Legacy (the old text-based boot menu).
Echo    [0] Return to the previous menu.
CHOICE /c 120 /n /m "> Your Wishes: "
If "!ErrorLevel!" equ "1" (!BCDcommand! /set {default} bootmenupolicy Standard)
If "!ErrorLevel!" equ "2" (!BCDcommand! /set {default} bootmenupolicy Legacy)
If "!ErrorLevel!" equ "3" (Goto :AVL.8.E.MainMenu)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.9
cls
Echo ----- AVL.8.E.9. Change DisplayOrder for boot menu -----
!BCDcommand! /enum
Echo.
Set "T=0"
Set "GUID2="
Set "DisplayOrder="
Set "ListInput="
For /f "tokens=2" %%a in ('!BCDcommand! /enum ^| findstr /r "identifier.*{.*}"') do (
	If "%%a" neq "{bootmgr}" (
		Set /a t+=1
		Set "ListInput=!ListInput!!t!, "
		Set "GUID2=%%a"
		Set "Desc="
		For /f "tokens=1,*" %%b in ('!BCDcommand! /enum !GUID2! 2^>nul ^| findstr /r "description"') do (Set "Desc=%%c")
		Set "DescArray[!T!]=!GUID2!"
		Set "DisplayOrder=!DisplayOrder!!GUID2! "
		echo Identifier !t!: !Desc! - !GUID2! 
	)
)
Echo DisplayOrder: !DisplayOrder!
Echo.
If "!GUID2!" NEQ "" (
	Set /p GUID2="> Input identifier to change display order (Press Enter to choose Identifier !t!): "
) Else (
	Echo !GUID2! not found.
	Set /p GUID2="> Input identifier to delete: "
)
If DEFINED DescArray[!GUID2!] (set GUID2=!DescArray[%GUID2%]!)
if not defined GUID2 (
	Echo Input invalid.
	Pause
	Goto :AVL.8.E.MainMenu
)
!BCDcommand! /enum !GUID2! >nul || (
	Echo Identifier is not found.
	Pause
	Goto :AVL.8.E.MainMenu
)

Set "DisplayOrder=!DisplayOrder:%GUID2% =!{WillRemove}"
Set "NewOrder="
set ListInput=%ListInput:~0,-2%
Set /p "NewOrder=> Input new display order to change (!ListInput!): " 
if not defined NewOrder (
	Echo Input invalid.
	Pause
	Goto :AVL.8.E.MainMenu
)
If !NewOrder! lss 1 if !NewOrder! gtr !t! (
	Echo Input invalid.
	Pause
	Goto :AVL.8.E.MainMenu
)
Echo.
Set "k=0"
Set "NewDisplayOrder="
For %%a in (!DisplayOrder!) do (
	Set /a k+=1
	If !k! equ !NewOrder! (Set "NewDisplayOrder=!NewDisplayOrder!!GUID2! %%a ") else (Set "NewDisplayOrder=!NewDisplayOrder!%%a ")
)
Set "NewDisplayOrder=!NewDisplayOrder:{WillRemove}=!"
Echo NewDisplayOrder=!NewDisplayOrder!
!BCDcommand! /displayorder !NewDisplayOrder! && (Echo Change display order successfully.) || (Echo Fail to change display order.)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.CopyBootSdi
If exist "X:" (
	For /f "delims=" %%a in ('dir /s /b "X:\Windows\Boot\boot.sdi" 2^>nul') do Set "BootSdiPath=%%a"
)
If "!BootSdiPath!" EQU "" (
	For /f "delims=" %%a in ('dir /s /b "C:\Windows\Boot\boot.sdi" 2^>nul') do Set "BootSdiPath=%%a"
)
If "!BootSdiPath!" EQU "" (
	Echo Boot SDI file not found in system partition
	Goto :AVL.8.E.MainMenu
)
If not exist "!BootWimPathNoFile!boot.sdi" (COPY /Y "!BootSdiPath!" "!BootWimPathNoFile!boot.sdi")
Set "BootSdiPath=!BootWimPathNoFile!boot.sdi"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.FindEFIpartition
Echo ----- Find EFI partition
SET "EfiDrive="
SET "BcdPath="
Set "T=0"
For /f "tokens=3" %%L in ('echo list volume ^| diskpart ^| find "FAT32"') do (
	Set /a T+=1
	set "BcdPath=%%L:\EFI\Microsoft\Boot\BCD"
	If exist "!BcdPath!" (
		Echo BCD !T!: "!BcdPath!"
		Set "BCDPathArray[!T!]=!BcdPath!"
	)
)
If exist "!BcdPath!" (
	Set /p "BcdPath=> Please input BCD path (press Enter to choose BCD !T!): "
) Else (
	Set /p "BcdPath=> Please input BCD path: "
)	
If DEFINED BCDPathArray[!BcdPath!] (set BcdPath=!BCDPathArray[%BcdPath%]!)
if not defined BcdPath (
	Echo Input invalid.
	Pause
	Goto :AVL.8.E.MainMenu
)
Set "BcdPath=!BcdPath:"=!"
If not exist "!BcdPath!" (
	Echo BCD path is not valid.
	Pause
	Goto :AVL.8.E.MainMenu
)

Echo The selected BCD Path: "!BcdPath!"
Goto :EOF


::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.E.CheckWimPathForBootMenu
Echo ----- Check Wim path
Set "BootWimPath="
For /f "delims=" %%a in ('dir /s /b "%CurrentPath%*.wim" 2^>nul') do (Set "BootWimPath=%%a")
If "!BootWimPath!" equ "" (
	For /f "delims=" %%a in ('dir /s /b "%CurrentPathDrive%\*.wim" 2^>nul') do (Set "BootWimPath=%%a")
)
If "!BootWimPath!" equ "" (
	IF EXIST "Y:\" For /f "delims=" %%a in ('dir /s /b "Y:\*.wim" 2^>nul') do (Set "BootWimPath=%%a")
)
Set "T=0"
If "!BootWimPath!" NEQ "" (
	For /f "delims=" %%i in ("!BootWimPath!") do (set "SearchFolder=%%~dpi")
	For %%i in ("!SearchFolder!*.wim") do (
		Set /a T+=1
		Set "BootWimPath=%%~fi"
		Echo WIM !T! is found: "%%~fi"
		Set "BootWimNameArray[!T!]=%%~fi"
	)
)
If "!BootWimPath!" NEQ "" (
	Set /p BootWimPath="> Please input WIM path (Press Enter to choose WIM %T%): "
) Else (
	Echo WIM not found.
	Set /p BootWimPath="> Please input WIM path: "
)
If DEFINED BootWimNameArray[!BootWimPath!] (set BootWimPath=!BootWimNameArray[%BootWimPath%]!)
Set "BootWimPath=!BootWimPath:"=!"
if /i "%BootWimPath:~-4%" NEQ ".wim" (
	Echo Error: Not WIM file.
	pause
	Goto :AVL.8.E.MainMenu
)
If not exist "!BootWimPath!" (
	Echo Error: Path is not found.
	pause
	Goto :AVL.8.E.MainMenu
)
For /f "delims=" %%i in ("!BootWimPath!") do (
	set "BootWimPathNoFile=%%~dpi"
	set "BootWimDrive=%%~di"
)
Echo The selected WIM path: "!BootWimPath!"
Set "BootSdiPath="
For /f "delims=" %%i in ("!BootWimPath!") do (set "BootWimDrive=%%~di")
For /f "delims=" %%b in ('dir /s /b "!BootWimDrive!\boot.sdi" 2^>nul') do Set "BootSdiPath=%%b"
If "!BootSdiPath!" EQU "" (Call :AVL.8.E.CopyBootSdi)
Echo The selected SDI path: "!BootSdiPath!"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CopyBootSdi
For /f "delims=" %%a in ('dir /s /b "%SystemDrive%\Windows\Boot\boot.sdi" 2^>nul') do Set "BootSdiPath=%%a"
If "!BootSdiPath!" EQU "" (
	Echo Boot SDI file not found in system partition
	Call :AVL.Finish ""
)
If not exist "!BootWimPathNoFile!boot.sdi" (COPY /Y "!BootSdiPath!" "!BootWimPathNoFile!boot.sdi")
Set "BootSdiPath=!BootWimPathNoFile!boot.sdi"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.FindEFIpartition
Echo ----- Find EFI partition
SET "EfiDrive="
SET "BcdPath="
::for /f "tokens=3" %%L in ('echo list volume ^| diskpart ^| find "FAT32"') do (set "EfiDrive=%%L")
for /f "tokens=*" %%L in ('powershell -Command "(Get-Partition | Where-Object { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' }).driveletter"') do (set "EfiDrive=%%L")

If exist "!EfiDrive!:\EFI\Microsoft\Boot\BCD" (
	SET "BcdPath=!EfiDrive!:\EFI\Microsoft\Boot\BCD"
	Echo BCD is available: "!BcdPath!"
	Set /p "BcdPath=> Please input BCD path (press Enter to choose path above): "
) Else (
	Set /p "BcdPath=> Please input BCD path: "
)	

Set "BcdPath=!BcdPath:"=!"
If not exist "!BcdPath!" (
	Echo BCD path is not valid.
	Call :AVL.Finish ""
)
Echo The selected BCD Path: "!BcdPath!"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckWimPathForBootMenu
Echo ----- Check Wim path
Set "BootWimPath="
For /f "delims=" %%a in ('dir /s /b "%~dp0*.wim" 2^>nul') do (Set "BootWimPath=%%a")
If "!BootWimPath!" equ "" (
	For /f "delims=" %%a in ('dir /s /b "%~d0\*.wim" 2^>nul') do (Set "BootWimPath=%%a")
)
If "!BootWimPath!" equ "" (
	IF EXIST "Y:\" For /f "delims=" %%a in ('dir /s /b "Y:\*.wim" 2^>nul') do (Set "BootWimPath=%%a")
)
Set "T=0"
If "!BootWimPath!" NEQ "" (
	For /f "delims=" %%i in ("!BootWimPath!") do (set "SearchFolder=%%~dpi")
	For %%i in ("!SearchFolder!*.wim") do (
		Set /a T+=1
		Set "BootWimPath=%%~fi"
		Echo WIM !T! is found: "%%~fi"
		Set "BootWimNameArray[!T!]=%%~fi"
	)
)
If "!BootWimPath!" NEQ "" (
	Set /p BootWimPath="> Please input WIM path (Press Enter to choose WIM %T%): "
) Else (
	Echo WIM not found.
	Set /p BootWimPath="> Please input WIM path: "
)
If DEFINED BootWimNameArray[!BootWimPath!] (set BootWimPath=!BootWimNameArray[%BootWimPath%]!)
Set "BootWimPath=!BootWimPath:"=!"
if /i "%BootWimPath:~-4%" NEQ ".wim" (Call :AVL.Finish "Not WIM file")
If not exist "!BootWimPath!" (Call :AVL.Finish "Path is not found")
For /f "delims=" %%i in ("!BootWimPath!") do (
	set "BootWimPathNoFile=%%~dpi"
	set "BootWimDrive=%%~di"
)
Echo The selected WIM path: "!BootWimPath!"
Set "BootSdiPath="
For /f "delims=" %%i in ("!BootWimPath!") do (set "BootWimDrive=%%~di")
For /f "delims=" %%b in ('dir /s /b "!BootWimDrive!\boot.sdi" 2^>nul') do Set "BootSdiPath=%%b"
If "!BootSdiPath!" EQU "" (Call :AVL.CopyBootSdi)
Echo The selected SDI path: "!BootSdiPath!"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.F
Set "AVLBackMenu=AVL.8.F"
cls
Echo ------- AVL.8.F. Manage Drivers with a WIM File -------
Echo   [1] Extract drivers from WIM to folder.
Echo   [2] Insert drivers from folder into WIM
Echo   [0] Return to the previous menu.
CHOICE /c 120 /n /m "------ (^_^) Your Wishes Come True (^_^) ------"
If %ErrorLevel% equ 1 Goto :AVL.8.F.1
If %ErrorLevel% equ 2 Goto :AVL.8.F.2
If %ErrorLevel% equ 3 Goto :AVL.8

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.F.1
cls
Echo ------- AVL.8.F.1. Extract drivers from WIM to folder -------
Echo ----- Check Mount Folder
Set "MountFolder="
Set /p "MountFolder=> Select mount folder path (press Enter to mount WIM): "
Set "MountFolder=!MountFolder:"=!"
If exist "!MountFolder!" (Goto Dism1) 
Echo ----- Check Wim path
Set "WimPath="
Set "T=0"
For %%i in ("%~dp0*.wim") do (
	Set /a T+=1
	Set "WimPath=%%~fi"
	Echo Wim !T! is found: "%%~fi"
	Set "WimNoArr[!T!]=!T!"
	Set "WimNameArr[!T!]=%%~fi"
)
If "!WimPath!" NEQ "" (
	Set /p WimPath="> Please input Wim path (Press Enter to choose Wim %T%): "
) Else (
	Set /p WimPath="> Please input Wim path: "
)
If DEFINED WimNameArr[%WimPath%] set "WimPath=!WimNameArr[%WimPath%]!"
Set "WimPath=!WimPath:"=!"
if /i "%WimPath:~-4%" NEQ ".wim" (Call :AVL.Finish "Not Wim file")
If not exist "!WimPath!" (Call :AVL.Finish "Input invalid")
Echo The selected WIM file: "!WimPath!"
Echo.
Echo ----- Show index of WIM
Call :ListAllIndexImages
Set "WimIndex=1"
Set /p "WimIndex=> Input WIM index (Press Enter to choose 1): "
Set "found="
For %%i in (!AllIndex!) do (
    if "%%i" EQU "!WimIndex!" set "found=true"
)
If "!found!" NEQ "true" (Call :AVL.Finish "Invalid index number")
Echo The selected index number: !WimIndex! (!AllName[%WimIndex%]!)
Echo.
Echo ----- Mount WIM
Set "MountFolder=%~dp0MountFolder%random%"
If exist "!MountFolder!" Rmdir /s /q "!MountFolder!"
Mkdir "!MountFolder!"
dism /Mount-Wim /WimFile:"!WimPath!" /Index:!WimIndex! /MountDir:"!MountFolder!" /ReadOnly && (
	Echo Mount WIM successfully
) || (
	call :AVL.Finish "Failed to mount WIM"
)

:Dism1
Echo ----- Extracting specific drivers -----
Set "ExtractDriverFolder=%~dp0ExtractDriverFolder%random%"
If exist "!ExtractDriverFolder!" Rmdir /s /q "!ExtractDriverFolder!"
Mkdir "!ExtractDriverFolder!"

if not exist "!MountFolder!\Windows\System32\DriverStore\FileRepository" (Call :AVL.Finish "The FileRepository folder is not found")

(
echo # --- Configuration ---
echo # Point this to your mount folder ^(e.g., C:\Mount^) or the root of a running OS ^(e.g., C:^)
echo $mountPath = "%MountFolder%"
echo # Where to save the organized drivers
echo $destinationPath = "%ExtractDriverFolder%"
echo.
echo # --- Define the driver classes you want to extract ---
echo # Add or remove classes from this list as needed.
echo $targetClasses = @^(
echo     "Net",           # Network Adapters
echo     "SCSIAdapter",   # RAID/SATA/SAS Controllers
echo     "STORNVME",      # NVMe Storage Controllers
echo     "USB"            # USB 3.x Host Controllers and Hubs
echo ^)
echo.
echo # --- Script Body ---
echo $fileRepositoryPath = Join-Path $mountPath "Windows\System32\DriverStore\FileRepository"
echo.
echo # Create the main destination folder if it doesn't exist
echo if ^(-not ^(Test-Path $destinationPath^)^) {
echo     New-Item -Path $destinationPath -ItemType Directory
echo }
echo.
echo Write-Host "Searching for drivers in: $fileRepositoryPath"
echo Write-Host "Targeting classes: $^($targetClasses -join ', '^)" -ForegroundColor Yellow
echo.
echo # Get all .inf files and process them
echo Get-ChildItem -Path $fileRepositoryPath -Recurse -Filter *.inf ^| ForEach-Object {
echo     $infFile = $_
echo.
echo     # Efficiently find the "Class=" line in the [Version] section of the INF
echo     $classLine = Get-Content $infFile.FullName ^| Select-String -Pattern "^^Class=" -List
echo.
echo     if ^($classLine^) {
echo         # Extract the actual class name
echo         $className = ^($classLine.Line -split '='^)[1].Trim^(^)
echo.
echo         # Check if the found class is one we are looking for
echo         if ^($targetClasses -contains $className^) {
echo             # Get the parent directory ^(the driver package folder^)
echo             $driverPackage = $infFile.Directory
echo             Write-Host "Found '$className' driver: $^($driverPackage.Name^)" -ForegroundColor Cyan
echo.
echo             # Create a dedicated subfolder for this class if it doesn't exist
echo             $classDestinationPath = Join-Path $destinationPath $className
echo             if ^(-not ^(Test-Path $classDestinationPath^)^) {
echo                 New-Item -Path $classDestinationPath -ItemType Directory
echo             }
echo.
echo             # Define the final destination for this specific driver package
echo             $destPackagePath = Join-Path $classDestinationPath $driverPackage.Name
echo.
echo             # Copy the entire driver package folder
echo             Write-Host "  -^> Copying to $classDestinationPath"
echo             Copy-Item -Path $driverPackage.FullName -Destination $destPackagePath -Recurse -Force
echo         }
echo     }
echo }
echo.
echo Write-Host "Extraction complete. Organized drivers are in: $destinationPath" -ForegroundColor Green
) > AVLExportDriver.ps1

powershell -ExecutionPolicy Bypass -File "%~dp0AVLExportDriver.ps1"
Del "%~dp0AVLExportDriver.ps1"

Echo ----- Unmount WIM
dism /Unmount-Wim /MountDir:"!MountFolder!" /Discard && (
	Echo Unmount WIM successfully.
) || (
	call :AVL.Finish "Failed to Unmount WIM"
)
Rmdir /s /q !MountFolder! 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.F.2
cls
Echo ------- AVL.8.F.2. Insert drivers from folder into WIM -------
Echo ----- Check Wim path
Set "WimPath="
Set "T=0"
For %%i in ("%~dp0*.wim") do (
	Set /a T+=1
	Set "WimPath=%%~fi"
	Echo Wim !T! is found: "%%~fi"
	Set "WimNoArr[!T!]=!T!"
	Set "WimNameArr[!T!]=%%~fi"
)
If "!WimPath!" NEQ "" (
	Set /p WimPath="> Please input Wim path (Press Enter to choose Wim %T%): "
) Else (
	Set /p WimPath="> Please input Wim path: "
)
If DEFINED WimNameArr[%WimPath%] set "WimPath=!WimNameArr[%WimPath%]!"
Set "WimPath=!WimPath:"=!"
if /i "%WimPath:~-4%" NEQ ".wim" (Call :AVL.Finish "Not Wim file")
If not exist "!WimPath!" (Call :AVL.Finish "Input invalid")
Echo The selected WIM file: "!WimPath!"
Echo.
Echo ----- Check Driver path
Set "DriverPath="
Set /p "DriverPath=> Input driver path: "
If not exist "!DriverPath!" (Call :AVL.Finish "Input invalid")
Set "DriverPath=!DriverPath:"=!"
Echo ----- Show index of WIM
Call :ListAllIndexImages
Set "WimIndex=1"
Set /p "WimIndex=> Input WIM index (Press Enter to choose 1): "
Set "found="
For %%i in (!AllIndex!) do (
    if "%%i" EQU "!WimIndex!" set "found=true"
)
If "!found!" NEQ "true" (Call :AVL.Finish "Invalid index number")
Echo The selected index number: !WimIndex! (!AllName[%WimIndex%]!)
Echo ----- Mount WIM
Set "MountFolder=MountFolder%random%"
If exist "!MountFolder!" Rmdir !MountFolder!
Mkdir !MountFolder!
dism /Mount-Wim /WimFile:"!WimPath!" /Index:!WimIndex! /MountDir:"!MountFolder!" && (Echo Mount WIM successfully) || (
    call :AVL.Finish "Failed to mount WIM"
)
Echo ----- Insert driver
dism /Image:"!MountFolder!" /Add-Driver /Driver:"!DriverPath!" /Recurse /ForceUnsigned && (Echo Insert driver successfully) || (
    call :AVL.Finish "Failed to insert driver"
)
Echo ----- Unmount WIM
dism /Unmount-Wim /MountDir:"!MountFolder!" /Commit && (Echo Unmount WIM successfully) || (
    call :AVL.Finish "Failed to Unmount WIM"
)
Rmdir !MountFolder! 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.G
cls
echo ------- AVL.8.G. Insert Driver (Ex: Intel RST VMD) from WinPE to Windows -------
Echo ----- Check OS is WinPE
Reg Query "HKLM\System\CurrentControlSet\Control\MiniNT" >nul 2>&1
If %ErrorLevel% EQU 0 (
	Echo Running in WinPE.
) Else (
	Echo NOT running in WinPE.
	Call :AVL.Finish ""
)
Echo.
Set "DriverPath=Y:\AVL_APP\Drivers\IntelRST"
dir "!DriverPath!" /b >nul 2>&1 && (Echo Driver is available at "Y:\AVL_APP\Drivers\IntelRST") || (Set "DriverPath=")
If "!DriverPath!" equ "" (
	Set /p "DriverPath=> Input driver path: "
) Else ( 
	Set /p "DriverPath=> Input driver path (Press Enter to choose the path above): "
)
Echo The selected driver path: "!DriverPath!"
Echo.
set "OSDrive="
for %%D in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
    if exist "%%D:\Windows\System32\" (
        set "OSDrive=%%D:"
        Echo Windows OS is available at drive "!OSDrive!"
    )
)
If "!OSDrive!" equ "" (
	Set /p "OSDrive=> Input the Windows drive: "
) else ( 
	Set /p "OSDrive=> Input the Windows drive (Press Enter to choose !OSDrive!) ^? "
)

If exist "!OSDrive!\Windows\System32" (
	dism /Image:!OSDrive!\ /Add-Driver /Driver:"!DriverPath!" /Recurse /ForceUnsigned && (Echo Insert driver successfully) || (Call :AVL.Finish "Failed to insert driver")
) Else (
	Echo Drive !OSDrive! is not valid.
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.H
cls
echo ------- AVL.8.H. Help (Automatic Windows Installation) -------
Start "" "https://docs.google.com/document/d/e/2PACX-1vRuOuflOhQNOmurl5bR-JmefBfi2FIW1grK56aHUhpWJxI3CCw1h0QjvXNHsQyo2PyIvernvNZaPq6a/pub"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.8.Z
cls
Echo ------- AVL.8.Z. Automatic Configuration -------
Echo ----- Copy ukmacro.txt
If exist "D:\Software\EVKey\ukmacro.txt" (
	If exist "C:\Unikey\UniKeyNT.exe" Copy /y "D:\Software\EVKey\ukmacro.txt" "C:\Unikey\"
)
tasklist | findstr /i "Unikey*" >nul 2>&1
If %errorlevel%==0 (taskkill /im Unikey* /f >nul 2>&1)
schtasks /Run /TN "Start UniKey as Admin"
Echo ----- Rename PC
powershell -Command "Rename-Computer -NewName 'AVL'"
Echo ----- Enable Dark Mode 
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f
If %WinVer% GEQ 22000 (
	Reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\Windows\Web\Wallpaper\Windows\img19.jpg" /f
	RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters
)
Echo ----- Add "Open CMD here" to Context Menu 
:: For right-clicking ON a folder
reg add "HKEY_CLASSES_ROOT\Directory\shell\open_cmd_admin" /ve /d "Open CMD here (Admin)" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\open_cmd_admin" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\open_cmd_admin\command" /ve /d "powershell.exe -windowstyle hidden -command \"Start-Process cmd.exe -ArgumentList '/s /k pushd \\\"%%V\\\"' -Verb RunAs\"" /f
:: For right-clicking INSIDE a folder (on the background)
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\open_cmd_admin" /ve /d "Open CMD here (Admin)" /f
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\open_cmd_admin" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\open_cmd_admin\command" /ve /d "powershell.exe -windowstyle hidden -command \"Start-Process cmd.exe -ArgumentList '/s /k pushd \\\"%%V\\\"' -Verb RunAs\"" /f
Echo ----- Only Search Icon on Taskbar 
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f
Echo ----- Show All Icons on Taskbar
For /F "Delims=\ tokens=4" %%b in ('Reg query "HKEY_CURRENT_USER\Control Panel\NotifyIconSettings" ^| findstr /b /c:"HKEY_CURRENT_USER"') do (
	Reg add "HKEY_CURRENT_USER\Control Panel\NotifyIconSettings\%%b" /v "IsPromoted" /t REG_DWORD /f /d 1
) 
Echo ----- Set Left Align For Taskbar
Reg add hkcu\software\microsoft\windows\currentversion\explorer\advanced /v TaskbarAl /t REG_DWORD /f /d 0
Echo ----- Reset explorer
taskkill /f /im explorer.exe
Start explorer.exe
Echo ----- Install 7-Zip 
Echo ----- Getting the latest Version
Set "URL=https://www.7-zip.org"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=3 delims=() " %%a in ('find "Windows x64 (64-bit)" a.txt') do Set t1=%%a
Set t1=%t1:.=%
Del a.txt
Set "zip64=https://www.7-zip.org/a/7z%t1%-x64.exe"
Set "zip86=https://www.7-zip.org/a/7z%t1%.exe"
If EXIST "%Windir%\SysWOW64" (Set "URL=%zip64%") ELSE (Set "URL=%zip86%")
Set "File=zip7.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Start /wait "" "%File%" /S /D="%ProgramFiles%\7-Zip"
Del %File%
Echo ----- Install the latest version IDM -----
Set "URL=https://www.internetdownloadmanager.com/download.html"
Set "File=a.html"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "delims=" %%A in ('Powershell -Command "$Pattern='https://mirror2.internetdownloadmanager\.com/idman\d+build\d+\.exe';" ^
	"$Matches=[regex]::Match((Get-Content -Raw a.html), $Pattern);" ^
	"If ($Matches.Success) { $Matches.Value }"') do Set "URL=%%A"
DEL %File%
Set "File=idman_setup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Start "" "%File%" /skipdlgs
Echo ----- OBS Studio
Set "URL=https://github.com/obsproject/obs-studio/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=1 delims=:" %%a in ('findstr "OBS-Studio-" a.txt') do Set t1=%%a
For /f "tokens=3 delims=-" %%a in ("%t1%") do Set t2=%%a
Del a.txt
Set "URL=https://github.com/obsproject/obs-studio/releases/download/%t2%/OBS-Studio-%t2%-Windows-x64-Installer.exe"
Set "File=OBSInstaller.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo Installing OBS Studio ...
Start "" "%File%" /s
Del idman_setup.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.GetDiskAndPartitionOfPath
:: 1. Initialize all output variables to prevent leaking state from previous calls
Set "DiskResult="
Set "PartitionResult="
Set "PathNoDriveResult="
Set "SystemDriveResult=false"

:: 2. Prepare and validate input path
Set "Path0=%~1"
If not exist "%Path0%" (Call :AVL.Finish "Input invalid")

Set "Path1Drive="
For %%D in ("%Path0%") do set "Path1Drive=%%~dD"

:: 3. Get Disk and Partition numbers using PowerShell
for /f "tokens=1,2" %%a in ('powershell -NoProfile "$p=Get-Partition -DriveLetter '%Path1Drive:~0,1%' -ErrorAction SilentlyContinue; if ($p) { write-host $p.DiskNumber $p.PartitionNumber } else { write-host 'NotAvailable NotAvailable' }"') do (
	set "DiskResult=%%a"
	set "PartitionResult=%%b"
)
If "%DiskResult%" equ "NotAvailable" (Call :AVL.Finish "Disk of path not found")
If "%PartitionResult%" equ "NotAvailable" (Call :AVL.Finish "Partition of path not found")

:: 4. Check if it's on the system drive
If /I "%Path1Drive%" EQU "%systemdrive%" (
	Echo Warning: %Path0% is on the system drive. Please move it to another drive.
	Set "SystemDriveResult=true"
)

:: 5. [FIXED] Get the path without the drive letter using Delayed Expansion
set "PathNoDriveResult=!Path0:%Path1Drive%=!"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckDiskPartition
Call :AVL_Numberic !RecommendedDisk!
Call :AVL_Numberic !RecommendedEFIPart!
Call :AVL_Numberic !RecommendedOSPart!
Call :AVL.CheckPartitionExist !RecommendedDisk! !RecommendedEFIPart!
Call :AVL.CheckPartitionExist !RecommendedDisk! !RecommendedOSPart!
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckPartitionExist
:: Check Disk exist
Powershell -Command "if (Get-Disk -Number %1 -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
if not %errorlevel%==0 (
	Echo Error: Disk %1 does NOT exist!
	Call :AVL.Finish ""
)
:: Check partition exist
set "PartitionExist=false"
For /f "delims=" %%i in ('powershell -NoProfile -Command "$result = [bool](Get-Partition -DiskNumber %1 -PartitionNumber %2 -ErrorAction SilentlyContinue); $result.ToString().ToLower()"') do set "PartitionExist=%%i"
if "%PartitionExist%" EQU "false" (
    	Echo Error: Partition %2 was NOT found on Disk %1.
	Call :AVL.Finish ""	
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.PartitionNumber
For /f "tokens=1,2 delims=," %%A in (
  'powershell -NoLogo -NoProfile -Command "(Get-Partition -DriveLetter %SystemDrive:~0,1% -ErrorAction SilentlyContinue | Select-Object -First 1 @{Name='Disk';Expression={$_.DiskNumber}},@{Name='Part';Expression={$_.PartitionNumber}} | ForEach-Object { $_.Disk, $_.Part -join ',' })"'
) do (
    set "disk1=%%A"
    set "part1=%%B"
)
set "part2=Not_Available"
set "disk2="
for /f "tokens=1,2 delims=," %%A in (
  'powershell -NoLogo -NoProfile -Command "(Get-Partition | Where-Object { $_.GptType -eq \"{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}\" } | Select-Object -First 1 @{Name='Disk';Expression={$_.DiskNumber}},@{Name='Part';Expression={$_.PartitionNumber}} | ForEach-Object { $_.Disk, $_.Part -join ',' })"'
) do (
    set "disk2=%%A"
    set "part2=%%B"
)
Echo ----- Current Status of Windows and EFI Partitions
Echo EFI Disk number = %disk2% --- EFI Partition number = %part2%
Echo OS Disk number  = %disk1% --- OS Partition number  = %part1%

PowerShell -NoProfile -Command "Get-Partition | ForEach-Object { $d = Get-Disk -Number $_.DiskNumber -EA SilentlyContinue; $v = Get-Volume -Partition $_ -EA SilentlyContinue; $blStatus = 'N/A'; if ($_.DriveLetter) { $blv = Get-BitLockerVolume -MountPoint ($_.DriveLetter + ':') -EA SilentlyContinue; if ($blv) { $blStatus = $blv.VolumeStatus; if ($blv.VolumeStatus -like '*InProgress') { $blStatus = \"$($blv.VolumeStatus) ($($blv.EncryptionPercentage)%%)\" } } }; [PSCustomObject]@{ Disk = $_.DiskNumber; Partition = $_.PartitionNumber; 'Size(MB)' = [Math]::Round($_.Size/1MB,2); Type = $_.Type; Style = $d.PartitionStyle; FileSystem = $v.FileSystem; BitLocker = $blStatus; Drive = $_.DriveLetter } } | Sort-Object Disk, Partition | Format-Table -AutoSize"
Echo ----- Recommended Partitions
Set "RecommendedDisk=%disk1%"
Set "RecommendedOSPart=%part1%"
If "%part2%" EQU "Not_Available" (
	Set "RecommendedEFIPart=%part1%"
) Else (
	Set "RecommendedEFIPart=%part2%"
)
Echo Firmware Type             = %FirmwareType% 
Echo Recommended Disk number   = %RecommendedDisk%
IF "%FirmwareType%" EQU "UEFI" (Echo Recommended EFI Partition = %RecommendedEFIPart%)
Echo Recommended OS Partition  = %RecommendedOSPart%
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.9
Set "AVLBackMenu=AVL.9"
cls
Echo ------------------------ AVL.9. Template ------------------------
<NUL SET/P=[1] &(Call :EchoColor "Template_01" 1E)& Echo  Background: Blue,   Text: Yellow. (Light Mode)
<NUL SET/P=[2] &(Call :EchoColor "Template_02" E1)& Echo  Background: Yellow, Text: Blue.   (Light Mode)
<NUL SET/P=[3] &(Call :EchoColor "Template_03" 0A)& Echo  Background: Black,  Text: Green.  (Dark Mode)
<NUL SET/P=[4] &(Call :EchoColor "Template_04" 0E)& Echo  Background: Black,  Text: Yellow. (Dark Mode)
Echo [5] Customize your Template
Echo [0] Return to the previous Menu
CHOICE /c 123450 /n /m "--------------- (^_^) Your Wishes Come True (^_^) ---------------"
If %ErrorLevel%==1 (Call :AVLTemplate 1E) && (Goto !AVLBackMenu!)
If %ErrorLevel%==2 (Call :AVLTemplate E1) && (Goto !AVLBackMenu!)
If %ErrorLevel%==3 (Call :AVLTemplate 0A) && (Goto !AVLBackMenu!)
If %ErrorLevel%==4 (Call :AVLTemplate 0E) && (Goto !AVLBackMenu!)
If %ErrorLevel%==5 Goto AVL.9.CustomizeTemplate
If %ErrorLevel%==6 Goto AVL.MainMenu
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVLTemplate
Reg add "HKCU\Console" /v QuickEdit /t REG_DWORD /d 1 /f >nul 2>&1
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\TrueTypeFont" /v 000 /t REG_SZ /d "Cascadia Code" /f >nul 2>&1
Reg add "HKCU\Console" /v FaceName /t REG_SZ /d "Cascadia Code" /f >nul 2>&1
Reg add "HKCU\Console" /v FontSize /t REG_DWORD /d 0x00140000 /f >nul 2>&1
Set "DefaultTemplate=%1"
Color %DefaultTemplate%
Set "a1=%DefaultTemplate:~0,1%"
Set "a2=%DefaultTemplate:~1,1%"
Set "ContrastColor=%a2%%a1%"
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.9.CustomizeTemplate
Echo.
Echo --------------------- AVL.9. Customize Template ---------------------
Echo 0:Black         1:Blue           2:Green           3:Aqua           
Echo 4:Red           5:Purple         6:Yellow (Dark)   7:White (Gray)
Echo 8:Gray (Dark)   9:Light Blue     A:Light Green     B:Light Aqua
Echo C:Light Red     D:Light Purple   E:Bright Yellow   F:Bright White
CHOICE /c 1234567890ABCDEF /n /m "----------------- Input Background Color (0-9, A-F) -----------------"
Set /A Index=%ErrorLevel%-1
Set "List=1234567890ABCDEF"
Set BackgroundColor=!List:~%Index%,1!
Echo BackgroundColor=%BackgroundColor%
CHOICE /c 1234567890ABCDEF /n /m "-------------------- Input Text Color (0-9, A-F) --------------------"
Set /A Index=%ErrorLevel%-1
Set "List=1234567890ABCDEF"
Set TextColor=!List:~%Index%,1!
Echo TextColor=%TextColor%
Echo ----- Set Background Color, Text Color, Contrast Color
If %BackgroundColor% EQU %TextColor% (Call :AVLTemplate E1) Else (Call :AVLTemplate %BackgroundColor%%TextColor%)
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.A
For %%a in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do Set "Status%%a=Not_Check"
Choco -v >nul 2>&1
If "%ErrorLevel%" EQU "0" (Set "ChocolateyStatus=Installed") else (Set "ChocolateyStatus=Not_Exist")
If exist "%ProgramData%\chocolatey\lib\chocolateygui" (Set "ChocolateyGUIStatus=Installed") else (Set "ChocolateyGUIStatus=Not_Exist")

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.A.Menu
Set "AVLBackMenu=AVL.A.Menu"
Set "FileDel="
Set "FolderDel="
CLS
Echo ---------------------------- AVL.A.Chocolatey ----------------------------
Echo   [1] Install Chocolatey. (%ChocolateyStatus%)  
Echo   [2] Uninstall Chocolatey.
Echo   [3] Check Software Status.
Echo   [4] Install ChocolateyGUI. (%ChocolateyGUIStatus%)
Echo   [5] Recommend some commands to install software by Chocolatey.
Echo   [6] Download Google Sharing URL by Gdown (Python).
Echo   [0] Go to the previous Menu.
Echo --------------------- Install Software by Chocolatey ---------------------
Echo       NAME                             ^|  STATUS   ^| INSTALL  ^| UNINSTALL^|
Echo ----- Developer Tools ----------------------------------------------------
Echo    A. Git                              ^| %StatusA% ^|   [A1]   ^|   [A2]   ^|
Echo    B. Python                           ^| %StatusB% ^|   [B1]   ^|   [B2]   ^|  
Echo    C. NodeJS                           ^| %StatusC% ^|   [C1]   ^|   [C2]   ^|
Echo    D. Java JDK                         ^| %StatusD% ^|   [D1]   ^|   [D2]   ^|
Echo    E. Postman                          ^| %StatusE% ^|   [E1]   ^|   [E2]   ^|
Echo ----- Website Browsers ---------------------------------------------------
Echo    F. Google Chrome                    ^| %StatusF% ^|   [F1]   ^|   [F2]   ^|
Echo    G. Mozilla Firefox                  ^| %StatusG% ^|   [G1]   ^|   [G2]   ^|
Echo    H. Opera Browser                    ^| %StatusH% ^|   [H1]   ^|   [H2]   ^|
Echo    I. Brave Browser                    ^| %StatusI% ^|   [I1]   ^|   [I2]   ^|
Echo    J. Tor Browser                      ^| %StatusJ% ^|   [J1]   ^|   [J2]   ^|
Echo ----- Messaging and Social Media -----------------------------------------
Echo    K. Skype                            ^| %StatusK% ^|   [K1]   ^|   [K2]   ^|
Echo    L. Zoom                             ^| %StatusL% ^|   [L1]   ^|   [L2]   ^|
Echo    M. Discord                          ^| %StatusM% ^|   [M1]   ^|   [M2]   ^|
Echo    N. Telegram                         ^| %StatusN% ^|   [N1]   ^|   [N2]   ^|
Echo    O. WhatsApp                         ^| %StatusO% ^|   [O1]   ^|   [O2]   ^|
Echo ----- File Compression and Archiving -------------------------------------
Echo    P. 7-Zip                            ^| %StatusP% ^|   [P1]   ^|   [P2]   ^|
Echo    Q. WinRAR                           ^| %StatusQ% ^|   [Q1]   ^|   [Q2]   ^|
Echo ----- Antivirus ----------------------------------------------------------
Echo    R. Malwarebytes                     ^| %StatusR% ^|   [R1]   ^|   [R2]   ^|
Echo    S. Bitdefender Free                 ^| %StatusS% ^|   [S1]   ^|   [S2]   ^|
Echo    T. Kaspersky Virus Removal Tool     ^| %StatusT% ^|   [T1]   ^|   [T2]   ^|
Echo    U. ESet NOD32 Antivirus             ^| %StatusU% ^|   [U1]   ^|   [U2]   ^|
Echo    V. ESet Internet Security           ^| %StatusV% ^|   [V1]   ^|   [V2]   ^|
Echo    W. ESet Endpoint Antivirus          ^| %StatusW% ^|   [W1]   ^|   [W2]   ^|
Echo ----- Other --------------------------------------------------------------
Echo    X. Notepad++                        ^| %StatusX% ^|   [X1]   ^|   [X2]   ^|
Echo    Y. HWinfo                           ^| %StatusY% ^|   [Y1]   ^|   [Y2]   ^|
Echo    Z. KLite Codec Pack Full            ^| %StatusZ% ^|   [Z1]   ^|   [Z2]   ^|
Set /P Input="----------------- Input value in [...] then press Enter -----------------"
:: ----- Upper Case
For /f %%A in ('Echo %Input% ^| Powershell -Command "[Console]::WriteLine('%input%'.ToUpper())"') do Set "Input=%%A"
Set "List1=1 2 3 4 5 6 0"
Set "List2=A1 B1 C1 D1 E1 F1 G1 H1 I1 J1 K1 L1 M1 N1 O1 P1 Q1 R1 S1 T1 U1 V1 W1 X1 Y1 Z1"
Set "List3=A2 B2 C2 D2 E2 F2 G2 H2 I2 J2 K2 L2 M2 N2 O2 P2 Q2 R2 S2 T2 U2 V2 W2 X2 Y2 Z2"
Set "List4=Git Python Node Java Postman GoogleChrome Firefox Opera Brave Tor-Browser Skype Zoom Discord Telegram WhatsApp 7zip WinRAR Malwarebytes Bitdefender KVRT Eset-Nod32-Antivirus Eset-Internet-Security Eset-Antivirus Notepadplusplus hwinfo KLiteCodecPackFull"
For %%L in (%List1%) do (If "%Input%"=="%%L" Goto AVL.A.%%L)
For %%L in (%List2%) do (If "%Input%"=="%%L" Call :MapList %Input% List2)
For %%L in (%List3%) do (If "%Input%"=="%%L" Call :MapList %Input% List3)
Echo Your Wishes %Input% are not realistic.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.A.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:MapList
Set "X=%1"
Set "Y=%2"
If "%2"=="List2" Goto MapList2
If "%2"=="List3" Goto MapList3

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:MapList2
Set "index=0"
For %%L in (%List2%) do (
    Set /a index+=1
    If "%X%" EQU "%%L" Goto :MapList1
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:MapList3
Set "index=0"
For %%L in (%List3%) do (
    Set /a index+=1
    If "%X%" EQU "%%L" Goto :MapList1
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:MapList1
Set "e=0"
For %%V in (%List4%) do (
	Set /a "e+=1"
	If "!e!" EQU "!index!" (Call :Maplist0 %%V)
)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:Maplist0
If "%Y%"=="List2" Call :InstallChocolateySoftware %Input% %1
If "%Y%"=="List3" Call :UnInstallChocolateySoftware %Input% %1
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:InstallChocolateySoftware
cls
Echo -------------- AVL.A.%1. Install %2 --------------
choco install %2 
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:UnInstallChocolateySoftware
cls
Echo -------------- AVL.A.%1. Uninstall %2 --------------
choco uninstall %2 
Call :AVL.Finish ""

:AVL.A.1
cls
Echo -------------- AVL.A.1 Install Chocolatey --------------
choco --version >nul 2>&1
If "%ErrorLevel%" EQU "0" (
	Echo Chocolatey is installed.
	Call :AVL.Finish ""
)
Set "URL=https://community.chocolatey.org/api/v2/package/chocolatey"
Set "File=chocolatey.zip"
Set "FileDel=%File%"
Set "FolderDel=chocolatey"
Call :AVLDownload
Powershell -Command Expand-Archive -LiteralPath '%File%'
Powershell -ExecutionPolicy Bypass -File chocolatey\tools\chocolateyInstall.ps1
Echo ----- Please close AVL. Reopen it to use Chocolatey.
pause
For /d %%A in (%FolderDel%*) do rmdir /s /q "%%A"
Del %File%
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.A.2
cls
Echo -------------- AVL.A.2 Uninstall Chocolatey --------------
choco --version >nul 2>&1
If "%ErrorLevel%" EQU "0" choco uninstall chocolatey -y
choco --version >nul 2>&1
If "%ErrorLevel%" EQU "0" (Echo Chocolatey is installed.) Else (Echo Chocolatey does not exist.)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:ByChoco
choco list | findstr /I "%1" >Nul 2>&1
If %errorlevel%==0 (Set "%2=Installed") else (Set "%2=Not_Exist")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:ByWhere
Where %1 >Nul 2>&1
If %errorlevel%==0 (Set "%2=Installed") else (Set "%2=Not_Exist")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:ByVersion
%1 %2 >Nul 2>&1
If %errorlevel%==0 (Set "%3=Installed") else (Set "%3=Not_Exist")
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.A.3
cls
Echo ----- AVL.A.3. Check Software Status -----
Echo ----- Checking Git
Call :ByVersion Git --version StatusA
Echo ----- Checking Python
Call :ByVersion Python --version StatusB
Echo ----- Checking Node
Call :ByVersion Node --version StatusC
Echo ----- Checking Java
Call :ByVersion Java -version StatusD
Echo ----- Checking postman
Call :ByChoco postman StatusE
Echo ----- Checking GoogleChrome
Call :ByChoco GoogleChrome StatusF
Echo ----- Checking Firefox
Call :ByChoco Firefox StatusG
Echo ----- Checking Opera
Call :ByChoco Opera StatusH
Echo ----- Checking Brave
Call :ByChoco Brave StatusI
Echo ----- Checking Tor-Browser
Call :ByChoco Tor-Browser StatusJ
Echo ----- Checking Skype
Call :ByChoco Skype StatusK
Echo ----- Checking Zoom
Call :ByChoco Zoom StatusL
Echo ----- Checking Discord
Call :ByChoco Discord StatusM
Echo ----- Checking Telegram
Call :ByChoco Telegram StatusN
Echo ----- Checking WhatsApp
Call :ByChoco WhatsApp StatusO
Echo ----- Checking 7zip
Call :ByChoco 7zip StatusP
Echo ----- Checking WinRAR
Call :ByChoco WinRAR StatusQ
Echo ----- Checking Malwarebytes
Call :ByChoco Malwarebytes StatusR
Echo ----- Checking Bitdefender
Call :ByChoco Bitdefender StatusS
Echo ----- Checking Kaspersky Virus Removal Tool
Call :ByChoco KVRT StatusT
Echo ----- Checking Eset-Nod32-Antivirus
Call :ByChoco Eset-Nod32-Antivirus StatusU
Echo ----- Checking Eset-Internet-Security
Call :ByChoco Eset-Internet-Security StatusV
Echo ----- Checking Eset-Antivirus
Call :ByChoco Eset-Antivirus StatusW
Echo ----- Checking Notepadplusplus
Call :ByChoco Notepadplusplus StatusX
Echo ----- Checking HWinfo
Call :ByChoco HWinfo StatusY
Echo ----- Checking KLiteCodecPackFull
Call :ByChoco KLiteCodecPackFull StatusZ
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.A.4
cls
Echo ------ AVL.A.4. ChocolateyGUI ------
choco install chocolateygui
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.A.5
cls
Echo ---- AVL.A.5. Recommend some commands to install software by Chocolatey ----
Echo choco install space-sniffer       :: Folder size analyzer
Echo choco install treesizefree        :: Check disk space usage visually
Echo choco install crystaldiskinfo     :: Monitor hard drive health
Echo choco install crystaldiskmark     :: Benchmark disk speed
Echo choco install processhacker       :: Advanced Task Manager alternative
Echo choco install sysinternals        :: Microsoft Sysinternals utilities pack
Echo choco install rufus               :: Create bootable USB drives
Echo choco install ddu                 :: Display Driver Uninstaller
Echo choco install nircmd              :: Small command-line utility with many features
Echo choco install partitionwizard     :: Disk partition management tool
Echo choco install autoruns            :: Advanced startup manager (from Sysinternals)
Echo choco install gpu-z               :: GPU information utility
Echo choco install fastcopy            :: Fast file copy/move utility
Echo choco install winmerge            :: Compare - merge files/folders
Echo choco install chocolateygui       :: GUI For Echo chocolatey package management
Echo choco install bat                 :: Better `cat` command For Windows (syntax highlighting)
Echo choco install sqlite              :: SQLite command-line tool
Echo choco install mysql               :: MySQL Database server
Echo choco install redis-64            :: Redis server For Windows
Echo choco install curl                :: Command-line HTTP client
Echo choco install vscode              :: Visual Studio Code (lightweight code editor)
Echo choco install vlc                 :: VLC Media Player (Highly recommended)
Echo choco install mpv                 :: MPV Player (Lightweight - powerful)
Echo choco install potplayer           :: PotPlayer (Advanced video player)
Echo choco install k-litecodecpackmega :: K-Lite Mega Codec Pack (For codecs)
Echo choco install musicbee            :: MusicBee (Music player - organizer)
Echo choco install spotify             :: Spotify Desktop App
Echo choco install cdburnerxp          :: CD/DVD burning tool
Echo choco install audacity            :: Audio editor - recorder
Echo choco install obs-studio          :: Screen recorder - streaming tool
Echo choco install handbrake           :: Video transcoder - converter
Echo choco install freac               :: Audio converter
Echo choco install mediainfo           :: Media file information analyzer
Echo choco install losslesscut         :: Simple - fast video/audio cutter
Echo choco install shotcut             :: Open-source video editor
Echo choco install mkvtoolnix          :: MKV file toolkit
Echo choco install ffmpeg              :: Command-line media toolkit
Echo choco install idm                 :: Internet Download Manager (Trial/Paid)
Echo choco install freedownloadmanager :: Free Download Manager (Free)
Echo choco install aria2               :: Aria2 - Lightweight multi-connection downloader
Echo choco install uget                :: uGet - Advanced download manager
Echo choco install motrix              :: Motrix - Simple, powerful downloader
Echo choco install persepolis          :: Persepolis Download Manager (GUI For Aria2)
Echo choco install jdownloader         :: JDownloader 2 - Universal downloader
Echo choco install qbitTorrent         :: qBittorrent - Torrent client
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.A.6
Set "AVLBackMenu=AVL.A.Menu"
cls
Echo -------- AVL.A.6. Download Google Sharing URL by Gdown (Python) --------
Echo ----- Chocolatey Status: %ChocolateyStatus%
If %ChocolateyStatus%==Not_Exist (Goto AVL.A.1) & Exit
Call :ByVersion Python --version StatusB
Echo ----- Python Status: %StatusB%
If %StatusB%==Not_Exist (choco install Python) & Exit
Call :ByVersion gdown --version GdownStatus
If %GdownStatus%==Not_Exist (pip install gdown) & Exit
Echo ----- Gdown Status: %GdownStatus%
Echo [1] Download Air Explorer 4.0.1
Echo [2] Download Windows SKUS
Echo [3] Download Office SKUS
Echo [4] Download WinToHDD 6.6.1
Echo [5] Download M.A.S 3.0
Echo (Input nothing to exit)
Set /p "URLInput=----- Input Google Sharing URL to download ? " 
If not defined URLInput (Goto !AVLBackMenu!)
If "%URLInput%"=="1" Set "URLInput=https://drive.google.com/file/d/1v-e357584LvPnABuOhk86m52WRBPBtqs/view?usp=drivesdk"
If "%URLInput%"=="2" Set "URLInput=https://drive.google.com/file/d/15CJxdXHcVlSWmw8wUGGklfCMOUNjdury/view?usp=drivesdk"
If "%URLInput%"=="3" Set "URLInput=https://drive.google.com/file/d/1d91wPZozqiSsW2pMH6XsjhZzUduz-80t/view?usp=drivesdk"
If "%URLInput%"=="4" Set "URLInput=https://drive.google.com/file/d/13KAYfm2ChIT4G7s4oCqkWp0hIqZsMWTQ/view?usp=drivesdk"
If "%URLInput%"=="5" Set "URLInput=https://drive.google.com/file/d/1uLf-jO7ouJg_t3emxojEBDM1ZxGAOEyc/view?usp=drivesdk"
Echo Please Wait ...
Set "URLInput=!URLInput:usercontent.=!"
Set "URLInput=!URLInput:docs.google.com=drive.google.com!"
Gdown --fuzzy "!URLInput!"
Call :AVLTemplate %DefaultTemplate%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B
If %WinVer% GTR 22000 (
	Set "te="
	For /F "delims=\ tokens=6" %%b in ('Reg query "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"') do Set "te=%%b"
	If "%te%" EQU "InprocServer32" (Set "Status=ON") Else (Set "Status=OFF")
)
Set "AVLBackMenu=AVL.B"
cls
Echo ----------------- AVL.B. Context Menu -----------------
Echo   Classic Context Menu Status: %Status%
Echo   [1] Turn OFF Classic Context Menu (Only Windows 11)
Echo   [2] Turn ON Classic Context Menu (Only Windows 11)
Echo   [3] Add "Open CMD here" to Context Menu
Echo   [4] Remove "Open CMD here" from Context Menu
Echo   [5] Install "Smart Context Menu"
Echo   [6] Install "Smart System Menu"
Echo   [7] Reset Explorer
Echo   [0] Return to the previous menu
CHOICE /c 12345670 /n /m "---------- (^_^) Your Wishes Come True (^_^) ----------"
Set /A Index=%ErrorLevel%-1
Set "List=12345670"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.B.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B.1
Echo --------- AVL.B.1. Turn OFF Classic Context Menu ---------
Reg delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B.2
Echo --------- AVL.B.2. Turn ON Classic Context Menu ---------
Reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B.3
cls
Echo --------- AVL.B.3. Add "Open CMD here" to Context Menu ---------
:: For right-clicking ON a folder
reg add "HKEY_CLASSES_ROOT\Directory\shell\open_cmd_admin" /ve /d "Open CMD here (Admin)" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\open_cmd_admin" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\open_cmd_admin\command" /ve /d "powershell.exe -windowstyle hidden -command \"Start-Process cmd.exe -ArgumentList '/s /k pushd \\\"%%V\\\"' -Verb RunAs\"" /f
:: For right-clicking INSIDE a folder (on the background)
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\open_cmd_admin" /ve /d "Open CMD here (Admin)" /f
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\open_cmd_admin" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\open_cmd_admin\command" /ve /d "powershell.exe -windowstyle hidden -command \"Start-Process cmd.exe -ArgumentList '/s /k pushd \\\"%%V\\\"' -Verb RunAs\"" /f
Call :AVL.Finish "Context menu added. Restart Explorer to apply the change"

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B.4
Echo --------- AVL.B.4. Remove "Open CMD here" from Context Menu ---------
reg delete "HKEY_CLASSES_ROOT\Directory\shell\open_cmd_admin" /f
reg delete "HKEY_CLASSES_ROOT\Directory\Background\shell\open_cmd_admin" /f
Call :AVL.Finish "Restart Explorer to apply the change"

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B.5
cls
Echo -------------- AVL.B.5. Smart Menu Context --------------
Echo ----- Getting the latest Version
Set "URL=https://github.com/AlexanderPro/SmartContextMenu/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set "URL=https://github.com/AlexanderPro/SmartContextMenu/releases/download/%t1%/SmartContextMenu_%t1%.zip"
del a.txt
Set "File=SmartContextMenu.zip"
Set "FileDel=%File%"
Set "FolderDel=SmartContextMenu"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command Expand-Archive -LiteralPath "%File%"
xcopy "SmartContextMenu" "%SystemDrive%\SmartContextMenu" /E /I /H /Y
Echo ----- Running SmartContextMenu
Start %SystemDrive%\SmartContextMenu\SmartContextMenu.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B.6
cls
Echo -------------- AVL.B.6. Smart System Menu --------------
Echo ----- Getting the latest Version
Set "URL=https://github.com/AlexanderPro/SmartSystemMenu/releases/latest"
Set "File=a.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1:"=%
Set t1=%t1: =%
Set "URL=https://github.com/AlexanderPro/SmartSystemMenu/releases/download/%t1%/SmartSystemMenu_%t1%.zip"
Del a.txt
Set "File=SmartSystemMenu.zip"
Set "FileDel=%File%"
Set "FolderDel=SmartContextMenu"
Call :AVLDownload
Echo ----- Extracting %File%
Powershell -command "Expand-Archive -LiteralPath '%File%' '%SystemDrive%\SmartSystemMenu'
Echo ----- Running SmartSystemMenu
Start %SystemDrive%\SmartSystemMenu\SmartSystemMenu.exe"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.B.7
Echo --------- AVL.B.7. Reset Explorer ---------
taskkill /f /im explorer.exe && Start explorer.exe
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C
If %winver% Lss 22000 (Goto AVL.C.win10) else (Goto AVL.C.win11)

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10
Set "AVLBackMenu=AVL.C.win10"
cls
Echo ----------- AVL.C. Taskbar Setting -----------
Echo   [1] Turn Off News And Interests
Echo   [2] Turn On News And Interests
Echo   [3] Show All Icons on Taskbar
Echo   [4] Hide All Icons on Taskbar
Echo   [5] Only Search Icon on Taskbar
Echo   [6] Show full search box on Taskbar
Echo   [7] Hide search box completely on Taskbar
Echo   [8] Unpin Store from Taskbar
Echo   [9] Set Short-Date to yyyy-MM-dd
Echo   [A] Set Short-Time to hh:mm tt
Echo   [B] Set Time-Zone Automatically
Echo   [C] Set Time-Zone Manually 
Echo   [D] Set Time-Zone GMT+7 
Echo   [E] Sync Time Immediately
Echo   [F] Open Taskbar Setting
Echo   [R] Reset Explorer
Echo   [0] Return to the previous Menu
CHOICE /c 123456789ABCDEFR0 /n /m "-------- (^_^) Your Wishes Come True (^_^) --------"
Set /A Index=%ErrorLevel%-1
Set "List=123456789ABCDEFR0"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.C.win10.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.1
Echo ----------- AVL.C.1. Turn Off News And Interests -----------
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.2
Echo ----------- AVL.C.2. Turn On News And Interests -----------
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 0 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.3
Echo ----------- AVL.C.3. Show All Icons on Taskbar -----------
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableAutoTray /t REG_DWORD /d 0 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.4
Echo ----------- AVL.C.4. Hide All Icons on Taskbar -----------
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableAutoTray /t REG_DWORD /d 1 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.5
Echo ----------- AVL.C.5. Only Search Icon on Taskbar -----------
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 1 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.6
Echo ----------- AVL.C.6. Show full search box on Taskbar -----------
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 2 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.7
Echo ----------- AVL.C.7. Hide search box completely on Taskbar -----------
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.8
Echo ----------- AVL.C.8. Unpin Store From Taskbar -----------
Reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v NoPinningStoreToTaskbar /t REG_DWORD /d 1 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.9
Reg add "HKEY_CURRENT_USER\Control Panel\International" /v sShortDate /t REG_SZ /d yyyy-MM-dd /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.A
Reg add "HKEY_CURRENT_USER\Control Panel\International" /v sShortTime /t REG_SZ /d "hh:mm tt" /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.B
Reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v Start /t REG_DWORD /d 2 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.C
Reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v Start /t REG_DWORD /d 4 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.D
tzutil /s "SE Asia Standard Time"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.E
Echo ----------- AVL.C.E. Sync Time Immediately -----------
net Start w32time
w32tm /resync
net stop w32time
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.F
Start ms-settings:taskbar
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win10.R
Echo ----------- AVL.C.R. reset Explorer -----------
taskkill /F /IM explorer.exe
Start explorer
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.win11
Set "AVLBackMenu=AVL.C.win11"
Set "FileDel="
Set "FolderDel="
cls
Echo ---------- AVL.C. Taskbar Settings ----------
Echo   [1] Set Left Align For Taskbar
Echo   [2] Set Center Align For Taskbar
Echo   [3] Turn Off News And Interests
Echo   [4] Turn On News And Interests
Echo   [5] Show All Icons on Taskbar
Echo   [6] Hide All Icons on Taskbar
Echo   [7] Only Search Icon on Taskbar
Echo   [8] Unpin Store From Taskbar
Echo   [9] Set Short-Date to yyyy-MM-dd
Echo   [A] Set Short-Time to hh:mm tt
Echo   [B] Set Time-Zone Automatically
Echo   [C] Set Time-Zone Manually 
Echo   [D] Set Time-Zone GMT+7 
Echo   [E] Sync Time Immediately
Echo   [F] Open Taskbar Setting
Echo   [R] Reset Explorer
Echo   [0] Return to the previous Menu
CHOICE /c 123456789ABCDEFR0 /n /m "----- (^_^) Your Wishes Come True (^_^) -----"
Set /A Index=%ErrorLevel%-1
Set "List=123456789ABCDEFR0"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.C.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.1
Echo ----------- AVL.C.1. Set Left Align For Taskbar -----------
Reg add hkcu\software\microsoft\windows\currentversion\explorer\advanced /v TaskbarAl /t REG_DWORD /f /d 0
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.2
Echo ----------- AVL.C.2. Set Center Align For Taskbar -----------
Reg add hkcu\software\microsoft\windows\currentversion\explorer\advanced /v TaskbarAl /t REG_DWORD /f /d 1
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.3
Echo ----------- AVL.C.3. Turn Off News And Interests -----------
Reg add "HKLM\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.4
Echo ----------- AVL.C.4. Turn On News And Interests -----------
Reg add "HKLM\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "1" /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.5
Echo ----------- AVL.C.5. Show All Icons on Taskbar -----------
For /F "Delims=\ tokens=4" %%b in ('Reg query "HKEY_CURRENT_USER\Control Panel\NotifyIconSettings" ^| findstr /b /c:"HKEY_CURRENT_USER"') do (
	Reg add "HKEY_CURRENT_USER\Control Panel\NotifyIconSettings\%%b" /v "IsPromoted" /t REG_DWORD /f /d 1
) 
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.6
Echo ----------- AVL.C.6. Hide All Icons on Taskbar -----------
For /F "Delims=\ tokens=4" %%b in ('Reg query "HKEY_CURRENT_USER\Control Panel\NotifyIconSettings" ^| findstr /b /c:"HKEY_CURRENT_USER"') do (
	Reg add "HKEY_CURRENT_USER\Control Panel\NotifyIconSettings\%%b" /v "IsPromoted" /t REG_DWORD /f /d 0
) 
Echo Hide All Icons on Taskbar successfully ...
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.7
Echo ----------- AVL.C.7. Only Search Icon on Taskbar -----------
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.8
Echo ----------- AVL.C.8. Unpin Store From Taskbar -----------
Reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v NoPinningStoreToTaskbar /t REG_DWORD /d 1 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.9
Reg add "HKEY_CURRENT_USER\Control Panel\International" /v sShortDate /t REG_SZ /d yyyy-MM-dd /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.A
Reg add "HKEY_CURRENT_USER\Control Panel\International" /v sShortTime /t REG_SZ /d "hh:mm tt" /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.B
Reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v Start /t REG_DWORD /d 2 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.C
Reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v Start /t REG_DWORD /d 4 /f
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.D
tzutil /s "SE Asia Standard Time"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.E
Echo ----------- AVL.C.E. Sync Time Immediately -----------
net Start w32time
w32tm /resync
net stop w32time
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.F
CLS
Echo ----------- AVL.C.9. Open Taskbar Setting -----------
Start ms-settings:taskbar
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.C.R
Echo ----------- AVL.C.R. reset Explorer (Apply Setting) -----------
taskkill /f /im explorer.exe
Start explorer.exe
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D
Set "AVLBackMenu=AVL.D"
Set "FileDel="
Set "FolderDel="
cls
Echo ----------- AVL.D. Windows Security Setting -----------
Echo   [1] Disable User Account Control (UAC)
Echo   [2] Enable User Account Control (UAC)
Echo   [3] Disable SmartScreen in Internet Explorer
Echo   [4] Enable SmartScreen in Internet Explorer
Echo   [5] Disable SmartScreen in Edge
Echo   [6] Enable SmartScreen in Edge
Echo   [7] Disable SmartScreen on file AppHost Explorer
Echo   [8] Enable SmartScreen on file AppHost Explorer
Echo   [A] Disable SmartScreen on Windows Defender
Echo   [B] Enable SmartScreen on Windows Defender
Echo   [C] Disable All SmartScreen settings
Echo   [D] Enable All SmartScreen settings
Echo   [E] Download Disable-Defender App
Echo   [F] Download Defender-Remover App
Echo   [G] Download Edge-Remover App
Echo   [H] ReStart Windows to Apply New Settings
Echo   [0] Return to the previous menu
CHOICE /c 12345678ABCDEFGH0 /n /m "---------- (^_^) Your Wishes Come True (^_^) ----------"
Set /A Index=%ErrorLevel%-1
Set "List=12345678ABCDEFGH0"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.D.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.1
CLS
Echo ----------- AVL.D.1. Disable User Account Control (UAC) -----------
Echo Disable User Account Control ...
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.2
CLS
Echo ----------- AVL.D.2. Enable User Account Control (UAC) -----------
Echo Enable User Account Control ...
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.3
CLS
Echo ----------- AVL.D.3. Disable SmartScreen in Internet Explorer -----------
Echo Disable SmartScreen in Internet Explorer
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.4
CLS
Echo ----------- AVL.D.4. Enable SmartScreen in Internet Explorer -----------
Echo Enable SmartScreen in Internet Explorer
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Warn" /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.5
CLS
Echo ----------- AVL.D.5. Disable SmartScreen in Edge -----------
Echo Disable SmartScreen in Egde
reg.exe ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.6
CLS
Echo ----------- AVL.D.6. Enable SmartScreen in Edge -----------
Echo Enable SmartScreen in Egde
reg.exe ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1  /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.7
CLS
Echo ----------- AVL.D.7. Disable SmartScreen on file AppHost Explorer -----------
Echo Disable SmartScreen on file AppHost Explorer
reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.8
CLS
Echo ----------- AVL.D.8. Enable SmartScreen on file AppHost Explorer -----------
Echo Enable SmartScreen on file AppHost Explorer
reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 1 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.A
CLS
Echo ----------- AVL.D.A. Disable SmartScreen on Windows Defender -----------
Echo Disable SmartScreen on file Windows Defender
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.B
CLS
Echo ----------- AVL.D.B. Enable SmartScreen on Windows Defender -----------
Echo Enable SmartScreen on file Windows Defender
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.C
CLS
Echo ----------- AVL.D.C. Disable All SmartScreen settings -----------
Echo Disable All SmartScreen settings
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg.exe ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f
reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.D
CLS
Echo ----------- AVL.D.D. Enable All SmartScreen settings -----------
Echo Enable All SmartScreen settings
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Warn" /f
reg.exe ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 1 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.E
CLS
Echo ----------- AVL.D.E. Download Disable-Defender App -----------
Echo Download Disable Defender App. Password to Extract: sordum
Start https://www.sordum.org/downloads/?st-defender-control
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.F
cls
Echo ----------- AVL.D.F. Download Defender-Remover App -----------
Start "" "https://github.com/ionuttbara/windows-defender-remover/releases/latest"
Echo Download and run DefenderRemover.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.G
CLS
Echo ----------- AVL.D.G. Download Edge-Remover App -----------
Start "" "https://github.com/ShadowWhisperer/Remove-MS-Edge"
Echo Download and run Remove-Edge.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.D.H
CLS
Echo ----------- AVL.D.H. ReStart Windows to Apply New Settings -----------
Echo ReStart Computer ...
Shutdown /r /c "For apply new setting" && Exit
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E
Set "AVLBackMenu=AVL.E"
Set "FileDel="
Set "FolderDel="
cls
Echo ------------------- AVL.E. Windows Setting ------------------
Echo   [1] About Setting                [B] Run Disk Clean-up
Echo   [2] Add-Remove Programs          [C] StartUp Apps Setting
Echo   [3] Computer Management          [D] Storage Setting
Echo   [4] Desktop Icon Setting         [E] System Configuration
Echo   [5] Disk Management              [F] System Information 
Echo   [6] File Explorer Options        [G] Task Manager
Echo   [7] Rename Computer Name         [H] Task Scheduler
Echo   [8] Resource Monitor             [I] Troubleshooting
Echo   [9] Reset Explorer               [K] User Account Control
Echo   [A] Reset Network                [L] Windows Features
Echo   [0] Return to the previous menu  [M] Windows Version
CHOICE /c 0123456789ABCDEFGHIKLM /n /m "------------- (^_^) Your Wishes Come True (^_^) -------------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDEFGHIKLM"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.E.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.1
Echo -------- AVL.E.1. About Setting --------
Start ms-settings:about
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.2
Echo -------- AVL.E.2. Add-Remove Programs --------
Start ms-settings:appsfeatures
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.3
Echo -------- AVL.E.3. Computer Management --------
Start compmgmt.msc
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.4
Echo -------- AVL.E.4. Desktop Icon Setting --------
Start rundll32 shell32.dll,Control_RunDLL desk.cpl,,0
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.5
Echo -------- AVL.E.5. Disk Management --------
Start diskmgmt.msc
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.6
Echo -------- AVL.E.6. File Explorer Options --------
Start rundll32.exe shell32.dll,Options_RunDLL 7
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.7
cls
Echo -------- AVL.E.7. Rename Computer Name --------
Echo Current Computer Name: %COMPUTERNAME%
Set "NewPCName="
Set /p "NewPCName=> Input new name for PC: "
powershell -Command "Rename-Computer -NewName 'NewPCName'"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.8
Echo -------- AVL.E.8. Resource Monitor --------
Start resmon.exe
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.9
CLS
Echo -------- AVL.E.9. reset Explorer --------
taskkill /f /im explorer.exe
Start explorer.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.A
CLS
Echo -------- AVL.E.A. reset Network --------
ipconfig /flushdns
ipconfig /release
ipconfig /renew
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.B
CLS
Echo -------- AVL.E.B. Run Disk Clean-up --------
cleanmgr /verylowdisk /sagerun:5
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.C
Echo -------- AVL.E.C. StartUp Apps Setting --------
Start ms-settings:startupapps
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.D
Echo -------- AVL.E.D. Storage Setting --------
Start ms-settings:storagesense
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.E
Echo -------- AVL.E.E. System Configuration --------
Start msconfig
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.F
Echo -------- AVL.E.F. System Information --------
Start Msinfo32
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.G
Echo -------- AVL.E.G. Task Manager --------
Start taskmgr
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.H
Echo -------- AVL.E.H. Task Scheduler  --------
Start taskschd.msc
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.I
Echo -------- AVL.E.I. Troubleshooting --------
Start ms-settings:troubleshoot
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.K
Echo -------- AVL.E.K. User Account Control --------
Start UserAccountControlSettings.exe
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.L
Echo -------- AVL.E.L. Windows Features  --------
Start rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl,,2
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.E.M
cls
Echo -------- AVL.E.M. Windows Version --------
Start winver.exe
CHOICE /c Y0123456789ABCDEFGHIJKLMNOPQRSTUVWXZ /n /m "> Do you want to change name of User and Org ? To proceed, type Y and press Enter: "
If %ErrorLevel% NEQ 1 Goto !AVLBackMenu!
Set "User1="
Set /p "User1=> Input Username: "
Set /p "Org1=> Input Organization Name: "
If not "%User1%"=="" (reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "%User1%" /f)
If not "%Org1%"=="" (reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "%Org1%" /f)
taskkill /f /im winver.exe
Start winver.exe
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F
Set "AVLBackMenu=AVL.F"
Set "FileDel="
Set "FolderDel="
cls
Echo ----------- AVL.F. Windows Update Setting -----------
Echo   [1] Disable Windows Update
Echo   [2] Enable Windows Update
Echo   [3] Disable "Get the latest updates ..."
Echo   [4] Enable "Get the latest updates ..."
Echo   [5] Download Disable-Windows-Update App
Echo   [6] Open Windows Update Setting
Echo   [7] Restart Windows
Echo   [0] Return to the previous menu
CHOICE /c 12345670 /n /m "--------- (^_^) Your Wishes Come True (^_^) ---------"
Set /A Index=%ErrorLevel%-1
Set "List=12345670"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.F.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F.1
CLS
Echo ----------- AVL.F.1. Disable Windows Update -----------
Echo Disable Windows Update ...
Sc config wuauserv start= disabled
net stop wuauserv
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 1 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F.2
CLS
Echo ----------- AVL.F.2. Enable Windows Update -----------
Echo Enable Windows Update ...
sc config wuauserv start= auto
net Start wuauserv
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 0 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F.3
CLS
Echo ----------- AVL.F.3. Disable "Get the latest updates ..." -----------
Echo Disable "Get the latest updates as soon as they are available" ...
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 0 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F.4
CLS
Echo ----------- AVL.F.4. Enable "Get the latest updates ..." -----------
Echo Enable "Get the latest updates as soon as they are available"
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 1 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F.5
CLS
Echo ----------- AVL.F.5. Download Disable-Windows-Update App -----------
Echo Download Windows-Update-Blocker App...
Start https://www.sordum.org/downloads/?st-windows-update-blocker
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F.6
CLS
Echo ----------- AVL.F.6. Open Windows Update Setting -----------
Start ms-settings:windowsupdate
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.F.7
CLS
Echo ----------- AVL.F.7. ReStart Windows to Apply New Settings -----------
Echo ReStart Computer ...
Shutdown /r /c "For apply new setting" && Exit
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G
Set "AVLBackMenu=AVL.G"
Set "FileDel="
Set "FolderDel="
cls
Echo -------------------------------- AVL.G. Windows Utility -------------------------------
Echo   [1] Backup Desktop, Documents, Downloads...        [C] GTweak
Echo   [2] Battery Report                                 [D] Uninstall App-Packages
Echo   [3] Clear Browser History                          [E] Repair Kit
Echo   [4] Create autounattend.xml Online                 [F] Set Template to Excel, Word
Echo   [5] Create autounattend.xml by UnattendedWinstall  [G] Win11Debloat
Echo   [6] Create Office Shortcuts to Desktop             [H] Windows Optimize
Echo   [7] Delete Temp Files                              [I] Windows PowerToys
Echo   [8] Disable Internet Explorer                      [J] Windows Utility
Echo   [9] Empty Recycle Bin                              [K] WinScript
Echo   [A] Enable Dark Mode                               [L] WinToys
Echo   [B] Enable WMIC Tool                               [M] WinUtil
Echo   [0] Return to the previous menu
CHOICE /c 0123456789ABCDEFGHIJKLMN /n /m "-------------------------- (^_^) Your Wishes Come True (^_^) --------------------------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789ABCDEFGHIJKLMN"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.G.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.1
CLS
Echo -------- AVL.G.1. Backup Desktop, Documents, Downloads, Music, Pictures, Videos --------
If not exist "%~dp0DATA" md "%~dp0DATA"
If not exist "%~dp0DATA\Desktop" md "%~dp0DATA\Desktop"
If not exist "%~dp0DATA\Documents" md "%~dp0DATA\Documents"
If not exist "%~dp0DATA\Downloads" md "%~dp0DATA\Downloads"
If not exist "%~dp0DATA\Music" md "%~dp0DATA\Music"
If not exist "%~dp0DATA\Pictures" md "%~dp0DATA\Pictures"
If not exist "%~dp0DATA\Videos" md "%~dp0DATA\Videos"
xcopy "%USERPROFILE%\Desktop" "%~dp0DATA\Desktop" /e /h /q
xcopy "%USERPROFILE%\Documents" "%~dp0DATA\Documents" /e /h /q
xcopy "%USERPROFILE%\Downloads" "%~dp0DATA\Downloads" /e /h /q
xcopy "%USERPROFILE%\Music" "%~dp0DATA\Music" /e /h /q
xcopy "%USERPROFILE%\Pictures" "%~dp0DATA\Pictures" /e /h /q
xcopy "%USERPROFILE%\Videos" "%~dp0DATA\Videos" /e /h /q
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.2
CLS
Echo -------- AVL.G.2. Battery Report --------
If exist "BatteryReport.html" del "BatteryReport.html" 
powercfg /batteryreport /output "%~dp0BatteryReport.html"
Start "" "%~dp0BatteryReport.html"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.3
CLS
Echo -------- AVL.G.3. Clear Browser History (Chrome, Edge, Firefox, Coccoc) --------
del /q /s "%LocalAppData%\Google\Chrome\User Data\Default\History"
del /q /s "%LocalAppData%\Google\Chrome\User Data\Default\Cache\*.*"
del /q /s "%LocalAppData%\Google\Chrome\User Data\Default\Cookies"
del /q /s "%LocalAppData%\Microsoft\Edge\User Data\Default\History"
del /q /s "%LocalAppData%\Microsoft\Edge\User Data\Default\Cache\*.*"
del /q /s "%LocalAppData%\Microsoft\Edge\User Data\Default\Cookies"
del /q /s "%APPDATA%\Mozilla\Firefox\Profiles\*.default\places.sqlite"
del /q /s "%APPDATA%\Mozilla\Firefox\Profiles\*.default\cache2\entries\*.*"
del /q /s "%LocalAppData%\Coccoc\Browser\User Data\Default\History"
del /q /s "%LocalAppData%\Coccoc\Browser\User Data\Default\Cache\*.*"
del /q /s "%LocalAppData%\Coccoc\Browser\User Data\Default\Cookies"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.4
CLS
Echo -------- AVL.G.4. Create autounattend.xml Online --------
Start "" "https://schneegans.de/windows/unattend-generator/"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.5
CLS
Echo -------- AVL.G.5. Create autounattend.xml by UnattendedWinstall --------
Set "URL=https://github.com/memstechtips/WIMUtil/raw/main/src/WIMUtil.ps1"
Set "File=WIMUtil.ps1"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Powershell .\%File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.6
CLS
Echo -------- AVL.G.6. Create Office Shortcuts --------
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Word*.lnk" "%AllUsersProfile%\Desktop"
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Excel*.lnk" "%AllUsersProfile%\Desktop"
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Power*.lnk" "%AllUsersProfile%\Desktop"
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Visio*.lnk" "%AllUsersProfile%\Desktop"
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Project*.lnk" "%AllUsersProfile%\Desktop"
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Access*.lnk" "%AllUsersProfile%\Desktop"
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Onedrive*.lnk" "%AllUsersProfile%\Desktop"
COPY /Y "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Teams*.lnk" "%AllUsersProfile%\Desktop"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.7
CLS
Echo -------- AVL.G.7. Delete Temp Files --------
del /s /f /q c:\windows\temp\*.*
del /s /f /q C:\WINDOWS\Prefetch
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.8
CLS
Echo -------- AVL.G.8. Disable Internet Explorer --------
dism /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0.
dism /online /disable-feature /featurename:Internet-Explorer-Optional-amd64 /norestart
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Internet Explorer" /v "SystemComponent" /t REG_DWORD /d 1 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.9
CLS
Echo -------- AVL.G.9. Empty Recycle Bin --------
Powershell -ExecutionPolicy Unrestricted -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10); $bin.items() | ForEach {; Write-Host "^""Deleting $($_.Name) from Recycle Bin"^""; Remove-Item $_.Path -Recurse -Force; }"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.A
CLS
Echo -------- AVL.G.A. Enable Dark Mode --------
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f
If %WinVer% GEQ 22000 (
	Reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\Windows\Web\Wallpaper\Windows\img19.jpg" /f
	RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters
)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.B
CLS
Echo -------- AVL.G.B. Enable WMIC Tool --------
Echo Check WMIC ...
If not exist "%windir%\System32\wbem\WMIC.exe" (
	Echo WMIC is Disable 
	Echo Adding WMIC to Windows ...
	DISM /Online /Add-Capability /CapabilityName:WMIC~~~~
) Else (Echo WMIC is Available)
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.C
CLS
Echo -------- AVL.G.C. GTweak --------
Set "URL=https://github.com/Greedeks/GTweak/releases/latest"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" v.txt') do Set t1=%%a
Echo %t1%
Set t1=%t1:"=%
Set t1=%t1: =%
Del v.txt
Set "URL=https://github.com/Greedeks/GTweak/releases/download/%t1%/GTweak.exe"
Set "File=GTweak.exe"
Set "FileDel=%File%"
Set "FolderDel=RepairKit"
Call :AVLDownload
Echo ----- Running GTweak
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.D
cls
Echo -------- AVL.G.D. Uninstall App-Packages --------
Powershell "Get-AppxPackage | Select PackageFullName | Sort PackageFullName"
Goto AVL.G.D.Remove

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.D.Remove
Set "Package="
Set /p "Package=Input PackageFullName (Enter Nothing To Exit):"
If "!Package!" EQU "" Goto AVL.G
Powershell "Remove-AppxPackage %Package%"
Goto AVL.G.D.Remove

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.E
CLS
Echo -------- AVL.G.E. Repair Kit --------
Set "URL=https://github.com/Foulest/RepairKit/releases/latest"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" v.txt') do Set t1=%%a
Echo %t1%
Set t1=%t1:"=%
Set t1=%t1: =%
Del v.txt
Set "URL=https://github.com/Foulest/RepairKit/releases/download/%t1%/RepairKit-%t1%.zip"
Set "File=RepairKit.zip"
Set "FileDel=%File%"
Set "FolderDel=RepairKit"
Call :AVLDownload
Powershell -command Expand-Archive -LiteralPath "%File%"
Echo ----- Running Repair Kit
For /r "RepairKit" %%f in (RepairKit*.exe) do @Start "" /D"RepairKit" "%%~nxf"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.F
CLS
Echo -------- AVL.G.F. Set Standard Template For Excel, Word --------
Echo Set Template to Microsoft Excel ...
Echo + Font     : Times New Roman
Echo + Font Size: 14
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Options" /v Font /t REG_SZ /d "Times New Roman,14" /f
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Options" /v DefFontName /t REG_SZ /d "Times New Roman" /f
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Options" /v DefFontSize /t REG_DWORD /d 14 /f
Echo --------
Echo Set Template to Microsoft Word ...
Echo + Font         : Times New Roman
Echo + Font Size    : 14
Echo + Alignment    : Justified
Echo + Page Margin  : 1
Echo + Page Size    : A4
Echo + Space Before : 6
Echo + Space After  : 0
Echo + First Line   : 0.5cm
Set "URL=%NormalURL%"
Set "File=Normal.dotm"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
If exist "%AppData%\Microsoft\Templates" xcopy "%~dp0Normal.dotm" "%AppData%\Microsoft\Templates" /e /h /r /y
Echo --------
Echo Close Word, Excel. ReOpen them to apply new Template ...
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.G
CLS
Echo -------- AVL.G.G. Win11Debloat --------
Set "URL=https://github.com/Raphire/Win11Debloat/releases/latest"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" v.txt') do Set t1=%%a
Echo %t1%
Set t1=%t1:"=%
Set t1=%t1: =%
Del v.txt
Set "URL=https://github.com/Raphire/Win11Debloat/releases/download/%t1%/Get.ps1"
Set "File=Win11Debloat.ps1"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start Powershell .\%File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.H
CLS
Echo -------- AVL.G.H. Windows Optimize --------
Set /p "Ans3=> To proceed, type Y and press Enter: "
If /i %Ans3% NEQ "y" Call :AVL.Finish ""

Echo ----- Modify Task Manager settings For Windows versions older than 22557
For /f "tokens=4-5 delims=[]. " %%i in ('ver') do Set "winver=%%i.%%j"
If "%winver%" lss "22557" (
    Start "" /min taskmgr.exe
    :loop
    ping -n 1 127.0.0.1 > nul
    Reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v Preferences > nul 2>&1
    If %errorlevel% equ 0 (
        taskkill /f /im taskmgr.exe
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v Preferences /t REG_BINARY /d 0 /f
    ) else (
        goto loop
    )
)

Echo ----- Disable Telemetry via Registry
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d "0" /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d "1" /f
Reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d "1" /f
Reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d "1" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d "0" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d "4294967295" /f
Reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d "1" /f
Reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v Start /t REG_DWORD /d "2" /f
Reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "400" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d "30" /f
Reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d "0" /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d "2" /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d "6" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f

Echo ----- Group svchost.exe processes
For /f "skip=1 tokens=1" %%a in ('wmic computersystem get totalphysicalmemory') do Set "ram=%%a"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d %ram% /f

Echo ----- Disable Scheduled Tasks
schtasks /change /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /change /tn "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /change /tn "Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /change /tn "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
schtasks /change /tn "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\MareBackup" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable
schtasks /change /tn "Microsoft\Windows\Maps\MapsUpdateTask" /disable

Echo ----- Disable Hibernate
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowHibernateOption /t REG_DWORD /d 0 /f
powercfg.exe /hibernate off

Echo ----- Disable GameDVR
Reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
Reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
Reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
Reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
Reg add "HKCU\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f

Echo ----- Disable Telemetry...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

REM Disable Advertising ID
Echo !BRIGHT_WHITE!Disable Advertising ID...
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f

Echo ----- Disable Wi-Fi Sense
Reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0 /f
Reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0 /f

Echo ----- Disable Activity Feed
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f

Echo ----- Disable Storage Sense
Reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /f

Echo ----- Delete Temporary Files
rd /s /q C:\Windows\Temp
rd /s /q %TEMP%
rd /s /q C:\Windows\Prefetch
del /q /s /f "%LocalAppData%\Microsoft\Windows\INetCache\*.*" > nul
rd /s /q %LocalAppData%\Microsoft\Windows\INetCache
rd /s /q %SystemDrive%\$Recycle.Bin
net stop wuauserv
rd /s /q C:\Windows\SoftwareDistribution
net Start wuauserv
For /F "tokens=*" %%G in ('wevtutil el') do (wevtutil cl "%%G")
rd /s /q C:\ProgramData\Microsoft\Windows\WER\ReportQueue
rd /s /q C:\ProgramData\Microsoft\Windows\WER\ReportArchive
rd /s /q C:\Windows.old
rd /s /q "%LocalAppData%\DirectX Shader Cache"
del /f /s /q /a "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db"

Echo ----- Disable Diagnostic Data...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 0 /f

Echo ----- Disable Handwriting Data Sharing...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f

Echo ----- Disable Windows Hello Biometrics...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v Enabled /t REG_DWORD /d 0 /f

Echo ----- Disable Timeline Function...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f

Echo ----- Disable Location Tracking...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f

Echo ----- Disable Feedback Notifications...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

Echo ----- Disable Windows Tips...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f

Echo ----- Disable Lock Screen Ads...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f

Echo ----- Disable Automatic Installation of Apps...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f

Echo ----- Disable Start Menu App Suggestions...
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f

Echo ----- Disable Setting App Ads...
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f

Echo ----- Disable Customer Experience Improvement Program...
Reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f

Echo ----- Disable Help Experience Program...
Reg add "HKLM\SOFTWARE\Policies\Assist" /v NoImplicitFeedback /t REG_DWORD /d 1 /f

Echo ----- Disable Experimental Features...
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\FlightSettings" /v UserPreferredRedirectStage /t REG_DWORD /d 0 /f

Echo ----- Disable Inventory Collector...
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

Echo ----- Disable Get More Out of Windows...
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.I
CLS
Echo -------- AVL.G.I. Windows PowerToys --------
Set "URL=https://github.com/microsoft/PowerToys/releases/latest"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" v.txt') do Set t1=%%a
Echo %t1%
Set t1=%t1:"=%
Set t1=%t1: =%
Set t1=%t1:~1%
Del v.txt
Set "URL=https://github.com/microsoft/PowerToys/releases/download/v%t1%/PowerToysSetup-%t1%-x64.exe"
Set "File=PowerToysSetup.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.J
CLS
Echo -------- AVL.G.J. Windows Utility --------
Set "URL=https://github.com/ChrisTitusTech/winutil/releases/latest"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" v.txt') do Set t1=%%a
Echo %t1%
Set t1=%t1:"=%
Set t1=%t1: =%
Del v.txt
Set "URL=https://github.com/ChrisTitusTech/winutil/releases/download/%t1%/winutil.ps1"
Set "File=winutil.ps1"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start Powershell .\%File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.K
cls
Echo ----------- AVL.G.K. WinScript -----------
Set "URL=https://github.com/flick9000/winscript/releases/latest"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" v.txt') do Set t1=%%a
Echo %t1%
Set t1=%t1:"=%
Set t1=%t1: =%
Del v.txt
Set "URL=https://github.com/flick9000/winscript/releases/download/%t1%/winscript-portable.exe"
Set "File=WinscriptPortable.exe"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start %File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.L
cls
Echo ----------- AVL.G.L. WinToys -----------
For /f "delims=" %%A in ('Powershell -command "(Get-StartApps -Name Wintoys).AppID"') do Set "AppID=%%A"
For /F %%b in ('Powershell -Command $Env:AppID.Length') do Set AppIDLen=%%b
If "%AppIDLen%" GEQ "3" (
	Set "AppID=%AppID:~0,-7%"
	Start "" "shell:AppsFolder\%AppID%^!wintoys"
	Goto !AVLBackMenu!
)
winget install --id 9p8ltpgcbzxd --accept-package-agreements
If "%errorlevel%" NEQ "0" (
	Echo Winget is not available!
	pause
	Goto :AVL.7.U
)
pause
For /f "delims=" %%A in ('Powershell -command "(Get-StartApps -Name Wintoys).AppID"') do Set "AppID=%%A"
Set "AppID=%AppID:~0,-7%"
Start "" "shell:AppsFolder\%AppID%^!wintoys"
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.G.M
cls
Echo ----------- AVL.G.M. WinUtil -----------
Set "URL=https://github.com/ChrisTitusTech/winutil/releases/latest"
Set "File=v.txt"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
For /f "tokens=7 delims=/" %%a in ('findstr "app-argument=" v.txt') do Set t1=%%a
Echo %t1%
Set t1=%t1:"=%
Set t1=%t1: =%
Del v.txt
Set "URL=https://github.com/ChrisTitusTech/winutil/releases/download/%t1%/winutil.ps1"
Set "File=winutil.ps1"
Set "FileDel=%File%"
Set "FolderDel="
Call :AVLDownload
Echo ----- Running %File%
Start Powershell .\%File%
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H
Set "AVLBackMenu=AVL.H"
cls 
Echo ------------ AVL.H. Fix Printer Error ------------
Echo     [1] Communication Error (Canon LBP 2900/3300)
Echo     [2] Error Code 0x0000007c
Echo     [3] Error Code 0x0000011b
Echo     [4] Error Code 0x00000709
Echo     [5] Error Code 0x00000040
Echo     [6] Error Code 0x00000bc4
Echo     [7] Error Code 0x000006d9
Echo     [8] Other Error Code
Echo     [9] Print management
Echo     [A] Print Server Properties
Echo     [0] Return to the previous menu
CHOICE /c 0123456789A /n /m "-------- (^_^) Your Wishes Come True (^_^) --------"
Set /A Index=%ErrorLevel%-1
Set "List=0123456789A"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.H.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.0
Goto AVL.MainMenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.RestartSpoolerService
echo.
echo ----- Stop Print Spooler service
sc stop spooler >nul 2>&1
taskkill /f /im spoolsv.exe >nul 2>&1
echo ----- Restart Print Spooler service
sc start spooler >nul 2>&1
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.1
cls
Echo ------------ AVL.H.1. Communication Error (Canon LBP 2900/3300) ------------
echo ----- Stop Spoolsv and Delete spool\PRINTERS
net stop spooler >nul
taskkill /f /im spoolsv.exe >nul 2>&1
del /q /f "%SystemRoot%\System32\spool\PRINTERS\*.*"
echo ----- Remove USB Monitor registry
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\USB Monitor" /f >nul 2>&1
echo ----- Remove Canon registry
for /f "tokens=*" %%K in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors" ^| findstr /I "CNBJNP" ') do reg delete "%%K" /f >nul
echo ----- Restart Spooler Service
Call :AVL.RestartSpoolerService
echo.
echo Disconnect the USB cable, then reconnect it.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.2
cls
Echo ------------ AVL.H.2. Error Code 0x0000007c ------------
echo ----- Set the RpcAuthnLevelPrivacyEnabled to 0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 0 /f >nul
Call :AVL.RestartSpoolerService
echo.
echo Disconnect the USB cable, then reconnect it.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.3
cls
Echo ------------ AVL.H.3. Error Code 0x0000011b ------------
echo ----- Set the RpcAuthnLevelPrivacyEnabled to 0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 0 /f >nul
echo ----- Enbale RpcOverNamedPipes and RpcOverTcp
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcOverNamedPipes /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcOverTcp /t REG_DWORD /d 1 /f >nul
Call :AVL.RestartSpoolerService
echo.
echo Disconnect the USB cable, then reconnect it.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.4
cls
Echo ------------ AVL.H.4. Error Code 0x00000709 ------------
echo ----- Stop spooler
net stop spooler >nul
echo ----- Enable Printing-Foundation-InternetPrinting-Client and Printing-LPRPortMonitor
dism /Online /Enable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client /NoRestart >nul
dism /Online /Enable-Feature /FeatureName:Printing-LPRPortMonitor /NoRestart >nul
echo ----- Set full control to User in Registry
powershell -NoProfile -Command "$p='HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows';$acl=Get-Acl $p;$rule=New-Object System.Security.AccessControl.RegistryAccessRule('Everyone','FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.SetAccessRule($rule);Set-Acl -Path $p -AclObject $acl"
echo ----- Remove Device and LegacyDefaultPrinterMode
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v Device /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LegacyDefaultPrinterMode /t REG_DWORD /d 1 /f >nul
Call :AVL.RestartSpoolerService
echo.
echo  Guide:
echo  1. Control Panel -> Devices and Printers.
echo  2. Delete the printer that cannot be made default.
echo  3. Turn off the printer and then turn it on.
echo  4. Right-click on the printer and select 'Set as default printer'.
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.5
cls
Echo ------------ AVL.H.5. Error Code 0x00000040 (Can not connect to printer) ------------
echo ----- Set rule for Firewall
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes >nul
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes >nul
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.6
cls
Echo ------------ AVL.H.6. Error Code 0x00000bc4, 0x000006e4 (RPC endpoint) ------------
echo ----- Enable RpcOverNamedPipes and RpcOverTcp
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcOverNamedPipes /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcOverTcp /t REG_DWORD /d 1 /f >nul
Call :AVL.RestartSpoolerService
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.7
cls
Echo ------------ AVL.H.7. Error Code 0x000006d9 ------------
echo ----- config MpsSvc
sc config MpsSvc start= auto >nul
echo ----- Start MpsSvc
sc start MpsSvc >nul
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.8
cls
Echo ------------ AVL.H.8. Other Error Code ------------
echo ----- Set Firewall for File and Printer Sharing & Network Discovery...
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes >nul
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes >nul
echo ----- Add registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcOverNamedPipes /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcOverTcp /t REG_DWORD /d 1 /f >nul
echo ----- Kiem tra va sao chep file mscms.dll neu thieu...
set "SourceFile=%SystemRoot%\System32\mscms.dll"
set "Dest64=%SystemRoot%\System32\spool\drivers\x64\3"
set "Dest32=%SystemRoot%\System32\spool\drivers\w32x86\3"
if exist "%SourceFile%" (
  if exist "%Dest64%" if not exist "%Dest64%\mscms.dll" copy /y "%SourceFile%" "%Dest64%\mscms.dll" >nul
  if exist "%Dest32%" if not exist "%Dest32%\mscms.dll" copy /y "%SourceFile%" "%Dest32%\mscms.dll" >nul
)
echo ----- Enable services
for %%S in (Spooler fdPHost FDResPub SSDPSRV upnphost) do (sc config %%S start= auto >nul 2>&1 & sc start %%S >nul 2>&1)
Call :AVL.RestartSpoolerService
sc start MpsSvc >nul

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.9
cls
Echo ------------ AVL.H.8. Print management ------------
start "" printmanagement.msc
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.H.A
cls
Echo ------------ AVL.H.A. Print Server Properties ------------
start "" rundll32 printui.dll,PrintUIEntry /s /t2
Call :AVL.Finish ""

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.I
Echo ----------- AVL.I. Help -----------
Start "" "https://docs.google.com/document/d/e/2PACX-1vTp0D3Xg-xphHKA5-XSoYEdEQX_1384fVhmgwaovSXs5EjEVn7vazioQywpkTTq6ewcd8sR1DaaO_GJ/pub"
Goto !AVLBackMenu!

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.J
cls 
Echo ------------ AVL.J. Shutdown ^& Restart ------------
Echo     [1] Restart to Windows Recovery Environment
Echo     [2] Restart to BIOS Setup
Echo     [3] Restart PC immediately
Echo     [4] Restart PC after 10 seconds
Echo     [5] Shutdown PC immediately
Echo     [6] Shutdown PC after 10 seconds
Echo     [0] Return to the previous menu
CHOICE /c 0123456 /n /m "-------- (^_^) Your Wishes Come True (^_^) --------"
Set /A Index=%ErrorLevel%-1
Set "List=012345"
Set MenuIndex=!List:~%Index%,1!
Goto AVL.J.%MenuIndex%

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.J.0
Goto AVL.Mainmenu

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.J.1
Echo ----- Restart to Windows Recovery Environment
Shutdown /r /o /t 0 
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.J.2
Echo ----- Restart to BIOS Setup
Shutdown /r /fw /t 0 
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.J.3
Echo ----- Restart to Windows Recovery Environment
Shutdown /r /t 0 
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.J.4
Echo ----- Restart PC after 10 seconds
Shutdown /r /t 10 
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.J.5
Echo ----- Shutdown PC immediately
Shutdown /s /t 0 
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.J.6
Echo ----- Shutdown PC after 10 seconds
Shutdown /s /t 10 
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.0
Echo ----------- AVL.0. Exit -----------
Powershell "(Get-WmiObject SoftwareLicensingService).OA3xOriginalProductKey"|CLIP
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.Z
Powershell "(Get-WmiObject SoftwareLicensingService).OA3xOriginalProductKey"|CLIP
del "%~f0"
Exit

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.Prompt
<nul Set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
pause >nul
If "%FileDel%" NEQ "" Del "%FileDel%"
If "%FolderDel%" NEQ "" (
	For /d %%A in (%FolderDel%*) do rmdir /s /q "%%A"
)
cls
Goto !AVLBackMenu!
GoTo :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.Finish
Set "k=%~1"
If "!k!" EQU "" (
	Set "k=%k:"=%"
	Set "Msg=Press any key to return to the previous menu"
) else (
	Set "Msg=%k%. Press any key to return to the previous menu"
)
For /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & Echo on & For %%b in (1) do rem"') do (Set "DEL=%%a")
Call :AVL.Prompt %ContrastColor% "%Msg%"
GoTo :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVLDownload
If exist "%File%" Del "%File%"
If "!Aria2cCheck!" equ "false" (Call :AVL.CheckAria2c)
Echo Downloading %File% ...
If "!Aria2cStatus!" EQU "Installed" (
	Echo The current download is using 16 connections. Just a moment, please...
	"!Aria2cPath!" -x 16 -s 16 -o "%File%" "%URL%"
) else (
	Echo The current download is using only 1 connection. Please wait...
	Powershell -command "Invoke-WebRequest -Uri '%URL%' -OutFile '%File%'"
)
If "%ErrorLevel%" NEQ "0" (
	Echo ----- Error: Download failed.
	Pause
	Goto !AVLBackMenu!
)
GoTo :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.CheckAria2c
Echo ----- Check Aria2c
Set "Aria2cCheck=true"
Set "Aria2cStatus=Not_Exist"
If "!Aria2cStatus!" equ "Installed" (Goto :EOF)
If exist "%SystemDrive%\Aria2\aria2c.exe" (
	Set "Aria2cPath=%SystemDrive%\Aria2\aria2c.exe"
	Set "Aria2cStatus=Installed"
	Goto :EOF
)
If exist "%ProgramFiles%\AutoAVL\aria2c.exe" (
	Set "Aria2cPath=%ProgramFiles%\AutoAVL\aria2c.exe"
	Set "Aria2cStatus=Installed"
	Goto :EOF
)
If exist "%ProgramFiles(x86)%\AutoAVL\aria2c.exe" (
	Set "Aria2cPath=%ProgramFiles(x86)%\AutoAVL\aria2c.exe"
	Set "Aria2cStatus=Installed"
	Goto :EOF
)
If "!Aria2cStatus!" neq "Installed" (
	For /f "delims=" %%a in ('dir /s /b "%SystemDrive%\aria2c.exe" 2^>nul') do (
		Set "Aria2cPath=%%a"
		Set "Aria2cStatus=Installed"
		Goto :EOF
	)
)
Set "ans4="
Set /p "ans4=> To install Aria2c, press Enter for Yes: "
If "!ans4!" equ "" (call :AVL.DownloadAria2c)
If /i "!ans4!" equ "y" (call :AVL.DownloadAria2c)
Goto :EOF

::::::::::::::AVL::::::::::::::AVL::::::::::::::AVL::::::::::::::
:AVL.DownloadAria2c
Echo ----- Getting the latest version of Aria2c
Set "URL=https://github.com/aria2/aria2/releases/latest"
Set "FolderDel=Aria2"
Set "FileDel=%File%"
Set "File=a.txt"
Call :AVLDownload
For /f "tokens=12 delims=/-" %%a in ('findstr "app-argument=" a.txt') do Set t1=%%a
Set t1=%t1: =%
Set "URL86=https://github.com/aria2/aria2/releases/download/release-%t1%/aria2-%t1%-win-32bit-build1.zip"
Set "URL64=https://github.com/aria2/aria2/releases/download/release-%t1%/aria2-%t1%-win-64bit-build1.zip"
Del %File%
If exist "%windir%\SysWOW64" (Set "URL=%URL64%") Else (Set "URL=%URL86%") 
Set "File=aria2.zip"
Set "FolderDel=Aria2"
Set "FileDel=%File%"
Call :AVLDownload
Echo ----- Extracting Aria2c
Powershell -command Expand-Archive -LiteralPath "%File%" -DestinationPath "%SystemDrive%"
Echo ----- Set PATH For Aria2c
For /d %%A in (%SystemDrive%\Aria2*) do (
	Rename "%%A" Aria2
	Setx PATH "%SystemDrive%\Aria2;!PATH!" /M
)
Echo ----- Close AVL and Reopen AVL to enable Aria2c. 
choice /T 5 /D Y /N > nul
Del "%File%"
If "%FolderDel%" NEQ "" (
	For /d %%A in (%FolderDel%*) do rmdir /s /q "%%A"
)
Powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" && exit
Exit