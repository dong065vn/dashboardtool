@echo off
setlocal enabledelayedexpansion
mode con: cols=80 lines=20
chcp 65001 >nul

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    goto goUAC 
) else (
 goto goADMIN )

:goUAC
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:goADMIN
    pushd "%CD%"
    CD /D "%~dp0"
cls

:main
cls
echo [A] Active Windows
echo[
echo [B] Active Office
echo[
echo [C] Xuat ket qua active
echo[
echo [D] Xuat key OEM co san trong may
echo[
echo [E] Backup ban quyen Office
echo[
echo [F] Restore ban quyen Office
echo[
echo [G] Copy ban quyen Winrar
echo[
echo [H] Active IDM
echo[
echo [I] Exit
echo[
Choice /N /C ABCDEFGHI /M "* Nhap Lua Chon Cua Ban :
if ERRORLEVEL 9 goto :8 I
if ERRORLEVEL 8 goto :7 H
if ERRORLEVEL 7 goto :6 G
if ERRORLEVEL 6 goto :5 F
if ERRORLEVEL 5 goto :4 E
if ERRORLEVEL 4 goto :3 D
if ERRORLEVEL 3 goto :2 C
if ERRORLEVEL 2 goto :1 B
if ERRORLEVEL 1 goto :0 A

:0
cscript //nologo %windir%\system32\slmgr.vbs /ato >nul
cscript //nologo %windir%\system32\slmgr.vbs /xpr |findstr "permanently" >nul
if %errorlevel%==0  (
cls
goto main
) else (
cls
echo [A] Nhap key
echo[
echo [B] Nhap CID
echo[
echo [C] Chay code non-core
echo[
echo [D] Thoat
echo[
Choice /N /C ABCD /M "* Nhap Lua Chon Cua Ban : 
if ERRORLEVEL 4 goto :03 D
if ERRORLEVEL 3 goto :02 C
if ERRORLEVEL 2 goto :01 B
if ERRORLEVEL 1 goto :00 A
)

:00
cls
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName') do set "ProductName=%%a %%b"
echo %ProductName% | findstr /r /c:"Windows 10" /c:"Windows 11" >nul
if %errorlevel% equ 0 (
    slui 3
    echo THIS-IS-YOUR-KEY | clip 
    Powershell Restart-Service -Name "cbdhsvc*" -force
    goto 0
)
echo %ProductName% | findstr /r /c:"Windows 7" /c:"Windows 8" /c:"Windows 8.1" >nul
if %errorlevel% equ 0 (
    set /p key= Nhap Key :
    echo THIS-IS-YOUR-KEY | clip 
    cls
    cscript //nologo %windir%\system32\slmgr.vbs /upk >nul
    cscript //nologo %windir%\system32\slmgr.vbs /ckms >nul
    cscript //nologo %windir%\system32\slmgr.vbs /cpky >nul
    cscript //nologo %windir%\system32\slmgr.vbs /ipk %key% >nul
    cscript //nologo %windir%\system32\slmgr.vbs /ato >nul
)
goto 0

:01
cls
cscript //nologo %windir%\system32\slmgr.vbs -dti > %temp%\InstallationID.txt
start %temp%\InstallationID.txt
echo Get CID theo id duoc hien len tren man hinh
set /p cid= Nhap cid vua get duoc: 
set cid=%cid:-=%
set cid=%cid: =%
cscript //nologo %windir%\system32\slmgr.vbs /atp %cid% >nul
cscript //nologo %windir%\system32\slmgr.vbs /ato >nul
cls 
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName') do set "ProductName=%%a %%b"
echo %ProductName% | findstr /r /c:"Windows 10" /c:"Windows 11" >nul
if %errorlevel% equ 0 (
    echo Vui long nhap lai key 1 lan nua
    echo[
    echo ==================================================
    slui 3
)
echo %ProductName% | findstr /r /c:"Windows 10" /c:"Windows 11" >nul
if %errorlevel% equ 0 (
    slui 3
    echo THIS-IS-YOUR-KEY | clip 
    Powershell Restart-Service -Name "cbdhsvc*" -force
    goto 0
)
echo %ProductName% | findstr /r /c:"Windows 7" /c:"Windows 8" /c:"Windows 8.1" >nul
if %errorlevel% equ 0 (
    set /p key= Nhap Key :
    echo THIS-IS-YOUR-KEY | clip 
)
cls
goto 0

:02
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName') do set "ProductName=%%a %%b"
echo %ProductName% | findstr /r /c:"Windows 10" /c:"Windows 11" >nul
if %errorlevel% equ 0 (
    goto :201
)
echo %ProductName% | findstr /r /c:"Windows 8" >nul
if %errorlevel% equ 0 (
    goto :202
)
echo %ProductName% | findstr /r /c:"Windows 7" >nul
if %errorlevel% equ 0 (
    goto :203
)
cls
goto 0

:201
net stop sppsvc
ren %windir%\System32\spp\store\2.0\tokens.dat tokens.bar
net start sppsvc
cscript %windir%\system32\slmgr.vbs /rilc
sc config wuauserv start= auto
sc config bits start= auto
sc config DcomLaunch start= auto
net stop wuauserv
net start wuauserv
net stop bits
net start bits
net start DcomLaunch
REG add "HKLM\SYSTEM\CurrentControlSet\services\sppsvc" /v Start /t REG_DWORD /d 4 /f
REG add "HKLM\SYSTEM\CurrentControlSet\services\sppsvc" /v Start /t REG_DWORD /d 2 /f
Restart-Service -Name sppsvc -Verbose
echo Go regedit, kiem tra Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\sppsvc va Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc co gia tri Start la 2 chua
echo Sau do Restart may lai 2 lan!
pause
cls
goto 0


:202
net stop sppsvc
cd %windir%\ServiceProfiles\LocalService\AppData\Local\Microsoft\WSLicense
ren tokens.dat tokens.bar
net start sppsvc
cscript.exe %windir%\system32\slmgr.vbs /rilc
echo Sau do Restart may lai 2 lan!
pause
cls
goto 0

:203
net stop sppsvc
cd %windir%\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SoftwareProtectionPlatform
ren tokens.dat tokens.bar
net start sppsvc
cscript.exe %windir%\system32\slmgr.vbs /rilc
slmgr -rearm
echo Sau do Restart may lai 2 lan!
pause
cls
goto 0


:03
cls 
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName') do set "ProductName=%%a %%b"
echo %ProductName% | findstr /r /c:"Windows 10" /c:"Windows 11" >nul
if %errorlevel% equ 0 (
    echo THIS-IS-YOUR-KEY | clip 
    Powershell Restart-Service -Name "cbdhsvc*" -force
)
goto main

:1
cls
echo [A] Nhap key
echo[
echo [B] Xuat ma cid
echo[
echo [C] Nhap ma cid
echo[
echo [D] Xoa key Office
echo[
echo [E] (Mo web) Download Office, xoa Office
echo[
echo [F] Ve menu
echo[
Choice /N /C ABCDEF /M "* Nhap Lua Chon Cua Ban : 
if ERRORLEVEL 6 goto :15 F
if ERRORLEVEL 5 goto :14 E
if ERRORLEVEL 4 goto :13 D
if ERRORLEVEL 3 goto :12 C
if ERRORLEVEL 2 goto :11 B
if ERRORLEVEL 1 goto :10 A

:10
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName') do set "ProductName=%%a %%b"
echo %ProductName% | findstr /r /c:"Windows 10" /c:"Windows 11" >nul
if %errorlevel% equ 0 (
    for /f "tokens=*" %%b in ('powershell -command "get-clipboard"') do set key=%%b
    echo THIS-IS-YOUR-KEY | clip 
    Powershell Restart-Service -Name "cbdhsvc*" -force
)
echo %ProductName% | findstr /r /c:"Windows 7" /c:"Windows 8" /c:"Windows 8.1" >nul
if %errorlevel% equ 0 (
    set /p key= Nhap Key: 
    echo THIS-IS-YOUR-KEY | clip
)
cscript O16OSPP.VBS /inpkey:!key! >nul
cscript O16OSPP.VBS /act >nul
cscript O10OSPP.VBS /inpkey:!key! >nul
cscript O10OSPP.VBS /act >nul
cls 
goto 1

:11
cscript O16OSPP.VBS /dinstid > %temp%/Iid_Office.txt
cscript O10OSPP.VBS /dinstid >> %temp%/Iid_Office.txt
start %temp%/Iid_Office.txt
cls 
goto 1

:12
echo[
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName') do set "ProductName=%%a %%b"
echo %ProductName% | findstr /r /c:"Windows 10" /c:"Windows 11" >nul
if %errorlevel% equ 0 (
    for /f "tokens=*" %%b in ('powershell -command "get-clipboard"') do set cid=%%b
    echo THIS-IS-YOUR-KEY | clip 
    Powershell Restart-Service -Name "cbdhsvc*" -force
)
echo %ProductName% | findstr /r /c:"Windows 7" /c:"Windows 8" /c:"Windows 8.1" >nul
if %errorlevel% equ 0 (
    set /p cid= Nhap Cid : 
    echo THIS-IS-YOUR-KEY | clip
)
set cid=%cid:-=%
set cid=%cid: =%
cscript O16OSPP.VBS /actcid:%cid% >nul
cscript O16OSPP.VBS /act >nul
cscript O10OSPP.VBS /actcid:%cid% >nul
cscript O10OSPP.VBS /act >nul
cls 
goto 1

:13
echo[
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName') do set "ProductName=%%a %%b"
echo %ProductName% | findstr /r /c:"Windows 10" /c:"Windows 11" >nul
if %errorlevel% equ 0 (
    for /f "tokens=*" %%b in ('powershell -command "get-clipboard"') do set key=%%b
    echo THIS-IS-YOUR-KEY | clip 
    Powershell Restart-Service -Name "cbdhsvc*" -force
)
echo %ProductName% | findstr /r /c:"Windows 7" /c:"Windows 8" /c:"Windows 8.1" >nul
if %errorlevel% equ 0 (
    set /p key= Nhap 5 ki tu cuoi cua key : 
)
cscript O16OSPP.VBS /unpkey:%key% >nul
cscript O10OSPP.VBS /unpkey:%key% >nul
cls
goto 1

:14
cls
echo [A] Office Tool Plus (Office 2016 Retail, Office 2019 - 2021 - 365)
echo[
echo [B] Office 2016 VL
echo[
echo [C] Office 2013 Retail
echo[
echo [D] Office 2013 VL
echo[
echo [E] Office 2010
echo[
echo [F] Thoat
echo[
Choice /N /C ABCDEF /M "* Nhap Lua Chon Cua Ban : 
if ERRORLEVEL 6 goto :106 F
if ERRORLEVEL 5 goto :105 E
if ERRORLEVEL 4 goto :104 D
if ERRORLEVEL 3 goto :103 C
if ERRORLEVEL 2 goto :102 B
if ERRORLEVEL 1 goto :101 A

:101
explorer "https://otp.landian.vip/redirect/download.php?type=runtime&arch=x86&site=onedrive"
cls 
goto 1

:102
if defined ProgramFiles(x86) (
    explorer "https://www.google.com/url?q=https://icedubai-my.sharepoint.com/:u:/g/personal/billgates_icedubai_onmicrosoft_com/EdUZX_WMN4VGrvRZobQvDLcBLpEmCicAIREZbCFFqSVoCg&sa=D&source=editors&ust=1700543379490731&usg=AOvVaw0HSvRc3YpRYdDQv73UDihs"
    cls 
    goto 1
) else (
    explorer "https://www.google.com/url?q=https://icedubai-my.sharepoint.com/:u:/g/personal/billgates_icedubai_onmicrosoft_com/EbDl_OwmFJtPtlCruqHwkd4BseE74G-rbvSni2vsQbaZYw&sa=D&source=editors&ust=1700543379492531&usg=AOvVaw1HsurHlsWDs8a5oKddh5sQ"
    cls 
    goto 1
)

:103
explorer "https://www.google.com/url?q=https://icedubai-my.sharepoint.com/:u:/g/personal/billgates_icedubai_onmicrosoft_com/Edmh8NUEVP5Aha76sNF0WpABbO95iHzga0K53i7XWqiCXw&sa=D&source=editors&ust=1700543379494058&usg=AOvVaw3USbuF4BU1jl_G5F89EqQH"
cls 
goto 1

:104
if defined ProgramFiles(x86) (
    explorer "https://www.google.com/url?q=https://icedubai-my.sharepoint.com/:u:/g/personal/billgates_icedubai_onmicrosoft_com/EY_b6I6Ve65FgLwL4hmn0RUBfqHhKaa51mYhlpIl6VJbyg&sa=D&source=editors&ust=1700543379497911&usg=AOvVaw3B9rgFG9SH5Jb1sAmvIPc2"
    cls 
    goto 1
) else (
    explorer "https://www.google.com/url?q=https://icedubai-my.sharepoint.com/:u:/g/personal/billgates_icedubai_onmicrosoft_com/EUnzySH6kKhIluMQPBOWwBkB4ogzCYXZIImxBBvf9_PN5g&sa=D&source=editors&ust=1700543379499487&usg=AOvVaw3FdIRsPdiiX8GZScilt8p_"
    cls 
    goto 1
)

:105
if defined ProgramFiles(x86) (
    explorer "https://www.google.com/url?q=https://icedubai-my.sharepoint.com/:u:/g/personal/billgates_icedubai_onmicrosoft_com/EbPymr069WZOhQIG2tfKCsIBWSfrMOasJC1nvUn_Xk0MZQ&sa=D&source=editors&ust=1700543379506927&usg=AOvVaw0E-EinBFu3X5h1X8Y6Fh63"
    cls 
    goto 1
) else (
    explorer "https://www.google.com/url?q=https://icedubai-my.sharepoint.com/:u:/g/personal/billgates_icedubai_onmicrosoft_com/EVEn2mM62yZJqWoZdbxy0XsBzQ7bA2JMTjfAXLa2VleeZQ&sa=D&source=editors&ust=1700543379508574&usg=AOvVaw1DPPO7tGfGdhc0fVDZZa5S"
    cls 
    goto 1
)

:106
cls
goto 1

:15
cls
goto main

:2
ECHO ************************************************************ > %temp%/result.txt
ECHO ***                   Windows Status                     *** >> %temp%/result.txt
ECHO ************************************************************ >> %temp%/result.txt
cscript //nologo %windir%\system32\slmgr.vbs /dli >> %temp%/result.txt
cscript //nologo %windir%\system32\slmgr.vbs /xpr >> %temp%/result.txt
ECHO ************************************************************ >> %temp%/result.txt
ECHO ***               Office 2013, 16, 19, 21                *** >> %temp%/result.txt
ECHO ************************************************************ >> %temp%/result.txt
cscript o16ospp.vbs /dstatus >> %temp%/result.txt
ECHO ************************************************************ >> %temp%/result.txt
ECHO ***                    Office 2010                       *** >> %temp%/result.txt
ECHO ************************************************************ >> %temp%/result.txt
cscript o10ospp.vbs /dstatus >> %temp%/result.txt
start %temp%/result.txt
cls
goto main

:3
wmic path softwarelicensingservice get OA3xOriginalProductKey > %temp%/result.txt
start %temp%/result.txt
cls
goto main

:4
Xcopy C:\Windows\System32\spp .\spp /E /H /C /I
ECHO ************************************************************ > .\spp\Infomation.txt
ECHO ***                   Windows Status                     *** >> .\spp\Infomation.txt
ECHO ************************************************************ >> .\spp\Infomation.txt
cscript //nologo %windir%\system32\slmgr.vbs /dli >> .\spp\Infomation.txt
cscript //nologo %windir%\system32\slmgr.vbs /xpr >> .\spp\Infomation.txt
ECHO ************************************************************ >> .\spp\Infomation.txt
ECHO ***               Office 2013, 16, 19, 21                *** >> .\spp\Infomation.txt
ECHO ************************************************************ >> .\spp\Infomation.txt
cscript o16ospp.vbs /dstatus >> .\spp\Infomation.txt
ECHO ************************************************************ >> .\spp\Infomation.txt
ECHO ***                    Office 2010                       *** >> .\spp\Infomation.txt
ECHO ************************************************************ >> .\spp\Infomation.txt
cscript o10ospp.vbs /dstatus >> .\spp\Infomation.txt
7z a spp.zip .\spp
rd /s /q .\spp
cls
goto main

:5
Net stop Sppsvc
Net stop Osppsvc
7z x spp.zip
del .\spp\Infomation.txt
Xcopy .\spp C:\Windows\System32\spp /E /H /C /I
Sc config Sppsvc start= auto & Net.exe start Sppsvc
Sc config Osppsvc  start= auto & Net.exe start Osppsvc
Sc config wuauserv start= auto & Net.exe start wuauserv
Sc config LicenseManager start= auto & Net.exe start LicenseManager
Cscript.exe /nologo %windir%\system32\slmgr.vbs /rilc
Cscript.exe /nologo %windir%\system32\slmgr.vbs -ato
Cscript.exe /nologo %windir%\system32\slmgr.vbs -dli
cscript O16OSPP.VBS /act
cscript O16OSPP.VBS /dstatus
cscript O10OSPP.VBS /act
cscript O10OSPP.VBS /dstatus
cls
goto main

:6
powershell -command "Get-Item 'rarreg.key' | Set-Clipboard"
cls 
goto main

:7 
powershell -command "irm https://massgrave.dev/ias | iex"
cls 
goto main

:8
exit

goto main