REM Author: Gilles Biagomba
REM Program: wind0z_Pr1v3sc.bat
REM Description: This script is designed to perform windows checks for privilege escalation
REM Ref: https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
REM http://pwnwiki.io/#!privesc/windows/index.md
REM https://hackmag.com/security/elevating-privileges-to-administrative-and-further/

@echo off

REM Basics
echo "Basic Enumeration of the System"
systeminfo
hostname
echo

REM Who am I?
whoami
echo %username%

REM What users/localgroups are on the machine?
net users
net localgroups

REM More info about a specific user. Check if user has privileges.
net user user1

REM View Domain Groups
net group /domain

REM View Members of Domain Group
net group /domain <Group Name>

REM Firewall
netsh firewall show state
netsh firewall show config

REM Network
ipconfig /all
route print
arp -A

REM How well patched is the system?
wmic qfe get Caption,Description,HotFixID,InstalledOn

echo "Cleartext Passwords"
REM Search for them
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

REM Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*

REM More passwords In files
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type c:\unattend.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini

REM VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

REM Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

REM SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

REM Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

REM Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

echo "Service only available from inside"
REM Service only available from inside
netstat -ano

REM Scheduled Tasks
echo "Scheduled Tasks"
schtasks /query /fo LIST /v

REM Weak Service Permissions
echo "Weak Service Permissions"
wmic service list brief
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"

REM sc.exe
sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt

REM Migrate the meterpreter shell
wmic process list brief | find "winlogon"

echo "Find Services With Unquoted Paths"
REM Using WMIC
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

REM Using sc
sc query
sc qc service name

REM How to search such directories/ files
accesschk.exe -uwdqs users c:\
accesschk.exe -uwdqs “Authenticated Users” c:\
accesschk.exe -uwqs users c:\*.*
accesschk.exe -uwqs “Authenticated Users” c:\*.*
accesschk.exe –uwcqv *

REM Ssearch for process Permissions
cd %ProgramFiles%
dir  /s /b *.exe | findstr /v .exe. >> %HOMEPATH%\Downloads\process.txt
FOR /F %%G IN ('"dir  /s /b *.exe | findstr /v .exe."') DO icacls "%%G"
FOR /F %%G IN ('"dir  /s /b *.exe | findstr /v .exe."') DO cacls "%%G"
echo "Look for Binary_path_name and see if it is unquoted."

echo "Vulnerable Drivers"
REM List all drivers
driverquery

REM AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

REM Lost auto launch
autorunsc.exe -a | findstr /n /R "File\ not\ found"
