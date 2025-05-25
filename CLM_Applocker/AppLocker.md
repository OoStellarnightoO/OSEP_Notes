# AppLocker CockBlocker

- Bascially makes life a pain in the ass by preventing execution of your favourite executables unless they are in whitelisted location

Reference: (https://juggernaut-sec.com/applocker-bypass/)

## Checking if AppLocker is live

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

## Check if Default World-Writeable Folders are well Writable for your User

Compile the following into a txt file

```
C:\Windows\Tasks 

C:\Windows\Temp 

C:\windows\tracing

C:\Windows\Registration\CRMLog

C:\Windows\System32\FxsTmp

C:\Windows\System32\com\dmp

C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys

C:\Windows\System32\spool\PRINTERS

C:\Windows\System32\spool\SERVERS

C:\Windows\System32\spool\drivers\color

C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter

C:\Windows\System32\Tasks_Migrated

C:\Windows\SysWOW64\FxsTmp

C:\Windows\SysWOW64\com\dmp

C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter

C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

Then on a cmd prompt, run the following script to see which folders you have Write perms

```cmd
for /F %A in (C:\temp\icacls.txt) do ( cmd.exe /c icacls "%~A" 2>nul | findstr /i "(F) (M) (W) (R,W) (RX,WD) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. ) 
```

## Via ADS



##  Via God-Tier Meterpreter's Post Exploit Module Execute dotner Assembly

https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/manage/execute_dotnet_assembly.md

