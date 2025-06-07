# TrollRPC

https://github.com/andreisss/Ghosting-AMSI released a amsi bypass by breaking NdrClientCall3 which means every subsequent RPC call breaks. </br> 
Everything uses RPC which makes this kind of void. 



## Compilation instructions
```
#Use Visual Studio Command Prompt
ml64 /c AsmStub.asm /Fo AsmStub.obj
cl /LD /EHsc TrollRPC.cpp rpcrt4.lib ole32.lib AsmStub.obj /FeTrollRPC.dll
```
## General Usage 
Just load the DLL into your desired process

## .powershell Usage (does not require admin)
```
Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
"@ -Namespace Win32 -Name NativeMethods

[Win32.NativeMethods]::LoadLibrary("C:\TrollRPC.dll")
```

## Disclaimer
Should only be used for educational purposes!

## Credits
https://github.com/andreisss/Ghosting-AMSI






