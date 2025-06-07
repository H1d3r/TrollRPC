# TrollRPC

https://github.com/andreisss/Ghosting-AMSI released a amsi bypass by breaking NdrClientCall3 which means every subsequent RPC call (eg. some name resolution uses RPC thats why web requests to github fail) breaks which kind of makes the technique obsolete. This particular dll will only break the specific RPC call to the AV scan engine, allowing all other RPC calls through. 

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

## Upgrades
Its made as a native c/c++ dll, but you can try doing it in c# 







