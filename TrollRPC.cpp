#include <windows.h>
#include <rpc.h>
#include <rpcndr.h>
#include <stdio.h> // For sprintf_s

// 14-byte JMP: mov rax, addr; jmp rax
const BYTE JMP_ABS64[14] = {
    0x48, 0xB8,          // mov rax, <imm64>
    0, 0, 0, 0, 0, 0, 0, 0, // imm64 placeholder
    0xFF, 0xE0           // jmp rax
};

typedef void* (__stdcall* NdrClientCall3_t)(PMIDL_STUB_DESC, PFORMAT_STRING, ...);

// Extern symbol for our ASM entry point
extern "C" void HookedNdrClientCall3_Asm();

// Original NdrClientCall3 address
static void* targetFunction = nullptr;

// A small executable buffer to serve as a trampoline.
// This will contain:
// 1. The original prologue bytes of NdrClientCall3 (16 bytes in this case).
// 2. A jump back to NdrClientCall3 + TRAMPOLINE_PROLOGUE_SIZE.
static BYTE* trampoline = nullptr;
// *** UPDATED: TRAMPOLINE_PROLOGUE_SIZE is now 16 bytes to cover initial instructions ***
static const SIZE_T TRAMPOLINE_PROLOGUE_SIZE = 16;
static const SIZE_T TRAMPOLINE_SIZE = TRAMPOLINE_PROLOGUE_SIZE + sizeof(JMP_ABS64);

// This will be set by C++ and read by ASM, pointing to our trampoline.
extern "C" void* TrampolineAddress = nullptr;

// Buffer to store the original 14 bytes of NdrClientCall3 that our hook overwrites.
// Used for uninstalling the hook.
static BYTE originalPatchedBytes[sizeof(JMP_ABS64)] = {};

// --- MODIFIED: HookedNdrClientCall3_C now accepts arguments ---
// This function will be called from the ASM stub with the original arguments.
extern "C" void HookedNdrClientCall3_C(void* arg0, void* arg1, void* arg2, void* arg3, void* arg4)
{
    char debug_msg[512]; // Increased buffer size for argument details
    sprintf_s(debug_msg, sizeof(debug_msg),
        "[hook_ndr.dll] NdrClientCall3 called via ASM stub (C callback)\n"
        "  Arg0 (PMIDL_STUB_DESC): %p\n"
        "  Arg1 (PFORMAT_STRING): %p\n"
        "  Arg2: %p\n"
        "  Arg3: %p\n"
        "  Arg4: %p\n",
        arg0, arg1, arg2, arg3, arg4);
    OutputDebugStringA(debug_msg);

    // --- You can add your argument modification logic here ---
    // Example: If arg1 (pFormatString) is a specific value, change it.
    // if ((ULONG_PTR)arg1 == 94) // Using ULONG_PTR for direct comparison
    // {
    //     OutputDebugStringA("[hook_ndr.dll] Found pFormatString == 94, modifying it to 500.\n");
    //     // NOTE: This modification *in C++* will only affect the local variables
    //     // passed to this C function. To affect the original NdrClientCall3's arguments,
    //     // the modification MUST happen in the ASM stub *before* it jumps to the trampoline.
    //     // The ASM stub already has logic for this if you enabled it.
    // }
}

// Write memory safely
bool WriteMemory(void* dest, const void* src, SIZE_T size)
{
    DWORD oldProtect;
    if (!VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    memcpy(dest, src, size);
    return VirtualProtect(dest, size, oldProtect, &oldProtect);
}

extern "C" __declspec(dllexport) BOOL __stdcall InstallHook()
{
    HMODULE hMod = GetModuleHandleW(L"rpcrt4.dll");
    if (!hMod)
    {
        OutputDebugStringA("[hook_ndr.dll] Failed to get rpcrt4.dll handle.\n");
        return FALSE;
    }

    targetFunction = (void*)GetProcAddress(hMod, "NdrClientCall3");
    if (!targetFunction)
    {
        OutputDebugStringA("[hook_ndr.dll] Failed to get NdrClientCall3 address.\n");
        return FALSE;
    }

    // 1. Allocate executable memory for the trampoline
    trampoline = (BYTE*)VirtualAlloc(NULL, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        OutputDebugStringA("[hook_ndr.dll] Failed to allocate trampoline memory.\n");
        return FALSE;
    }
    TrampolineAddress = trampoline; // Make it accessible to ASM

    // 2. Copy the actual original prologue bytes to the start of our trampoline
    // *** UPDATED: Copy TRAMPOLINE_PROLOGUE_SIZE (16 bytes) ***
    memcpy(trampoline, targetFunction, TRAMPOLINE_PROLOGUE_SIZE);

    // 3. Prepare the jump back patch to NdrClientCall3 + TRAMPOLINE_PROLOGUE_SIZE
    BYTE jumpBackPatch[sizeof(JMP_ABS64)];
    memcpy(jumpBackPatch, JMP_ABS64, sizeof(JMP_ABS64));
    *reinterpret_cast<void**>(jumpBackPatch + 2) = (BYTE*)targetFunction + TRAMPOLINE_PROLOGUE_SIZE; // Jump to original function after the copied prologue

    // 4. Copy the jump back patch to the trampoline, immediately following the original prologue bytes
    memcpy(trampoline + TRAMPOLINE_PROLOGUE_SIZE, jumpBackPatch, sizeof(jumpBackPatch));

    // 5. Save the entire 14 bytes of NdrClientCall3 that our primary hook will overwrite.
    memcpy(originalPatchedBytes, targetFunction, sizeof(originalPatchedBytes));

    // 6. Build the main hook (JMP_ABS64) to our ASM stub.
    BYTE mainHookPatch[sizeof(JMP_ABS64)];
    memcpy(mainHookPatch, JMP_ABS64, sizeof(JMP_ABS64));
    *reinterpret_cast<void**>(mainHookPatch + 2) = (void*)&HookedNdrClientCall3_Asm;

    // 7. Overwrite the original function with our main hook.
    if (!WriteMemory(targetFunction, mainHookPatch, sizeof(mainHookPatch)))
    {
        OutputDebugStringA("[hook_ndr.dll] Failed to write main hook patch.\n");
        VirtualFree(trampoline, 0, MEM_RELEASE);
        trampoline = nullptr;
        TrampolineAddress = nullptr;
        return FALSE;
    }

    OutputDebugStringA("[hook_ndr.dll] Hook installed successfully.\n");
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL __stdcall UninstallHook()
{
    if (!targetFunction)
    {
        OutputDebugStringA("[hook_ndr.dll] targetFunction is null, cannot uninstall.\n");
        return FALSE;
    }

    // Restore the full 14-byte original content of the patched area.
    if (!WriteMemory(targetFunction, originalPatchedBytes, sizeof(originalPatchedBytes)))
    {
        OutputDebugStringA("[hook_ndr.dll] Failed to restore original bytes.\n");
        return FALSE;
    }

    // Release the trampoline memory
    if (trampoline) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        trampoline = nullptr;
        TrampolineAddress = nullptr;
    }

    OutputDebugStringA("[hook_ndr.dll] Hook removed.\n");
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        InstallHook();
    }
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
        UninstallHook();
    }

    return TRUE;
}
