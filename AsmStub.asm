; hook_ndr_asm.asm - x64 stub for NdrClientCall3 varargs hook
; This stub handles the hook, calls a C callback, and then jumps to a trampoline
; which executes the original NdrClientCall3 prologue and jumps back to the original function.

EXTERN HookedNdrClientCall3_C:PROC
EXTERN OutputDebugStringA:PROC ; Still useful for basic debugging of the ASM stub itself
EXTERN TrampolineAddress:QWORD ; External reference to the trampoline address from C++

.DATA
dbgMsg db "[hook_ndr.dll] ASM stub entered (before C callback)", 0

.CODE
PUBLIC HookedNdrClientCall3_Asm
HookedNdrClientCall3_Asm PROC

    ; Save ALL general-purpose registers that might hold critical state or arguments.
    ; This is a robust approach to avoid register clobbering issues.
    ; The stack layout after these pushes (from RSP upwards) is crucial for argument retrieval.
    ; Current RSP points to the saved R15.
    ; Offsets from current RSP to original arguments:
    ; [RSP + 70h] : Original RAX
    ; [RSP + 68h] : Original RCX (Ndr Arg0)
    ; [RSP + 60h] : Original RDX (Ndr Arg1)
    ; [RSP + 58h] : Original R8  (Ndr Arg2)
    ; [RSP + 50h] : Original R9  (Ndr Arg3)
    ; [RSP + 80h] : Original NdrClientCall3 1st stack argument (Ndr Arg4)

    push rax  ; Volatile
    push rcx  ; Volatile (Ndr Arg0)
    push rdx  ; Volatile (Ndr Arg1)
    push r8   ; Volatile (Ndr Arg2)
    push r9   ; Volatile (Ndr Arg3)
    push r10  ; Volatile
    push r11  ; Volatile
    push rbx  ; Non-volatile
    push rbp  ; Non-volatile
    push rsi  ; Non-volatile
    push rdi  ; Non-volatile
    push r12  ; Non-volatile
    push r13  ; Non-volatile
    push r14  ; Non-volatile
    push r15  ; Non-volatile

    ; --- Prepare arguments for HookedNdrClientCall3_C ---
    ; HookedNdrClientCall3_C now takes 5 arguments: (arg0, arg1, arg2, arg3, arg4)
    ; Win64 fastcall convention: RCX, RDX, R8, R9 for first 4 args. 5th arg passed on stack.

    ; Load NdrClientCall3's first 4 arguments from our saved stack into volatile registers
    ; (We use temp registers like R10, R11, R12, R13 for clarity and to not clobber RCX/RDX/R8/R9 just yet)
    mov r10, QWORD PTR [rsp + 68h] ; Ndr Arg0 (original RCX)
    mov r11, QWORD PTR [rsp + 60h] ; Ndr Arg1 (original RDX)
    mov r12, QWORD PTR [rsp + 58h] ; Ndr Arg2 (original R8)
    mov r13, QWORD PTR [rsp + 50h] ; Ndr Arg3 (original R9)

    ; Load NdrClientCall3's 5th argument (Ndr Arg4) from its original stack location.
    ; This is at [RSP + 80h] relative to the *current* RSP (after all our pushes).
    mov r14, QWORD PTR [rsp + 80h] ; Ndr Arg4 (original 1st stack arg)

    ; Now set up registers for the C callback (HookedNdrClientCall3_C)
    mov rcx, r10 ; C Arg0 (Ndr Arg0)
    mov rdx, r11 ; C Arg1 (Ndr Arg1)
    mov r8,  r12 ; C Arg2 (Ndr Arg2)
    mov r9,  r13 ; C Arg3 (Ndr Arg3)

    ; Push the 5th argument for the C function onto the stack.
    ; This will decrement RSP by 8 bytes.
    push r14 ; C Arg4 (Ndr Arg4)

    ; Allocate shadow space (32 bytes) + 8 bytes for alignment = 40 bytes.
    ; This ensures RSP is 16-byte aligned before the CALL instruction.
    sub rsp, 40

    ; Call our C callback
    call HookedNdrClientCall3_C

    ; Restore stack after C callback: shadow space (40 bytes) + 5th arg (8 bytes)
    add rsp, 40
    add rsp, 8 ; Pop the 5th argument passed to C++

    ; --- MODIFICATION LOGIC: Modify pFormatString (original RDX) on stack ---
    ; At this point, the original RDX (pFormatString) is still saved on the stack
    ; at [rsp + 60h] (relative to RSP after all register pushes have been restored).
    ; We retrieve it, check its value, and if it's 94, overwrite it on the stack.

    ; NOTE: The comparison value '94' is decimal. In hex, it's 5Eh.
    ; This logic still targets the saved original RDX (NdrArg1) on the stack.
    mov r10, QWORD PTR [rsp + 60h] ; Load saved pFormatString into R10 for comparison
    cmp r10, 94                     ; Compare its value with 94 (decimal)
    jne skip_modification           ; If not equal, jump to skip_modification

    ; If equal to 94, overwrite the saved RDX (pFormatString) on stack with 500
    mov QWORD PTR [rsp + 60h], 500 ; The new value (500 decimal)

skip_modification:
    ; Restore ALL general-purpose registers in reverse order of how they were pushed.
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

    ; === CRITICAL STEP: Jump to the trampoline ===
    ; The trampoline contains the original 16 prologue bytes of NdrClientCall3
    ; followed by a jump back to NdrClientCall3+16.
    ; By restoring RCX and other registers, the original function will now see
    ; its arguments and state as if it were never hooked.
    jmp QWORD PTR [TrampolineAddress]

HookedNdrClientCall3_Asm ENDP
END
