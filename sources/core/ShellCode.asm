
MANUAL_MAP_MAIN  STRUCT

    HinstDLL				QWORD ?

    FdwReason				DWORD ?
    Pad1					DWORD ?

    lpvReserved				QWORD ?
    
	EntryPoint				DWORD ?
    Pad2					DWORD ?
    Done					DWORD ?
    Pad3					DWORD ?

	FunctionTable			QWORD ?

	EntryCount				DWORD ?
	Pad4					DWORD ?

	BaseAddress				QWORD ?
	RtlAddFunctionTable		QWORD ?

	TLSCallbacks			QWORD ?

MANUAL_MAP_MAIN  ENDS


.code

PUBLIC ShellCode
PUBLIC ShellCodeEnd

ShellCode PROC

	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	lea r15, ShellCodeDataOffset

	mov r14, rsp
	and rsp, 0FFFFFFFFFFFFFFF0h
	sub rsp, 20h

	mov rcx, [r15 + MANUAL_MAP_MAIN.FunctionTable]
	mov edx, [r15 + MANUAL_MAP_MAIN.EntryCount]
	mov r8,  [r15 + MANUAL_MAP_MAIN.BaseAddress]

	call [r15 + MANUAL_MAP_MAIN.RtlAddFunctionTable]
	
	mov rbx, [r15 + MANUAL_MAP_MAIN.TLSCallbacks]
	test rbx, rbx
	jz SkipTLS

LoopTLS:
	mov rax, [rbx]
	test rax, rax
	jz SkipTLS

	mov rcx, [r15 + MANUAL_MAP_MAIN.HinstDLL]
	mov edx, [r15 + MANUAL_MAP_MAIN.FdwReason]
	xor r8, r8
	call rax

	add rbx, 8
	jmp LoopTLS


SkipTLS:
	mov rax, [r15 + MANUAL_MAP_MAIN.HinstDLL]
	mov ecx, [r15 + MANUAL_MAP_MAIN.EntryPoint]
	add rax, rcx

	mov rcx, [r15 + MANUAL_MAP_MAIN.HinstDLL]
	mov edx, [r15 + MANUAL_MAP_MAIN.FdwReason]
	xor r8, r8
	call rax

	add rsp, 20h
	mov rsp, r14

	mov dword ptr[r15 + MANUAL_MAP_MAIN.Done], 1

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax

	ret

	ShellCodeDataOffset:
ShellCode ENDP

ShellCodeEnd:

END