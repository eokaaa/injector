
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
	pushfq

	lea r15, ShellCodeDataOffset

	mov r14, rsp
	and rsp, 0FFFFFFFFFFFFFFF0h

	sub rsp, 0f0h
    movaps xmmword ptr [rsp + 00h],  xmm1
    movaps xmmword ptr [rsp + 10h],  xmm2
    movaps xmmword ptr [rsp + 20h],  xmm3
    movaps xmmword ptr [rsp + 30h],  xmm4
    movaps xmmword ptr [rsp + 40h],  xmm5
    movaps xmmword ptr [rsp + 50h],  xmm6
    movaps xmmword ptr [rsp + 60h],  xmm7
    movaps xmmword ptr [rsp + 70h],  xmm8
    movaps xmmword ptr [rsp + 80h],  xmm9
    movaps xmmword ptr [rsp + 90h],  xmm10
    movaps xmmword ptr [rsp + 0a0h], xmm11
    movaps xmmword ptr [rsp + 0b0h], xmm12
    movaps xmmword ptr [rsp + 0c0h], xmm13
    movaps xmmword ptr [rsp + 0d0h], xmm14
    movaps xmmword ptr [rsp + 0e0h], xmm15

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

	movaps xmm1,  xmmword ptr [rsp + 00h]
    movaps xmm2,  xmmword ptr [rsp + 10h]
    movaps xmm3,  xmmword ptr [rsp + 20h]
    movaps xmm4,  xmmword ptr [rsp + 30h]
    movaps xmm5,  xmmword ptr [rsp + 40h]
	movaps xmm6,  xmmword ptr [rsp + 50h]
    movaps xmm7,  xmmword ptr [rsp + 60h]
    movaps xmm8,  xmmword ptr [rsp + 70h]
    movaps xmm9,  xmmword ptr [rsp + 80h]
    movaps xmm10, xmmword ptr [rsp + 90h]
    movaps xmm11, xmmword ptr [rsp + 0a0h]
    movaps xmm12, xmmword ptr [rsp + 0b0h]
    movaps xmm13, xmmword ptr [rsp + 0c0h]
    movaps xmm14, xmmword ptr [rsp + 0d0h]
    movaps xmm15, xmmword ptr [rsp + 0e0h]
    add rsp, 0f0h

	mov dword ptr[r15 + MANUAL_MAP_MAIN.Done], 1
	mov rsp, r14

	popfq
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