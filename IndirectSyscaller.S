.intel_syntax noprefix
.global IndirectSetup
.global IndirectSystemCall

// Move the system service number and syscall address to TLS slots
IndirectSetup:
	mov DWORD PTR gs:0x24c, ecx
	mov QWORD PTR gs:0x250, rdx
	ret

// Low latency system call
IndirectSystemCall:
	mov r10, rcx
	mov eax, DWORD PTR gs:0x24c
	jmp QWORD PTR gs:0x250
	ret
