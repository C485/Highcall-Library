; AllocateVirtualMemory

IFDEF RAX
; 64bit

EXTERNDEF sciAllocateVirtualMemory:DWORD

.DATA
.CODE
 
HcAllocateVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciAllocateVirtualMemory
	syscall
	ret
HcAllocateVirtualMemory ENDP 

ELSE
; 32bit

EXTERNDEF C sciAllocateVirtualMemory:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcAllocateVirtualMemory PROC 
	mov eax, sciAllocateVirtualMemory
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcAllocateVirtualMemory ENDP 

ENDIF

END
