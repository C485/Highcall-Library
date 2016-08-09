; AllocateVirtualMemory
EXTERNDEF sciAllocateVirtualMemory:DWORD

IFDEF RAX
; 64bit
   
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
