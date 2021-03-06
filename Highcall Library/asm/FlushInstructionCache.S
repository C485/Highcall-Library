; FlushInstructionCache

IFDEF RAX
; 64bit

EXTERNDEF sciFlushInstructionCache:DWORD
   
.DATA
.CODE
 
HcFlushInstructionCache PROC 
	mov r10, rcx
	mov eax, sciFlushInstructionCache
	syscall
	ret
HcFlushInstructionCache ENDP 

ELSE
; 32bit

EXTERNDEF C sciFlushInstructionCache:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcFlushInstructionCache PROC 
	mov eax, sciFlushInstructionCache
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcFlushInstructionCache ENDP 

ENDIF

END