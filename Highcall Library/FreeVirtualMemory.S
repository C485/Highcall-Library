; FreeVirtualMemory

EXTERNDEF sciFreeVirtualMemory:DWORD

IFDEF RAX
; 64bit
   
.DATA
.CODE
 
HcFreeVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciFreeVirtualMemory
	syscall
	ret
HcFreeVirtualMemory ENDP 

ELSE
; 32bit

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcFreeVirtualMemory PROC 
	mov eax, sciFreeVirtualMemory
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcFreeVirtualMemory ENDP 

ENDIF

END