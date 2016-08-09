; ReadVirtualMemory

EXTERNDEF sciReadVirtualMemory:DWORD

IFDEF RAX
; 64bit
   
.DATA
.CODE
 
HcReadVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciReadVirtualMemory
	syscall
	ret
HcReadVirtualMemory ENDP 

ELSE
; 32bit

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcReadVirtualMemory PROC 
	mov eax, sciReadVirtualMemory
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcReadVirtualMemory ENDP 

ENDIF

END