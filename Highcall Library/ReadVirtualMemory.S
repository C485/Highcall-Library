; ReadVirtualMemory

IFDEF RAX
; 64bit
  
EXTERNDEF sciReadVirtualMemory:DWORD
 
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

EXTERNDEF C sciReadVirtualMemory:DWORD

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