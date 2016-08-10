; OpenProcessTokenToken

IFDEF RAX
; 64bit

EXTERNDEF sciOpenProcessToken:DWORD
   
.DATA
.CODE
 
HcOpenProcessToken PROC 
	mov r10, rcx
	mov eax, sciOpenProcessToken
	syscall
	ret
HcOpenProcessToken ENDP 

ELSE
; 32bit

EXTERNDEF C sciOpenProcessToken:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcOpenProcessToken PROC 
	mov eax, sciOpenProcessToken
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcOpenProcessToken ENDP 

ENDIF

END
