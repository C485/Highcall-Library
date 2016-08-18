; OpenProcess

IFDEF RAX
; 64bit

EXTERNDEF sciOpenProcess:DWORD
   
.DATA
.CODE
 
HcOpenProcess PROC 
	mov r10, rcx
	mov eax, sciOpenProcess
	syscall
	ret
HcOpenProcess ENDP 

ELSE
; 32bit

EXTERNDEF C sciOpenProcess:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcOpenProcess PROC 
	mov eax, sciOpenProcess
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcOpenProcess ENDP 

ENDIF

END
