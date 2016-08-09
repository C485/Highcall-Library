; CreateThread

EXTERNDEF sciCreateThread:DWORD

IFDEF RAX
; 64bit
   
.DATA
.CODE
 
HcCreateThread PROC 
	mov r10, rcx
	mov eax, sciCreateThread
	syscall
	ret
HcCreateThread ENDP 

ELSE
; 32bit

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcCreateThread PROC 
	mov eax, sciCreateThread
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcCreateThread ENDP 

ENDIF

END