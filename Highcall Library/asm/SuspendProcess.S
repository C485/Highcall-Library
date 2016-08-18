; SuspendProcess

IFDEF RAX
; 64bit
   
EXTERNDEF sciSuspendProcess:DWORD

.DATA
.CODE
 
HcSuspendProcess PROC 
	mov r10, rcx
	mov eax, sciSuspendProcess
	syscall
	ret
HcSuspendProcess ENDP 

ELSE
; 32bit

EXTERNDEF C sciSuspendProcess:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcSuspendProcess PROC 
	mov eax, sciSuspendProcess
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcSuspendProcess ENDP 

ENDIF

END
