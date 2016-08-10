; ResumeProcess

IFDEF RAX
; 64bit
   
EXTERNDEF sciResumeProcess:DWORD

.DATA
.CODE
 
HcResumeProcess PROC 
	mov r10, rcx
	mov eax, sciResumeProcess
	syscall
	ret
HcResumeProcess ENDP 

ELSE
; 32bit

EXTERNDEF C sciResumeProcess:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcResumeProcess PROC 
	mov eax, sciResumeProcess
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcResumeProcess ENDP 

ENDIF

END