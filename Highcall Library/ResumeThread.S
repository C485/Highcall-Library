; ResumeThread

EXTERNDEF sciResumeThread:DWORD

IFDEF RAX
; 64bit
   
.DATA
.CODE
 
HcResumeThread PROC 
	mov r10, rcx
	mov eax, sciResumeThread
	syscall
	ret
HcResumeThread ENDP 

ELSE
; 32bit

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcResumeThread PROC 
	mov eax, sciResumeThread
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcResumeThread ENDP 

ENDIF

END
