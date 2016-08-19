; SetInformationThread

IFDEF RAX
; 64bit

EXTERNDEF sciSetInformationThread:DWORD
   
.DATA
.CODE
 
HcSetInformationThread PROC 
	mov r10, rcx
	mov eax, sciSetInformationThread
	syscall
	ret
HcSetInformationThread ENDP 

ELSE
; 32bit

EXTERNDEF C sciSetInformationThread:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcSetInformationThread PROC 
	mov eax, sciSetInformationThread
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcSetInformationThread ENDP 

ENDIF

END