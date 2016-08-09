; QueryInformationThread

EXTERNDEF sciQueryInformationThread:DWORD

IFDEF RAX
; 64bit
   
.DATA
.CODE
 
HcQueryInformationThread PROC 
	mov r10, rcx
	mov eax, sciQueryInformationThread
	syscall
	ret
HcQueryInformationThread ENDP 

ELSE
; 32bit

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcQueryInformationThread PROC 
	mov eax, sciQueryInformationThread
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcQueryInformationThread ENDP 

ENDIF

END
