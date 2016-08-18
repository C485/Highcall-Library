; QueryInformationProcess

IFDEF RAX
; 64bit
  
EXTERNDEF sciQueryInformationProcess:DWORD
 
.DATA
.CODE
 
HcQueryInformationProcess PROC 
	mov r10, rcx
	mov eax, sciQueryInformationProcess
	syscall
	ret
HcQueryInformationProcess ENDP 

ELSE
; 32bit

EXTERNDEF C sciQueryInformationProcess:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcQueryInformationProcess PROC 
	mov eax, sciQueryInformationProcess
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcQueryInformationProcess ENDP 

ENDIF

END
