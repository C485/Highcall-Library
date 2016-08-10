; QueryInformationToken

IFDEF RAX
; 64bit
   
EXTERNDEF sciQueryInformationToken:DWORD

.DATA
.CODE
 
HcQueryInformationToken PROC 
	mov r10, rcx
	mov eax, sciQueryInformationToken
	syscall
	ret
HcQueryInformationToken ENDP 

ELSE
; 32bit

EXTERNDEF C sciQueryInformationToken:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcQueryInformationToken PROC 
	mov eax, sciQueryInformationToken
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcQueryInformationToken ENDP 

ENDIF

END