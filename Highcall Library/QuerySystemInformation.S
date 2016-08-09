; QuerySystemInformation
EXTERNDEF sciQuerySystemInformation:DWORD

IFDEF RAX
; 64bit
   
.DATA
.CODE
 
HcQuerySystemInformation PROC 
	mov r10, rcx
	mov eax, sciQuerySystemInformation
	syscall
	ret
HcQuerySystemInformation ENDP 

ELSE
; 32bit

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcQuerySystemInformation PROC 
	mov eax, sciQuerySystemInformation
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcQuerySystemInformation ENDP 

ENDIF

END
