; CreateThreadEx

IFDEF RAX
; 64bit

EXTERNDEF sciCreateThreadEx:DWORD

.DATA
.CODE
 
HcCreateThreadEx PROC 
	mov r10, rcx
	mov eax, sciCreateThreadEx
	syscall
	ret
HcCreateThreadEx ENDP 

ELSE
; 32bit

EXTERNDEF C sciCreateThreadEx:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcCreateThreadEx PROC 
	mov eax, sciCreateThreadEx
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcCreateThreadEx ENDP 

ENDIF

END
