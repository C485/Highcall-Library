; Close (HANDLE)

EXTERNDEF sciClose:DWORD

IFDEF RAX
; 64bit
   
.DATA
.CODE
 
HcClose PROC 
	mov r10, rcx
	mov eax, sciClose
	syscall
	ret
HcClose ENDP 

ELSE
; 32bit

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcClose PROC 
	mov eax, sciClose
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcClose ENDP 

ENDIF

END