; WaitForSingleObject

IFDEF RAX
; 64bit
   
EXTERNDEF sciWaitForSingleObject:DWORD

.DATA
.CODE
 
HcWaitForSingleObject PROC 
	mov r10, rcx
	mov eax, sciWaitForSingleObject
	syscall
	ret
HcWaitForSingleObject ENDP 

ELSE
; 32bit

EXTERNDEF C sciWaitForSingleObject:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcWaitForSingleObject PROC 
	mov eax, sciWaitForSingleObject
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcWaitForSingleObject ENDP 

ENDIF

END