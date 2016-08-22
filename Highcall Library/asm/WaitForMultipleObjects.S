; WaitForMultipleObjects

IFDEF RAX
; 64bit
   
EXTERNDEF sciWaitForMultipleObjects:DWORD

.DATA
.CODE
 
HcWaitForMultipleObjects PROC 
	mov r10, rcx
	mov eax, sciWaitForMultipleObjects
	syscall
	ret
HcWaitForMultipleObjects ENDP 

ELSE
; 32bit

EXTERNDEF C sciWaitForMultipleObjects:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcWaitForMultipleObjects PROC 
	mov eax, sciWaitForMultipleObjects
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcWaitForMultipleObjects ENDP 

ENDIF

END