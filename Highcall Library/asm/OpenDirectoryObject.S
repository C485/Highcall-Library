; OpenDirectoryObject

IFDEF RAX
; 64bit

EXTERNDEF sciOpenDirectoryObject:DWORD

.DATA
.CODE
 
HcOpenDirectoryObject PROC 
	mov r10, rcx
	mov eax, sciOpenDirectoryObject
	syscall
	ret
HcOpenDirectoryObject ENDP 

ELSE
; 32bit

EXTERNDEF C sciOpenDirectoryObject:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcOpenDirectoryObject PROC 
	mov eax, sciOpenDirectoryObject
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcOpenDirectoryObject ENDP 

ENDIF

END
