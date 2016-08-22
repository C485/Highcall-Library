; UnlockVirtualMemory (HANDLE)

IFDEF RAX
; 64bit
   
EXTERNDEF sciUnlockVirtualMemory:DWORD

.DATA
.CODE
 
HcUnlockVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciUnlockVirtualMemory
	syscall
	ret
HcUnlockVirtualMemory ENDP 

ELSE
; 32bit

EXTERNDEF C sciUnlockVirtualMemory:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcUnlockVirtualMemory PROC 
	mov eax, sciUnlockVirtualMemory
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcUnlockVirtualMemory ENDP 

ENDIF

END