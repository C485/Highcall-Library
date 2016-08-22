; LockVirtualMemory (HANDLE)

IFDEF RAX
; 64bit
   
EXTERNDEF sciLockVirtualMemory:DWORD

.DATA
.CODE
 
HcLockVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciLockVirtualMemory
	syscall
	ret
HcLockVirtualMemory ENDP 

ELSE
; 32bit

EXTERNDEF C sciLockVirtualMemory:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcLockVirtualMemory PROC 
	mov eax, sciLockVirtualMemory
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcLockVirtualMemory ENDP 

ENDIF

END