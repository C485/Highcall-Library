; ProtectVirtualMemory

IFDEF RAX
; 64bit
   
EXTERNDEF sciProtectVirtualMemory:DWORD

.DATA
.CODE
 
HcProtectVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciProtectVirtualMemory
	syscall
	ret
HcProtectVirtualMemory ENDP 

ELSE
; 32bit

EXTERNDEF C sciProtectVirtualMemory:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcProtectVirtualMemory PROC 
	mov eax, sciProtectVirtualMemory
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcProtectVirtualMemory ENDP 

ENDIF

END
