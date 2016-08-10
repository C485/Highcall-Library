; WriteVirtualMemory

IFDEF RAX
; 64bit
   
EXTERNDEF sciWriteVirtualMemory:DWORD

.DATA
.CODE
 
HcWriteVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciWriteVirtualMemory
	syscall
	ret
HcWriteVirtualMemory ENDP 

ELSE
; 32bit

EXTERNDEF C sciWriteVirtualMemory:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcWriteVirtualMemory PROC 
	mov eax, sciWriteVirtualMemory
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcWriteVirtualMemory ENDP 

ENDIF

END