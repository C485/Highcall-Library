; QueryVirtualMemory

IFDEF RAX
; 64bit

EXTERNDEF sciQueryVirtualMemory:DWORD
   
.DATA
.CODE
 
HcQueryVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciQueryVirtualMemory
	syscall
	ret
HcQueryVirtualMemory ENDP 

ELSE
; 32bit

EXTERNDEF C sciQueryVirtualMemory:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcQueryVirtualMemory PROC 
	mov eax, sciQueryVirtualMemory
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0C0h]
	ret
HcQueryVirtualMemory ENDP 

ENDIF

END
