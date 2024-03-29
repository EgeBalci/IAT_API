;-----------------------------------------------------------------------------;
; Author: Ege Balcı (ege.balci[at]invictuseurope[dot]com)
; Version: 1.1 (29 April 2023)
; Architecture: x64
; Size: 218 bytes
;-----------------------------------------------------------------------------;

; This block locates addresses from import address table with given ror(13) hash value.
; Design is inspired from Stephen Fewer's hash api.

[BITS 64]

; Windows x64 calling convention:
; http://msdn.microsoft.com/en-us/library/9b372w95.aspx

; Input: The hash of the module+function name in R10D 
; Output: The address of the function will be in RAX.
; Clobbers: R10
; Un-Clobbered: RAX, RCX, RDX, R8, R9, RBX, RSI, RDI, RBP, R12, R13, R14, R15.
; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.

api_call:
	push r9                 ; Save R9
	push r8                 ; Save R8
	push rdx                ; Save RDX
	push rcx                ; Save RCX
	push rsi                ; Save RSI
	xor rdx,rdx             ; Zero rdx
 	mov rdx,[gs:rdx+96]     ; Get a pointer to the PEB
	mov rdx,[rdx+24]        ; Get PEB->Ldr
	mov rdx,[rdx+32]        ; Get the first module from the InMemoryOrder module list
	mov rdx,[rdx+32]        ; Get this modules base address
	push rdx                ; Save the image base to stack (will use this alot)
	add dx,word [rdx+60]    ; "PE" Header
	mov edx,dword [rdx+144] ; Import table RVA
	add rdx,[rsp]           ; Address of Import Table
	push rdx                ; Save the &IT to stack (will use this alot)
 	mov rsi,[rsp+8]         ; Move the image base to RSI
	sub rsp,16              ; Allocate space for import descriptor counter & hash
	sub rdx,20              ; Prepare import descriptor pointer for processing
next_desc:
	add rdx,20              ; Get the next import descriptor
	cmp dword [rdx],0       ; Check if import descriptor is valid
	jz not_found            ; If import name array RVA is zero finish parsing
	mov rsi,[rsp+16]        ; Move import table address to RSI
	mov si,[rdx+12]         ; Get pointer to module name string RVA
	xor rdi,rdi	            ; Clear RDI which will store the hash of the module name
loop_modname:
	xor rax,rax             ; Clear RAX for calculating the hash
	lodsb                   ; Read in the next byte of the name
	cmp al,'a'              ; Some versions of windows use lower case module names
	jl not_lowercase        ;
	sub al,32               ; If so normalize to uppercase 
not_lowercase:
	crc32 edi,al            ; Calculate CRC32 of module name
	crc32 edi,ah            ; Feed NULL for unicode effect
	test al,al              ; Check if end of the module name
	jnz loop_modname        ; 
	; We now have the module hash computed
	mov [rsp+8],rdx         ; Save the current position in the module listfor later
	mov [rsp],edi           ; Save the current module hash for later
	; Proceed to itterate the export address table, 
	mov ecx,dword [rdx]     ; Get RVA of import names table
	add rcx,[rsp+24]        ; Add the image base and get the address of import names table
	sub rcx,8               ; Go 4 bytes back
get_next_func:              ;
	mov rdi,[rsp]           ; Reset module hash
	add rcx,8               ; 8 byte forward
	cmp dword [rcx],0       ; Check if end of INT 
	jz next_desc            ; If no INT present, process the next import descriptor
	mov esi,dword [rcx]     ; Get the RVA of func name hint
  	btr rsi,0x3F            ; Check if the high order bit is set
  	jc get_next_func        ; If high order bit is not set resolve with INT entry
	add rsi,[rsp+24]        ; Add the image base and get the address of function name hint
	add rsi,2               ; Move 2 bytes forward to asci function name
	; now ecx returns to its regularly scheduled counter duties
	; Computing the module hash + function hash
	; And compare it to the one we want
loop_funcname:
	xor rax,rax             ; Clear RAX
	lodsb                   ; Read in the next byte of the ASCII function name
	crc32 edi,al            ; Calculate CRC32 of the function name
	cmp al,ah               ; Compare AL (the next byte from the name) to AH (null)
	jne loop_funcname       ; If we have not reached the null terminator, continue
	cmp edi,r10d            ; Compare the hash to the one we are searchnig for 
	jnz get_next_func       ; Go compute the next function hash if we have not found it
	; If found, fix up stack, call the function and then value else compute the next one...
	mov eax,dword [rdx+16]  ; Get the RVA of current descriptor's IAT
	mov edx,dword [rdx]     ; Get the import names table RVA of current import descriptor
	add rdx,[rsp+24]        ; Get the address of import names table of current import descriptor
	sub rcx,rdx             ; Find the function array index ?
	add rax,[rsp+24]        ; Add the image base to current descriptors IAT RVA
	add rax,rcx             ; Add the function index
	; Now clean the stack
	; We now fix up the stack and perform the call to the drsired function...
finish:
	pop r8                  ; Clear off the current modules hash
	pop r8                  ; Clear off the current position in the module list
	pop r8                  ; Clear off the import table address of last module
	pop r8                  ; Clear off the image base address of last module
	pop rsi                 ; Restore RSI
	pop rcx                 ; Restore the RCX
	pop rdx                 ; Restore the RDX
	pop r8                  ; Restore the R8
	pop r9                  ; Restore the R9
	mov rax,[rax]           ; Get the address of the desired API
	ret                     ; Return to caller with the function address inside RAX
	; We now automatically return to the correct caller...
not_found:
	add rsp,72              ; Clean out the stack
	ret                     ; Return to caller
