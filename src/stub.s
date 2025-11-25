section .text
global _start
_start:
	; writes "....WOODY....\n"
	mov rdi, 1
	lea rsi, [rel woody]
	mov rdx, 15
	mov rax, 1
	syscall

	; Calculate ASLR base address (we need this for all address calculations)
	call .get_myaddr
.get_myaddr:
	pop r12                           ; r12 = runtime address of this instruction (no stack imbalance!)
	sub r12, (.get_myaddr - _start)   ; r12 = runtime address of _start (base + stub_vaddr)
	mov rbx, 0x4206420642064206       ; stub_vaddr placeholder (8 bytes) - will be patched
	sub r12, rbx                      ; r12 = ASLR base address
	
	; Calculate original entry runtime address (we'll need it after decryption)
	mov r13, r12                      ; r13 = ASLR base
	mov rbx, 0x4205420542054205       ; original_entry link address (patched, 8 bytes)
	add r13, rbx                      ; r13 = original entry runtime address
	
	; Calculate encrypted segment runtime address
	mov r14, r12                      ; r14 = ASLR base
	mov rbx, 0x4201420142014201       ; encrypted_vaddr placeholder (8 bytes)
	add r14, rbx                      ; r14 = encrypted segment runtime address
	
	; mprotect: Make encrypted segment writable (RWX)
	; int mprotect(void *addr, size_t len, int prot)
	; Need to align address to page boundary
	mov rdi, r14                      ; addr = encrypted segment
	and rdi, ~0xFFF                   ; Align down to page boundary
	mov esi, dword [rel encrypt_size] ; len = encrypt_size (4 bytes placeholder)
	add esi, 0x1000                   ; Add one page for safety
	mov edx, 7                        ; prot = PROT_READ | PROT_WRITE | PROT_EXEC (7)
	mov rax, 10                       ; syscall number for mprotect
	syscall
	test rax, rax
	js .skip_decrypt                  ; If mprotect failed, skip decryption
	
	; Decrypt the executable segment
	; void decrypt(char *to_decrypt, size_t encr_size, char *key, size_t key_size)
	mov rdi, r14                      ; to_decrypt = encrypted segment runtime address
	mov esi, dword [rel encrypt_size] ; encr_size
	lea rdx, [rel key_data]           ; key pointer
	mov ecx, dword [rel key_size]     ; key_size
	call decrypt
	
	; mprotect: Restore segment to read-execute only (RX)
	mov rdi, r14                      ; addr = encrypted segment
	and rdi, ~0xFFF                   ; Align down to page boundary
	mov esi, dword [rel encrypt_size] ; len
	add esi, 0x1000
	mov edx, 5                        ; prot = PROT_READ | PROT_EXEC (5)
	mov rax, 10                       ; syscall number for mprotect
	syscall

.skip_decrypt:
	; Restore initial state as if kernel jumped directly to original _start
	; The kernel passes rtld_fini in RDX, but it's for OUR entry, not the real one
	xor rdx, rdx                      ; Clear rtld_fini
	
	; Align stack to 16 bytes as required by x86-64 ABI
	and rsp, -16                      ; Align RSP to 16-byte boundary
	
	; Jump to original entry
	mov rax, r13                      ; Get saved original entry address
	jmp rax

decrypt:		; void decrypt(char *to_decrypt, size_t encr_size, char *key, size_t key_size)
	test rdi, rdi
	je .end
	test rdx, rdx
	je .end

	xor r8, r8
	xor r9, r9
	.loop:
		cmp r8, rsi
		je .end

		mov r10b, [rdi + r8]
		mov al, [rdi + r8]
		xor al, [rdx + r9]
		mov [rdi + r8], al
		
		mov al, r10b
		add [rdx + r9], al
		add [rdx + r9], r8b
		xor byte[rdx + r9], 0xA5

		inc r8
		inc r9
		cmp rcx, r9
		jne .loop
		xor r9, r9
		jmp .loop

	.end:
		ret

woody: db "....WOODY....", 10, 0
encrypt_size: dd 0x42024202  ; placeholder for encrypt_size (4 bytes)
key_size: dd 0x42044204      ; placeholder for key_size (4 bytes)
key_data: db 0x03, 0x42, 0x03, 0x42  ; placeholder for key (will be replaced by C packer)
encrypted_data:  ; Mark where encrypted data starts (label used for offset calculation)