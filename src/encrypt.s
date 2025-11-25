section .text

global encrypt

encrypt:		; void	encrypt(char *to_encrypt, size_t encr_size, char *key, size_t key_size)
	; make sure no pointers are NULL
	test rdi, rdi
	je .end
	test rdx, rdx
	je .end

	xor r8, r8	; to_encrypt index
	xor r9, r9	; key index
	.loop:
		cmp r8, rsi
		je .end

		; data[i] ^= key[i % key_size]
		mov al, [rdi + r8]
		xor al, [rdx + r9]
		mov [rdi + r8], al
		
		;key[i % key_size] = (key[i % key_size] + data[i] + i) ^ 0xA5
		mov al, [rdi + r8]
		add byte[rdx + r9], al
		add byte[rdx + r9], r8b
		xor byte[rdx + r9], 0xA5	; 0xA5 = 1010 0101 (mask)

		inc r8
		inc r9
		cmp rcx, r9	; if key index == key size, key index = 0, equivalent of using modulo
		jne .loop
		mov r9, 0
		jmp .loop

	.end:
		ret