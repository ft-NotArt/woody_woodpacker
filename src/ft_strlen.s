section .text

global ft_strlen

ft_strlen:
	xor rax, rax
	; 1st, xor a register over itself is a quicker way to do `mov rax, 0`.
	; 2nd, rax is our return register, but as the increment value is the value we return, we avoid oursleves a mov instruction later on.

	.loop:
		mov cl, [rdi]	; rdi = 1st arg ; [] dereferences ; this moves the 1st char of str to cl registers ; we're using cl because we only need 1 byte
		
		cmp cl, 0		; this set CPU flags to 0/1 (in a dedicated register) indicating what the result of the substraction between the 2 values gave.
		je .end			; this jump to end if cl and 0 were equals (NULL-byte)
		
		inc rax			; increment rax register (our increment and result)
		inc rdi			; increment rdi, the str passed as arg (next char)

		jmp .loop		; jump back to .loop (so that it is a loop)

	.end:
		ret