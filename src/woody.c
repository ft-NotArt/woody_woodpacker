#include "woody.h"
#include "stub.h"

size_t new_stub_len;

// Forward declaration
char *replace_mock_var(Elf64_Addr encrypted_vaddr, Elf64_Addr original_entry, Elf64_Addr stub_vaddr, size_t encrypt_size, unsigned char *key, size_t key_size);

int is_elf(unsigned char *ident) { //see man elf, ident must contain 0x7fELF
	if ( ident[0] != ELFMAG0 || ident[1] != ELFMAG1
		|| ident[2] != ELFMAG2 || ident[3] != ELFMAG3)	return 0;
		return 1;
}

int check_file(int fd, t_elf *elf) {
	struct stat st;
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return 1;
	}
	if (st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
		printf("file too small to be an ELF\n");
		return 1;
	}

	void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

	if (!is_elf((unsigned char *)ehdr->e_ident)) {
		printf("file is not an ELF\n");
		munmap(map, st.st_size);
		return 1;
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		printf("ELF is not 64 bits\n");
		munmap(map, st.st_size);
		return 1;
	}
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
		printf("file is not a binary\n");
		munmap(map, st.st_size);
		return 1;
	}

	elf->map = map;
	elf->size = st.st_size;
	elf->fd = fd;
	return 0;
}

int check_elf(const char *path, t_elf *elf, int *out_fd) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (check_file(fd, elf))
	{
		close(fd);
		return 1;
	}
	*out_fd = fd;
	return 0;
}

unsigned char *generate_key(size_t *key_size) {
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/urandom");
		return NULL;
	}
	unsigned char first;
	ssize_t byte = read(fd, &first, 1);
	if (byte != 1) {
		perror("read /dev/urandom");
		close(fd);
		return NULL;
	}
	size_t len = (first % 29) + 4;
	unsigned char *key = malloc(len);
	if (!key) {
		perror("malloc");
		close(fd);
		return NULL;
	}
	key[0] = first;
	if (len > 1)
		read(fd, key + 1, len - 1);
	close(fd);
	*key_size = len;
	return key;
}

int parse_args(int ac, char **av, unsigned char **out_key, size_t *key_size) {
	unsigned char *key = NULL;

	if (!(ac == 2 || ac == 3)) {
		printf("Usage : ./woody_woodpacker <binary> [<key>]\n");
		return 1;
	}
	if (ac == 3) {
		if (av[2][0] == '\0') {
			printf("Empty key.\n");
			return 1;
		}
		key = (unsigned char *)av[2];
		*key_size = strlen(av[2]);
	} else {
		key = generate_key(key_size);
		if (!key)
			return 1;
	}
	printf("KEY : %.*s\n", (int)*key_size, key);
	*out_key = key;
	return 0;
}


Elf64_Phdr *find_exec(Elf64_Ehdr *ehdr, void *base) {
	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)base + ehdr->e_phoff);
	for (int i = 0; i < ehdr->e_phnum; i++) {
		Elf64_Phdr *p = &phdr[i];
		if (p->p_type == PT_LOAD && (p->p_flags & PF_X))
			return p;
	}
	return NULL;
}

unsigned char *build_encrypt_buffer(t_elf *elf, Elf64_Phdr *exe_seg, size_t *out_size) {
	Elf64_Off payload_off = exe_seg->p_offset;
	size_t payload_size = exe_seg->p_filesz;

	unsigned char *file_bytes = (unsigned char *)elf->map;
	unsigned char *to_encrypt = (unsigned char *)malloc(payload_size);
	if (!to_encrypt) {
		printf("Failed to allocate to_encrypt buffer\n");
		return NULL;
	}

	memcpy(to_encrypt, file_bytes + payload_off, payload_size);
	*out_size = payload_size;
	return to_encrypt;
}

int build_woody(t_elf *elf, Elf64_Phdr *exe_seg, Elf64_Addr encrypted_vaddr, Elf64_Addr original_entry, unsigned char *encrypt_buff __attribute__((unused)), size_t encrypt_size, unsigned char *key, size_t key_size)
{
	// PT_NOTE to PT_LOAD injection - append payload to EOF
	// Convert PT_NOTE segment to PT_LOAD pointing to our code
	(void)exe_seg;
	size_t old_size = elf->size;
	
	// Calculate stub_vaddr with correct alignment FIRST
	size_t page_size = 0x1000;
	size_t offset_in_page = old_size % page_size;
	Elf64_Addr stub_vaddr = 0x800000 + offset_in_page;  // Match offset alignment
	
	// NOW create the stub with all the correct values
	char *new_stub = replace_mock_var(encrypted_vaddr, original_entry, stub_vaddr, encrypt_size, key, key_size);
	
	size_t payload_size = new_stub_len;  // Only the stub, no encryption for now
	size_t new_size = old_size + payload_size;

	unsigned char *new_img = malloc(new_size);
	if (!new_img) {
		perror("malloc new_img");
		return 1;
	}

	// Copy entire original file
	memcpy(new_img, elf->map, old_size);
	
	// NOW encrypt the executable segment in the new image
	// The stub will decrypt it at runtime before jumping to it
	memcpy(new_img + exe_seg->p_offset, encrypt_buff, encrypt_size);
	
	// Append just the stub at EOF
	memcpy(new_img + old_size, new_stub, new_stub_len);

	// Patch ELF headers in the new image
	Elf64_Ehdr *nehdr = (Elf64_Ehdr *)new_img;
	Elf64_Phdr *nphdr = (Elf64_Phdr *)(new_img + nehdr->e_phoff);

	// Zero out section headers - they're now invalid after our modifications
	nehdr->e_shoff = 0;
	nehdr->e_shnum = 0;
	nehdr->e_shstrndx = SHN_UNDEF;

	// Find PT_NOTE segment and convert it to PT_LOAD (just for stub, not encrypted data)
	// stub_vaddr was calculated earlier
	int found_note = 0;
	
	int note_count = 0;
	for (int i = 0; i < nehdr->e_phnum; i++) {
		Elf64_Phdr *p = &nphdr[i];
		if (p->p_type == PT_NOTE) {
			note_count++;
			// Skip first NOTE (likely GNU_PROPERTY with security features)
			// Convert the SECOND PT_NOTE (usually build-id, safe to remove)
			if (note_count == 2 && !found_note) {
				// Convert PT_NOTE to PT_LOAD
				p->p_type = PT_LOAD;
				p->p_flags = PF_R | PF_X | PF_W;  // RWX for stub execution
				p->p_offset = old_size;    // Points to stub at EOF
				p->p_vaddr = stub_vaddr;
				p->p_paddr = stub_vaddr;
				p->p_filesz = new_stub_len;  // Only the stub!
				p->p_memsz = new_stub_len;
				p->p_align = 0x1000;
				found_note = 1;
				break;
			}
		}
	}
	
	if (!found_note) {
		printf("ERROR: No PT_NOTE segment found!\n");
		free(new_img);
		return 1;
	}

	nehdr->e_entry = stub_vaddr;
	int out = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (out < 0) {
		perror("open woody");
		free(new_img);
		return 1;
	}
	ssize_t written = write(out, new_img, new_size);
	if (written != (ssize_t)new_size) {
		perror("write woody");
		close(out);
		free(new_img);
		return 1;
	}
	close(out);
	free(new_img);
	free(new_stub);
	return 0;
}
char *replace_mock_var(Elf64_Addr encrypted_vaddr, Elf64_Addr original_entry, Elf64_Addr stub_vaddr, size_t encrypt_size, unsigned char *key, size_t key_size) {
	uint8_t *long_to_insert;

	new_stub_len = stub_bin_len + key_size - 4;
	char *key_placeholder = memmem(stub_bin, stub_bin_len, "\x03\x42\x03\x42", 4);

	size_t key_offset = key_placeholder - (char *)stub_bin;

	char *new_stub = malloc(new_stub_len);

	/* Copy before key placeholder */
	memcpy(new_stub, stub_bin, key_offset);
	/* Insert full key */
	memcpy(new_stub + key_offset, key, key_size);
	/* Copy rest of stub after placeholder */
	memcpy(new_stub + key_offset + key_size, stub_bin + key_offset + 4, stub_bin_len - key_offset - 4);

	/* Patch 8-byte placeholder for encrypted data vaddr */
	long_to_insert = memmem(new_stub, new_stub_len, "\x01\x42\x01\x42\x01\x42\x01\x42", 8);
	if (long_to_insert)
		memcpy(long_to_insert, &encrypted_vaddr, 8);

	/* Patch 4-byte placeholder for encrypt size */
	long_to_insert = memmem(new_stub, new_stub_len, "\x02\x42\x02\x42", 4);
	if (long_to_insert)
		memcpy(long_to_insert, &encrypt_size, 4);

	/* Patch 4-byte placeholder for key size */
	long_to_insert = memmem(new_stub, new_stub_len, "\x04\x42\x04\x42", 4);
	if (long_to_insert)
		memcpy(long_to_insert, &key_size, 4);

	/* Patch 8-byte placeholder for original entry point */
	long_to_insert = memmem(new_stub, new_stub_len, "\x05\x42\x05\x42\x05\x42\x05\x42", 8);
	if (long_to_insert)
		memcpy(long_to_insert, &original_entry, 8);

	/* Patch 8-byte placeholder for stub_vaddr */
	long_to_insert = memmem(new_stub, new_stub_len, "\x06\x42\x06\x42\x06\x42\x06\x42", 8);
	if (long_to_insert)
		memcpy(long_to_insert, &stub_vaddr, 8);

	return new_stub;
}

int main(int ac, char **av) {
	unsigned char *key = NULL;
	size_t key_size = 0;

	if (parse_args(ac, av, &key, &key_size))
		return 1;

	int fd;
	t_elf elf;
	if (check_elf(av[1], &elf, &fd)) {
		if (ac == 2 && key)
			free(key);
		return 1;
	}

	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf.map;
	Elf64_Phdr *exe_seg = find_exec(ehdr, elf.map);
	if (!exe_seg) {
		printf("No executable segment\n");
		munmap(elf.map, elf.size);
		close(fd);
		if (ac == 2 && key)
			free(key);
		return 1;
	}
	size_t encrypt_size;
	unsigned char *encrypt_buff = build_encrypt_buffer(&elf, exe_seg, &encrypt_size);
	if (!encrypt_buff) {
		munmap(elf.map, elf.size);
		close(fd);
		if (ac == 2 && key)
			free(key);
		return 1;
	}

	unsigned char *saved_key = malloc(key_size);
	memcpy(saved_key, key, key_size);
	
	// Save original entry point and encrypted segment virtual address
	Elf64_Addr original_entry = ehdr->e_entry;
	Elf64_Addr encrypted_vaddr = exe_seg->p_vaddr;
	
	encrypt(encrypt_buff, encrypt_size, key, key_size);
	
	// build_woody now creates the stub internally with correct stub_vaddr
	build_woody(&elf, exe_seg, encrypted_vaddr, original_entry, encrypt_buff, encrypt_size, saved_key, key_size);
	
	free(encrypt_buff);
	if (ac == 2 && key)
		free(key);
	munmap(elf.map, elf.size);
	close(fd);
	return 0;
}