#include "woody.h"

int is_elf(unsigned char *ident) { //see man elf, ident must contain 0x7fELF
	if ( ident[0] != ELFMAG0 || ident[1] != ELFMAG1
		|| ident[2] != ELFMAG2 || ident[3] != ELFMAG3)	return 0;
		return 1;
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
	size_t len = (first % 32) + 1;
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
	printf("KEY : %s\n", key);
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

unsigned char *build_payload_buffer(t_elf *elf, Elf64_Phdr *exe_seg, size_t *out_size) {
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

int build_woody(t_elf *elf, Elf64_Phdr *exe_seg, unsigned char *payload_buff, size_t payload_size)
{
	//append payload_buff (stub + encrypted payload) at the end of PT_LOAD.

	Elf64_Off seg_off = exe_seg->p_offset;
	size_t old_filesz = exe_seg->p_filesz;
	size_t old_memsz = exe_seg->p_memsz;
	Elf64_Off insert_off = seg_off + old_filesz; // offset where we append
	size_t old_size = elf->size;
	size_t new_size = old_size + payload_size;

	unsigned char *new_img = malloc(new_size);
	if (!new_img) {
		perror("malloc new_img");
		return 1;
	}

	// copy bytes before insertion point
	memcpy(new_img, elf->map, insert_off);
	// copy appended payload (stub + encrypted code)
	memcpy(new_img + insert_off, payload_buff, payload_size);
	// copy tail of original file after the insertion point
	size_t tail_size = old_size - insert_off;
	memcpy(new_img + insert_off + payload_size,
		(unsigned char *)elf->map + insert_off, tail_size);

	// patch ELF headers for the new_img
	Elf64_Ehdr *nehdr = (Elf64_Ehdr *)new_img;
	Elf64_Phdr *nphdr = (Elf64_Phdr *)(new_img + nehdr->e_phoff);

	/* increase size of the exec segment and bump p_offset of any segment 
	that starts after the exec PT_LOAD */
	for (int i = 0; i < nehdr->e_phnum; i++) {
		Elf64_Phdr *p = &nphdr[i];
		if (p->p_type == PT_LOAD && (p->p_flags & PF_X) && p->p_offset == seg_off) {
			p->p_filesz = old_filesz + payload_size;
			p->p_memsz  = old_memsz  + payload_size;
		} else if (p->p_offset > seg_off) {
			p->p_offset += payload_size;
		}
	}

	// update entry point so that it jumps to beginning of the appended part
	Elf64_Addr stub_vaddr = exe_seg->p_vaddr + old_filesz;
	nehdr->e_entry = stub_vaddr;
	int out = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (out < 0) {
		perror("open woody");
		free(new_img);
		return 1;
	}
	if (write(out, new_img, new_size) != (ssize_t)new_size) {
		perror("write woody");
		close(out);
		free(new_img);
		return 1;
	}
	close(out);
	free(new_img);
	return 0;
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

	size_t payload_size;
	unsigned char *payload_buff = build_payload_buffer(&elf, exe_seg, &payload_size);
	if (!payload_buff) {
		munmap(elf.map, elf.size);
		close(fd);
		if (ac == 2 && key)
			free(key);
		return 1;
	}

	unsigned char *saved_key = strdup(key);
	// stub virtual address = end of original exec PT_LOAD
	Elf64_Addr stub_vaddr = exe_seg->p_vaddr + exe_seg->p_filesz;
	// pack‑time delta = from stub start to original entry
	Elf64_Addr old_entry_delta = ehdr->e_entry - stub_vaddr;
	// encrypt(payload_buff, payload_size, key, key_size);
	// add_stub(&payload_buff, &payload_size, saved_key, key_size, old_entry_delta);
	// build_woody(&elf, exe_seg, payload_buff, payload_size);
	free(payload_buff);
	if (ac == 2 && key)
		free(key);
	munmap(elf.map, elf.size);
	close(fd);
	return 0;
}