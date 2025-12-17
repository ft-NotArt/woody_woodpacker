#define _GNU_SOURCE // for memmem
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>


typedef struct s_elf {
	void   *map;
	size_t  size;
	int     fd;
}   t_elf;


void	encrypt(unsigned char *to_encrypt, size_t encr_size, unsigned char *key, size_t key_size);


/* Elf64_Ehdr :

unsigned char e_ident[EI_NIDENT]: identification bytes (magic, class, endianness, ABI).

Elf64_Half e_type: object file type (relocatable, executable, shared, core).

Elf64_Half e_machine: target architecture (EM_X86_64 for woody).

Elf64_Word e_version: ELF version (usually EV_CURRENT).

Elf64_Addr e_entry: virtual address of entry point.

Elf64_Off e_phoff: file offset to the program header table.

Elf64_Off e_shoff: file offset to the section header table.

Elf64_Word e_flags: target-specific flags (usually 0 on x86_64).

Elf64_Half e_ehsize: size of this ELF header.

Elf64_Half e_phentsize: size of a single program header entry.

Elf64_Half e_phnum: number of program header entries.

Elf64_Half e_shentsize: size of a single section header entry.

Elf64_Half e_shnum: number of section header entries.

Elf64_Half e_shstrndx: index of the section header containing section names. */



/* Elf64_Phdr :

Elf64_Word p_type: segment type (e.g., PT_LOAD, PT_PHDR, PT_DYNAMIC).

Elf64_Word p_flags: segment flags (PF_R / PF_W / PF_X).

Elf64_Off  p_offset: file offset where the segment starts.

Elf64_Addr p_vaddr: virtual address the segment should be mapped to.

Elf64_Addr p_paddr: physical address (ignored on most modern systems).

Elf64_Xword p_filesz: number of bytes in the file for this segment.

Elf64_Xword p_memsz: size of the segment in memory (can be larger than filesz — BSS).

Elf64_Xword p_align: alignment in file and memory (usually page size for PT_LOAD). */

