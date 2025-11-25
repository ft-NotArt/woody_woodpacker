#pragma once
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <errno.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>
# include <sys/mman.h>
# include <elf.h>

typedef struct s_elf {
	void   *map;
	size_t  size;
	int     fd;
}   t_elf;