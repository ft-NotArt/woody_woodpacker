# COLORS

PURPLE			=	\x1b[0m\x1b[38;2;153;37;190m
LIGHT_PURPLE	=	\x1b[0m\x1b[38;2;184;102;210m
DARK_PURPLE		=	\x1b[1m\x1b[38;2;107;26;133m

# TARGET

NAME			=	woody_woodpacker

# FLAGS

MAKEFLAGS		+=	-s
CC				=	gcc
CFLAGS			=	-Wall -Werror -Wextra -g -Iinc
# CFLAGS			=	-g -Iinc
AS				=	nasm
ASFLAGS			=	-f elf64 -g

# FILES

C_FILES			=	woody

ASM_FILES		=	encrypt						\
					ft_strlen

STUB_FILES		=	stub						\

C_SRC			=	$(addprefix src/, $(addsuffix .c, $(C_FILES)))
ASM_SRC			=	$(addprefix src/, $(addsuffix .s, $(ASM_FILES)))
STUB_SRC		=	$(addprefix src/, $(addsuffix .s, $(STUB_FILES)))

C_OBJ			=	$(C_SRC:.c=.o)
ASM_OBJ			=	$(ASM_SRC:.s=.o)
STUB_OBJ		=	$(STUB_SRC:.s=.o)

OBJ				=	$(C_OBJ) $(ASM_OBJ)

# RULES

all				:	$(NAME)

$(NAME)			:	inc/stub.h $(OBJ)
					$(CC) $(CFLAGS) $^ -o $@
					echo -e '$(LIGHT_PURPLE) \tCompiled$(DARK_PURPLE) $@'

inc/stub.h			:	$(STUB_OBJ)
					objcopy -O binary -j .text src/stub.o stub.bin
					xxd -i stub.bin > inc/stub.h

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.s
	$(AS) $(ASFLAGS) $< -o $@

clean			:
					$(RM) $(OBJ) $(STUB_OBJ) stub.bin inc/stub.h
					echo -e '$(LIGHT_PURPLE) \tCleaned$(PURPLE) $(OBJ) $(STUB_OBJ) stub.bin stub.h'

fclean			:	clean
					$(RM) $(NAME) woody
					echo -e '$(LIGHT_PURPLE) \tCleaned$(DARK_PURPLE) $(NAME)'

re				:	fclean all

.PHONY			=	all clean fclean re
