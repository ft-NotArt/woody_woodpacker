# COLORS

PURPLE			=	\x1b[0m\x1b[38;2;153;37;190m
LIGHT_PURPLE	=	\x1b[0m\x1b[38;2;184;102;210m
DARK_PURPLE		=	\x1b[1m\x1b[38;2;107;26;133m

# TARGET

NAME			=	woody_woodpacker

# FLAGS

MAKEFLAGS		+=	-s
CC				=	gcc
# CFLAGS			=	-Wall -Werror -Wextra -g -Iinc
CFLAGS			=	-g -Iinc
AS				=	nasm
ASFLAGS			=	-f elf64 -g

# FILES

C_FILES			=	parser

ASM_FILES		=	encrypt						\
					decrypt						\
					ft_strlen

C_SRC			=	$(addprefix src/, $(addsuffix .c, $(C_FILES)))
ASM_SRC			=	$(addprefix src/, $(addsuffix .s, $(ASM_FILES)))

C_OBJ			=	$(C_SRC:.c=.o)
ASM_OBJ			=	$(ASM_SRC:.s=.o)

OBJ				=	$(C_OBJ) $(ASM_OBJ)

# RULES

all				:	$(NAME)

$(NAME)			:	$(OBJ)
					$(CC) $(CFLAGS) $^ -o $@
					echo -e '$(LIGHT_PURPLE) \tCompiled$(DARK_PURPLE) $@'

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.s
	nasm -f elf64 $< -o $@

clean			:
					$(RM) $(OBJ)
					echo -e '$(LIGHT_PURPLE) \tCleaned$(PURPLE) $(OBJ)'

fclean			:	clean
					$(RM) $(NAME)
					echo -e '$(LIGHT_PURPLE) \tCleaned$(DARK_PURPLE) $(NAME)'

re				:	fclean all

.PHONY			=	all clean fclean re
