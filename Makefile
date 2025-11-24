NAME	:= woody_woodpacker

CC		:= cc
CFLAGS	:= -Wall -Wextra -Werror

SRC_DIR	:= src
INC_DIR	:= inc

SRC		:= $(SRC_DIR)/parser.c
OBJ		:= $(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
