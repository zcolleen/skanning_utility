
NAME = scan_util

CC = clang++

FLAGS = -Wall -Wextra -Werror --std=c++14

HEADER = SkanUtility.hpp

SRCS = main.cpp SkanUtility.cpp

OBJS = $(SRCS:.cpp=.o)

%.o: %.cpp $(HEADER)
		$(CC) $(FLAGS) -c $< -o $@

all: $(NAME)

$(NAME): $(OBJS)
		$(CC) $(FLAGS) $(OBJS) -o $(NAME)

clean:
		rm -rf $(OBJS)

fclean:
		rm -rf $(OBJS) $(NAME)

re: fclean all


.PHONY: all clean fclean re