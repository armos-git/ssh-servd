CC = gcc
CFLAGS =

SRC = ./src
INC = ./include
BLD = ./build
FLAGS = -g -Wall -I$(INC) $(CFLAGS)

all:	clean

	gcc -c $(FLAGS) -o $(BLD)/mem.o $(SRC)/mem.c
	gcc -c $(FLAGS) -o $(BLD)/log.o $(SRC)/log.c
	gcc -c $(FLAGS) -o $(BLD)/users.o $(SRC)/users.c
	gcc -c $(FLAGS) -o $(BLD)/handle_user.o $(SRC)/handle_user.c
	gcc $(FLAGS) -lssh -o testing $(SRC)/server.c $(BLD)/*.o config_tool.a

clean:
	rm -rf $(BLD)/* testing
