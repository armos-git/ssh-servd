CC = gcc
CFLAGS =

SRC = ./src
INC = ./include
BLD = ./build
FLAGS = -I$(INC) $(CFLAGS)

all:	clean

	gcc -c $(FLAGS) -o $(BLD)/log.o $(SRC)/log.c
	gcc -c $(FLAGS) -o $(BLD)/users.o $(SRC)/users.c
	gcc $(FLAGS) -lssh -o testing $(SRC)/server.c $(BLD)/*.o

clean:
	rm -rf $(BLD)/* testing
