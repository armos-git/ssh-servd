CC = gcc
CFLAGS =

SRC = ./src
INC = ./include
BLD = ./build
FLAGS = -I$(INC) $(CFLAGS)

all:	clean

	gcc -c $(FLAGS) -o $(BLD)/log.o $(SRC)/log.c
	gcc $(FLAGS) -o testing $(SRC)/test.c $(BLD)/log.o

clean:
	rm -rf $(BLD)/*
