CC = gcc
CFLAGS =

SRC = ./src
INC = ./include
BLD = ./build
OUT = testing

FLAGS = -g -Wall -I$(INC) $(CFLAGS)

all:	clean

	$(CC) -c $(FLAGS) -o $(BLD)/mem.o $(SRC)/mem.c
	$(CC) -c $(FLAGS) -o $(BLD)/log.o $(SRC)/log.c
	$(CC) -c $(FLAGS) -o $(BLD)/users.o $(SRC)/users.c
	$(CC) -c $(FLAGS) -o $(BLD)/handle_user.o $(SRC)/handle_user.c
	$(CC) $(FLAGS) -lssh -ldl -o $(OUT) $(SRC)/server.c $(BLD)/*.o config_tool.a

shell:
	$(CC) -shared -fPIC $(FLAGS) -o shell_example.mod $(SRC)/shell_example.c
clean:
	rm -rf $(BLD)/* $(OUT)
