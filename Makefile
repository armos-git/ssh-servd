CC = gcc
FLAGS = -g -Wall -I$(INC) $(CFLAGS)
CFLAGS =
LDFLAGS = -lssh -ldl -lcrypt
AR = ar

SRC = src
INC = include
BLD = build

SRCS = mem.c log.c users.c handle_user.c server.c
SOURCES = $(SRCS:%.c=$(SRC)/%.c)
OBJ = $(SRCS:%.c=$(BLD)/%.o)
OUT = testing



all:	$(SOURCES) $(OUT)

$(OUT):	objs.a

	$(CC) $(FLAGS) $(LDFLAGS) -o $(OUT) $(BLD)/objs.a config_tool.a

objs.a:	$(OBJ)

	$(AR) cr $(BLD)/objs.a $(OBJ) $(LIB)

$(BLD)/%.o: $(SRC)/%.c

	$(CC) -c $(FLAGS) -o $@ $< 

debug:	clean

	make FLAGS='$(FLAGS) -D SERV_DEBUG'

shell:
	$(CC) -shared -fPIC $(FLAGS) -o shell_example.mod $(SRC)/shell_example.c

clean:
	rm -rf $(BLD)/* $(OUT)
