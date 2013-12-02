CC = gcc
FLAGS = -g -Wall $(INC) $(CFLAGS)
CFLAGS =
LDFLAGS = -L/usr/lib -lssh -ldl -lcrypt
AR = ar

SRC = src
INC = -Iinclude -I$(LIB)/include
BLD = build
LIB = lib/config-tool

SRCS = mem.c log.c users.c handle_user.c server.c
SOURCES = $(SRCS:%.c=$(SRC)/%.c)
OBJ = $(SRCS:%.c=$(BLD)/%.o)
OUT = testing



all:	$(BLD) $(LIB)/config_tool.a $(SOURCES) $(OUT)

$(OUT):	objs.a

	$(CC) $(FLAGS) $(LDFLAGS) -o $(OUT) $(BLD)/objs.a $(LIB)/config_tool.a

objs.a:	$(OBJ)

	$(AR) cr $(BLD)/objs.a $(OBJ)

$(LIB)/config_tool.a: $(LIB)

	cd $(LIB); make
	
$(BLD)/%.o: $(SRC)/%.c

	$(CC) -c $(FLAGS) -o $@ $< 

$(BLD):
	mkdir $(BLD)

debug:	clean

	make FLAGS='$(FLAGS) -D SERV_DEBUG'

shell:
	$(CC) -shared -fPIC $(FLAGS) -o shell_example.mod $(SRC)/shell_example.c

clean:
	rm -rf $(BLD)/* $(OUT)
