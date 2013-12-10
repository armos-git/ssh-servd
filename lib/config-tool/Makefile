########################################
CC	= gcc
CFLAGS	=
FLAGS	= -Wall -I$(INC) $(CFLAGS)
prefix  = /usr
########################################


MAIN	= config_tool
PROG1	= config_test_simple
PROG2	= config_test_subject

SRC	= ./src
INC	= ./include
BUILD	= ./build

OPT	= none


static:

	make config-tool
	ar cr $(MAIN).a $(BUILD)/*.o 

config-tool: clean 

	mkdir $(BUILD)
	$(CC) $(FLAGS) -c -o $(BUILD)/hash.o $(SRC)/hash.c 
	$(CC) $(FLAGS) -c -D $(OPT) -o $(BUILD)/llist.o $(SRC)/llist.c 
	$(CC) $(FLAGS) -c -D $(OPT) -o $(BUILD)/$(MAIN).o $(SRC)/$(MAIN).c

shared:
	make static FLAGS='$(FLAGS) -fPIC'
	$(CC) -shared -fPIC $(FLAGS) -o lib$(MAIN).so $(MAIN).a

example:	clean_example

	make static
	$(CC) $(FLAGS) -o $(PROG1) $(SRC)/$(PROG1).c $(MAIN).a
	$(CC) $(FLAGS) -o $(PROG2) $(SRC)/$(PROG2).c $(MAIN).a

install:
	cp *$(MAIN).* $(prefix)/lib
	cp $(INC)/config_tool.h $(prefix)/include

clean:
	rm -rf $(BUILD)
	rm -rf *$(MAIN).*

clean_example:
	rm -rf $(PROG1) $(PROG2)

clean_all:
	make clean
	make clean_example
