INCS	= -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
OPTLVL =  
CFLAGS	= $(OPTLVL) $(INCS) -DLINUX

LDFLAGS = -lc  -ldl -lpthread

#VPATH = ..

CC = gcc
LD = gcc

#OBJS = driver.o



.c.o: ; $(CC)  -c -g $(CFLAGS) -o $@ $<


all: init_tok 

init_tok: init_tok.o
	$(CC) $(LDFLAGS)  -o $@  init_tok.o


clean:
	rm init_tok init_tok.o
