INCS	= -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
OPTLVL =  
CFLAGS	= $(OPTLVL) $(INCS) -DLINUX

LDFLAGS = -lc  -ldl -lpthread

#VPATH = ..

CC = gcc
LD = gcc

#OBJS = driver.o



.c.o: ; $(CC)  -c -g $(CFLAGS) -o $@ $<


all: threadmkobj 

threadmkobj: threadmkobj.o
	$(CC) $(LDFLAGS)  -o $@  threadmkobj.o


clean:
	rm threadmkobj threadmkobj.o
