INCS	= -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
OPTLVL =  
CFLAGS	= $(OPTLVL) $(INCS) -DLINUX

LDFLAGS = -lc  -ldl -lpthread

#VPATH = ..

CC = gcc
LD = gcc

#OBJS = driver.o



.c.o: ; $(CC)  -c -g $(CFLAGS) -o $@ $<


all: mkobj 

mkobj: mkobj.o
	$(CC) $(LDFLAGS)  -o $@  mkobj.o


clean:
	rm mkobj mkobj.o
