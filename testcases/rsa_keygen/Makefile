INCS	= -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
OPTLVL =  
CFLAGS	= $(OPTLVL) $(INCS) -DLINUX

LDFLAGS = -lc  -ldl -lpthread

#VPATH = ..

CC = gcc
LD = gcc

#OBJS = driver.o



.c.o: ; $(CC)  -c -g $(CFLAGS) -o $@ $<


all: rsa_keygen 

rsa_keygen: rsa_keygen.o
	$(CC) $(LDFLAGS)  -o $@  rsa_keygen.o


clean:
	rm rsa_keygen rsa_keygen.o
