INCS	= -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
OPTLVL =  
CFLAGS	= $(OPTLVL) $(INCS) -DLINUX

LDFLAGS = -lc  -ldl -lpthread

#VPATH = ..

CC = gcc
LD = gcc

#OBJS = driver.o



.c.o: ; $(CC)  -c -g $(CFLAGS) -o $@ $<


all: test_crypto 

test_crypto: test_crypto.o
	$(CC) $(LDFLAGS)  -o $@  test_crypto.o


clean:
	rm test_crypto test_crypto.o
