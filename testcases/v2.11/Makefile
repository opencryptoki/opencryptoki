INCS    = -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
OPTLVL =
CFLAGS  = $(OPTLVL) $(INCS) -DLINUX $(M31FLAG)

LDFLAGS = -lc  -ldl -lpthread $(M31FLAG)

#VPATH = ..

CC = gcc
LD = gcc


.c.o: ; $(CC) -c -g $(CFLAGS) -o $@ $<


all: login aes_func rijndael hw_fn

rijndael: rijndael.o
	$(CC) $(LDFLAGS)  -o $@  rijndael.o

login: login.o
	$(CC) $(LDFLAGS)  -o $@  login.o

aes_func: aes_func.o
	$(CC) $(LDFLAGS)  -o $@ aes_func.o

hw_fn: hw_fn.o
	$(CC) $(LDFLAGS)  -o $@ hw_fn.o

clean:
	rm -f login rijndael aes_func hw_fn *.o

