INCS	= -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
OPTLVL =  
CFLAGS	= $(OPTLVL) $(INCS) -DLINUX

LDFLAGS = -lc  -ldl -lpthread

#VPATH = ..

CC = gcc
LD = gcc

#OBJS = driver.o



.c.o: ; $(CC)  -c -g $(CFLAGS) -o $@ $<


all: rsa_test rsa_thread_test rsa_test_genkey

rsa_test: rsa_test.o
	$(CC) $(LDFLAGS)  -o $@  rsa_test.o

rsa_thread_test: rsa_thread_test.o
	$(CC) $(LDFLAGS)  -o $@  rsa_thread_test.o

rsa_test_genkey: rsa_test_genkey.o 
	$(CC) $(LDFLAGS)  -o $@  rsa_test_genkey.o

clean:
	rm rsa_test rsa_thread_test rsa_test_genkey *.o
