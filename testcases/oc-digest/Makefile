INCS	= -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
OPTLVL =  
CFLAGS	= $(OPTLVL) $(INCS) -DLINUX -g -m31

LDFLAGS = -lc  -ldl -lpthread -m31

#VPATH = ..

CC = gcc
LD = gcc


.c.o: ; $(CC)  -c -g $(CFLAGS) -o $@ $<


all: oc-digest

speed: oc-digest.o
	$(CC) $(LDFLAGS)  -o $@  oc-digest.o


clean:
	rm oc-digest oc-digest.o
