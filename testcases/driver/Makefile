INCS	= -I. -I../../usr/include/pkcs11 -I../include
OPTLVL =  
CFLAGS	= $(OPTLVL) $(INCS) -DLINUX

LDFLAGS = -lc  -ldl -lpthread

#VPATH = ..

CC = gcc
LD = gcc

#OBJS = driver.o

DRIVER_OBJ =  des_func.o des3_func.o digest_func.o driver.o \
              dsa_func.o misc_func.o obj_mgmt.o rsa_func.o  \
              sess_mgmt.o ssl3_func.o md5.o dh_func.o


.c.o: ; $(CC)  -c -g $(CFLAGS) -o $@ $<


all: driver 

driver: $(DRIVER_OBJ)
	$(CC) $(LDFLAGS)  -o $@  $(DRIVER_OBJ)


clean:
	rm $(DRIVER_OBJ) driver

