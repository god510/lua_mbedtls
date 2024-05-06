CC = gcc
LUA_LIB= -L../../lua -llua
LUA_INC= -I../../lua
MBEDTLS_LIB=-L../../mbedtls/library/ -lmbedcrypto
MBEDTLS_INC= -I../../mbedtls/include
EXTRACFLAGS= -std=c99 -fPIC


INC= $(LUA_INC) $(MBEDTLS_INC)
LIB= $(LUA_LIB)
WARN= -Wall
CFLAGS= -O2 $(WARN) $(INC)

LIBNAME= mbedtls
T= $(LIBNAME).so
OBJS= l$(LIBNAME).o \
		lmbedtls_gcm.o \
		lmbedtls_aes.o \
		lmbedtls_sha256.o \
		lmbedtls_base64.o \
		lmbedtls_md5.o \
		common.o


all: $T

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

$T:	$(OBJS)
	$(CC) $(CFLAGS) $(LIB) $(EXTRACFLAGS) -o $@ -shared $(OBJS) $(MBEDTLS_LIB)

clean:
	rm -f $T $(OBJS)

clean-all:
	rm -f $T $(OBJS)


test: clean all 

install: $(TARGET)
