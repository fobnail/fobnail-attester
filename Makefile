CC=gcc
CFLAGS=-Wall -O2
BIN=fobnail-attester
#LDFLAGS="-lcoap"

all:
	$(CC) $(CFLAGS) -o $(BIN) fobnail-attester.c -lcoap-2-tinydtls
clean:
	rm -f $(BIN)
