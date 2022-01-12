CC=gcc
CFLAGS=-Wall -O2
BIN=fobnail-attester
#LDFLAGS="-lcoap"

all:
	$(CC) $(CFLAGS) -o $(BIN) fobnail-attester.c -lcoap-3
clean:
	rm -f $(BIN)
