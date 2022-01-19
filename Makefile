CC=gcc
CFLAGS=-Wall -O2
BIN=fobnail-attester
#LDFLAGS="-lcoap"

all:
	$(CC) $(CFLAGS) -o $(BIN) fobnail-attester.c meta.c -lcoap-3
clean:
	rm -f $(BIN)
