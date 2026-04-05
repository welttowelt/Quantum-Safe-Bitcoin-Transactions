CC = gcc
CFLAGS = -O3 -march=native -fopenmp -Wall
LDFLAGS = -lsecp256k1 -lcrypto -lm -fopenmp

all: qsb_search

qsb_search: qsb_search.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f qsb_search

.PHONY: all clean
