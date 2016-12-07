CC=gcc
CFLAGS=-lpthread -Wall

all: worm

worm: worm.c scanner.c bruteforce.c spread.c exploit.c
	${CC} -o $@ $^ ${CFLAGS}

clean:
	rm -f worm
