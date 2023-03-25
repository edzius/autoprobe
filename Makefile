
CC = gcc
CFLAGS = -D_GNU_SOURCE
CFLAGS += -g -O2

all: autoprobe

autoprobe: autoprobe.c mod-probe.c mod-index.c libmodules.c libkmod-index.c

clean:
	rm -f autoprobe *.o
