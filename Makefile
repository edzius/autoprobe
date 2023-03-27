.PHONY: install clean

INSTALL_E ?= cp -f
INSTALL_D ?= mkdir -p

INSTALL_DIR ?= out/

CC ?= $(CROSS_COMPILE)gcc

CFLAGS += -g -Os
CFLAGS += -std=gnu89
CFLAGS += -Wall
CFLAGS += -Wp,-MT,$@,-MD,$(@D)/.$(@F).d
CFLAGS += -D_GNU_SOURCE
ifneq ($(DEBUG),)
CFLAGS += -DDEBUG
endif

sources-y := \
	libkmod-index.c \
	libmodules.c \
	mod-index.c \
	mod-probe.c \
	autoprobe.c
objects-y := $(patsubst %.c,%.o,$(sources-y))
depends-y := $(wildcard .*.d)

all: autoprobe Makefile

%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS-$<) -c -o $@ $<

autoprobe: $(objects-y)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	$(INSTALL_D) $(INSTALL_DIR)/usr/bin
	$(INSTALL_E) autoprobe $(INSTALL_DIR)/usr/bin

clean:
	rm -f autoprobe *.o

-include $(depends-y)
