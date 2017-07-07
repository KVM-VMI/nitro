CC ?= gcc
CFLAGS += -std=gnu99 -Wall -O2

all: open

open: open.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean

clean:
	rm -f open
