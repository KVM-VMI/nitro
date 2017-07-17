CC ?= gcc
CFLAGS += -std=gnu99 -Wall -O2
OUTDIR = build
SOURCES = $(wildcard *.c)
TARGETS = $(patsubst %.c, $(OUTDIR)/%, $(SOURCES))

all: outdir $(TARGETS)

outdir:
	mkdir -p $(OUTDIR)

$(OUTDIR)/%: %.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean

clean:
	rm -f $(TARGETS)
