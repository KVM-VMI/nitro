TARGET = nitro
CC = gcc
CFLAGS = -g -Wall
HEAD = kfuncs.h
OBJ = kfuncs.o nitro_main.o

.PHONY: default all clean

default: $(TARGET)
all: default

%.o: %.c $(HEAD)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

clean:
	-rm -f *.o
	-rm -f $(TARGET)