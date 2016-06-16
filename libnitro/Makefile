CC = gcc

TARGET = nitro
LIBTARGET = libnitro
CFLAGS = -g -Wall
DEPS = libnitro.h
LIBOBJ = libnitro.o
OBJ = nitro_main.o $(LIBOBJ)

.PHONY: default all clean

default: $(TARGET) $(LIBTARGET)
all: default

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

$(LIBTARGET): 
	ar -cvq $(LIBTARGET).a $(LIBOBJ)

clean:
	-rm -f *.o
	-rm -f $(TARGET)
	-rm -f $(LIBTARGET).a