CC = gcc
CFLAGS = -Wall -Werror -DCOLOR
BIN = mydump
LIBS =

SRC = $(wildcard *.c)

all: $(BIN)

debug: CFLAGS += -g -DDEBUG
debug: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f $(BIN) *.o
