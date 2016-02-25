CC = gcc
CFLAGS = -Wall -Werror
BIN = mydump
LIBS =

SRC = $(wildcard *.c)

all: $(BIN)

debug: CFLAGS += -g -DDEBUG -DCOLOR
debug: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f $(BIN) *.o
