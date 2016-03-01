CC = gcc
CFLAGS = -Wall -Werror -DCOLOR
BIN = mydump
LIBS =

SRC = $(wildcard *.c)

.DEFAULT_GOAL := help

all: $(BIN) ## Generates all programs that this makefile can generate.

debug: CFLAGS += -g -DDEBUG
debug: $(BIN) ## Generates a binary with debugging symbols and debug print statements.

mydump: $(SRC) ## Generates the mydump program
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean: ## Removes all source binaries and object files.
	rm -f $(BIN) *.o

.PHONY: help
help: ## Generates this help menu.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
