CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto -pthread

SRC_DIR = src
BIN_DIR = bin
DOC_DIR = doc

all: $(BIN_DIR)/proxy

$(BIN_DIR)/proxy: $(SRC_DIR)/proxy.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/proxy $(SRC_DIR)/proxy.c $(LDFLAGS)

clean:
	rm -f $(BIN_DIR)/proxy
