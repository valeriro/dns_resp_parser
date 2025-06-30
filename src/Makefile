CC = gcc
CFLAGS = -Wall  -g

SRC = main.c dns_resp_parser.c
OBJ = $(SRC:.c=.o)

BIN = dns_resp_parser

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJ) $(BIN)

