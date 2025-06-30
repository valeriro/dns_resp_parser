# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -I../src

# Source files
SRC_DIR = ../src
TEST_SRC = tests_dns_resp_parser.c
TEST_BIN = tests_dns_resp_parser

# Object files
TEST_OBJ = tests_dns_resp_parser.o
PARSER_OBJ = $(SRC_DIR)/dns_resp_parser.o

.PHONY: all clean run

# Default target
all: $(TEST_BIN)

# Build test binary
$(TEST_BIN): $(TEST_OBJ) $(PARSER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile test source
$(TEST_OBJ): $(TEST_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile dns_parser.o from src
$(PARSER_OBJ): $(SRC_DIR)/dns_resp_parser.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run the test
run: all
	./$(TEST_BIN)

# Clean test binaries and objects
clean:
	rm -f *.o $(TEST_BIN) $(PARSER_OBJ)

