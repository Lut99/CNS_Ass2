# MAKEFILE for CNS ASSIGNMENT 2
#   by DukeD1rtfarm3r

### CONSTANTS ###
GCC := gcc
GCC_ARGS := -O2 -Wall -Wextra -std=c11
EXT_LIBS := -lnet -lpcap

SRC := src
BIN := bin
OBJ := $(BIN)/obj

LIBS := 



### PHONY RULES ###

.PHONY: default exploit all clean
default: all

all: exploit
clean:
	rm -f $(BIN)/exploit
	rm -f $(OBJ)/*.o



### DIRECTORY RULES ###

$(BIN):
	mkdir -p $@
$(OBJ): $(BIN)
	mkdir -p $@



### COMPILATION RULES ###

# Any object file in source
$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)
	$(GCC) $(GCC_ARGS) -o $@ -c $<

# The exploit itself
$(BIN)/exploit: $(OBJ)/exploit.o $(LIBS) | $(BIN)
	$(GCC) $(GCC_ARGS) -o $@ $^ $(EXT_LIBS)
exploit: $(BIN)/exploit
