# MAKEFILE for CNS ASSIGNMENT 2
#   by DukeD1rtfarm3r

### CONSTANTS ###
GCC := gcc
GCC_ARGS := -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE
EXT_LIBS := -lnet -lpcap

SRC := src
LIB := $(SRC)/lib
BIN := bin
OBJ := $(BIN)/obj
LIB_OBJ := $(OBJ)/lib

LIBS := $(LIB_OBJ)/test_server_status.o $(LIB_OBJ)/tools.o
INCL := -I$(LIB)



### PHONY RULES ###

.PHONY: default exploit check_server all clean
default: all

all: exploit check_server
clean:
	rm -f $(BIN)/exploit
	rm -f $(BIN)/check_server
	rm -f $(OBJ)/*.o



### DIRECTORY RULES ###

$(BIN):
	mkdir -p $@
$(OBJ): $(BIN)
	mkdir -p $@
$(LIB_OBJ): $(OBJ)
	mkdir -p $@



### COMPILATION RULES ###

# Any object file in source
$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)
	$(GCC) $(GCC_ARGS) $(INCL) -o $@ -c $<
# Any object file in lib
$(LIB_OBJ)/%.o: $(LIB)/%.c | $(LIB_OBJ)
	$(GCC) $(GCC_ARGS) $(INCL) -o $@ -c $<

# The exploit itself
$(BIN)/exploit: $(OBJ)/exploit.o $(LIBS) | $(BIN)
	$(GCC) $(GCC_ARGS) -o $@ $^ $(EXT_LIBS)
exploit: $(BIN)/exploit

# The server status check
$(BIN)/check_server: $(OBJ)/check_server.o $(LIBS) | $(BIN)
	$(GCC) $(GCC_ARGS) -o $@ $^ $(EXT_LIBS)
check_server: $(BIN)/check_server
