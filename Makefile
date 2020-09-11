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

LIBS := $(LIB_OBJ)/server_operations.o $(LIB_OBJ)/tools.o
INCL := -I$(LIB)



### PHONY RULES ###

.PHONY: default exploit server server_enable server_disable check_server all clean
default: all

all: exploit server_enable server_disable check_server
server: server_enable server_disable check_server
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

# The server-enable program
$(BIN)/server_enable: $(OBJ)/server_enable.o $(LIBS) | $(BIN)
	$(GCC) $(GCC_ARGS) -o $@ $^ $(EXT_LIBS)
server_enable: $(BIN)/server_enable

# The standalone server DoS attack
$(BIN)/server_disable: $(OBJ)/server_disable.o $(LIBS) | $(BIN)
	$(GCC) $(GCC_ARGS) -o $@ $^ $(EXT_LIBS)
server_disable: $(BIN)/server_disable

# The server status check
$(BIN)/check_server: $(OBJ)/check_server.o $(LIBS) | $(BIN)
	$(GCC) $(GCC_ARGS) -o $@ $^ $(EXT_LIBS)
check_server: $(BIN)/check_server
