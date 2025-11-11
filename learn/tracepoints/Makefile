# Compiler setup
BPF_CLANG      	:= clang
BPF_LLVM_STRIP 	:= llvm-strip
CC 			   	:= g++
# Compiler flags
CFLAGS 		   	:= -Wall -O2 -std=c++17
BPF_CFLAGS     	:= -O2 -g -target bpf -D__TARGET_ARCH_x86

# Include paths (adjust if needed)
LIBBPF_CFLAGS  	:= $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")
LIBBPF_LDLIBS  	:= $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf")

# Directories
BPF_DIR        	:= .
BUILD_DIR      	:= build

# Detect source files
BPF_SRCS       	:= $(wildcard $(BPF_DIR)/*.bpf.c)
USER_SRCS      	:= $(filter-out $(BPF_SRCS), $(wildcard $(BPF_DIR)/*.c))

# Derived object names
BPF_OBJS       	:= $(patsubst $(BPF_DIR)/%.bpf.c, $(BUILD_DIR)/%.bpf.o, $(BPF_SRCS))
USER_OBJS      	:= $(patsubst $(BPF_DIR)/%.c, $(BUILD_DIR)/%, $(USER_SRCS))

# Default target: build everything
.PHONY: all
all: $(USER_OBJS)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Rule: build eBPF object (.bpf.c → .bpf.o)
$(BUILD_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c | $(BUILD_DIR)
	@echo "[BPF] Compiling $<"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

# Rule: build user-space loader (name.c + matching .bpf.o)
$(BUILD_DIR)/%: $(BPF_DIR)/%.cpp $(BUILD_DIR)/%.bpf.o | $(BUILD_DIR)
	@echo "[USER] Compiling $<"
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LDLIBS)

# Pattern rule to allow: make <name>
# e.g. "make xdp_prog" → builds build/xdp_prog
%:
	@$(MAKE) $(BUILD_DIR)/$@

# Prevent intermediate files from being deleted
.SECONDARY: $(BPF_OBJS)

# Clean targets
.PHONY: clean
clean:
	@echo "[CLEAN]"
	@find $(BUILD_DIR) -type f -delete

# Debug info
.PHONY: list
list:
	@echo "Detected eBPF sources: $(BPF_SRCS)"
	@echo "Detected user sources: $(USER_SRCS)"
