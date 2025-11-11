BPF_CLANG       := clang
BPF_LLVM_STRIP  := llvm-strip
CC              := g++
CFLAGS          := -Wall -O2 -std=c++17
BPF_CFLAGS      := -O2 -g -target bpf -D__TARGET_ARCH_x86

LIBBPF_CFLAGS   := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")
LIBBPF_LDLIBS   := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

BUILD_DIR := build
BPF_SRCS := $(wildcard *.bpf.c)
USER_CPP := storefs_loader.cpp

BPF_OBJS := $(patsubst %.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))
USER_BIN := $(BUILD_DIR)/storefs_loader

all: $(BPF_OBJS) $(USER_BIN)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.bpf.o: %.bpf.c | $(BUILD_DIR)
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

$(USER_BIN): $(BUILD_DIR)/storefs.bpf.o $(USER_CPP) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(USER_CPP) -o $@ $(LIBBPF_LDLIBS)

clean:
	rm -rf $(BUILD_DIR)
.PHONY:
	all clean