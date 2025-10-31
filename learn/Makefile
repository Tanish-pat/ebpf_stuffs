BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip

ARCH_INCLUDE := /usr/include/x86_64-linux-gnu
TARGET = xdp_count.o
SRC = xdp_count.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(BPF_CLANG) -O2 -g -target bpf \
	-I/usr/include \
	-I$(ARCH_INCLUDE) \
	-c $(SRC) -o $(TARGET)
	$(BPF_LLVM_STRIP) -g $(TARGET) || true

clean:
	rm -f $(TARGET)
