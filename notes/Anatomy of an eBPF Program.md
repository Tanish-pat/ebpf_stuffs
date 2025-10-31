## Anatomy of an eBPF Program

## The eBPF Virtual Machine
The eBPF virtual machine is a software implementation of a computer. It takes in a program in the form of eBPF bytecode instructions, and these have to be converted to native machine instructions that run on the CPU. Earlier, the eBPF programs were interpreted, but now they are just-in-time (JIT) compiled to native code for better performance. eBPF bytecode consists of a set of instructions, and those instructions act on (virtual) eBPF registers. The eBPF instruction set and register model were designed to map neatly to common CPU architectures so that the step of compiling or interpreting from bytecode to machine code is reasonably straightforward.

## eBPF Registers
The eBPF virtual machine uses 10 general-purpose registers, numbered 0 to 9. Additionally, Register 10 is used as a stack frame pointer (and can only be read, but not written). We can see them enumerated from BPF_REG_0 to BPF_REG_10 in the Linux kernel source code file `include/uapi/linux/bpf.h` header file.

The context argument to an eBPF program is loaded into Register 1 before its execution begins. The return value from the function is stored in Register 0. Before calling a function from eBPF code, the arguments to that function are placed in Register 1 through Register 5

## eBPF Instructions
```C
    struct bpf_insn {
    __u8 code;
    __u8 dst_reg:4;
    __u8 src_reg:4;
    __s16 off;
    __s32 imm;
    };
```
This bpf_insn structure is 64 bits (or 8 bytes) long and is defined in `include/uapi/linux/bpf.h` header file in the Linux kernel source code.
When loaded into the kernel, the bytecode of an eBPF program is represented by a series of these bpf_insn structures
Most of the different opcodes fall into the following categories:
* Load and Store Instructions
* Performance Arithmetic Instructions
* Jump Instructions


# Compiling an eBPF Object File

Compile C eBPF sources to eBPF bytecode with Clang using the `-target bpf` flag. The output is an ELF object containing relocatable eBPF instructions. Include headers and optimization/debug flags as needed. Example Makefile rule:

```
hello.bpf.o: %.o: %.c
	clang -target bpf \
	  -I/usr/include/$(shell uname -m)-linux-gnu \
	  -g -O2 -c $< -o $@
```

`-g` embeds BTF/debug info (useful for human-readable maps and variables). `-O2` is typical for production-grade code; reduce optimization during iterative development if you need straightforward mapping from source to bytecode. The compiler emits .o which you will load into the kernel. Validate toolchain compatibility and that Clang/LLVM target for BPF is installed before building.

# Inspecting an eBPF Object File

Validate the ELF and examine embedded bytecode and symbols. Use `file` to confirm format:

```
file hello.bpf.o
```

Use `llvm-objdump` (or `objdump` with BPF support) to disassemble and view section layout and instruction offsets. Example:

```
llvm-objdump -d hello.bpf.o
```

Inspect sections that map to `SEC()` annotations (e.g., `xdp`, `raw_tp`). The disassembly shows instruction opcodes, offsets, and human-readable register operations. If compiled with `-g`, BTF/debug symbols appear and help correlate source lines to bytecode. This stage is for verification — ensuring the compiler produced the expected functions, constants, and map references before loading.

# Loading the Program into the Kernel

Load and pin the object into the kernel with `bpftool`. Root privileges are required. Pinning persists the program to the BPF filesystem so it remains accessible:

```
sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello
```

A successful load typically emits no output; verify with `ls /sys/fs/bpf`. Pinning creates a stable handle (path) which can be used by tools or user-space programs later. For programmatic loading use libbpf or BPF syscalls; `bpftool` is the CLI analog for testing and operational workflows. Confirm kernel support for your program type (XDP, tracepoint, etc.) and that resource limits (rlimits/memlock) are sufficient.

# Inspecting the Loaded Program

Query runtime metadata and lifecycle state using `bpftool`. List programs:

```
sudo bpftool prog list
```

Get details (pretty JSON) for a specific program:

```
sudo bpftool prog show id <id> --pretty
```

Key fields include `id`, `type`, `name`, `tag`, `gpl_compatible`, `loaded_at`, `bytes_xlated`, `jited`, `bytes_jited`, `map_ids`, and `btf_id`. These tell you whether the verifier accepted the program, JIT status, memory locking, and referenced maps. Use `bpftool prog dump xlated name <name>` to see post-verifier bytecode and `bpftool prog dump jited name <name>` to inspect architecture-specific JIT output. Use this data for debugging, compliance, and performance analysis.

# The BPF Program Tag

The program tag is a stable SHA-based fingerprint of the program’s instructions. It does not change across reloads if the instructions remain identical; the numeric `id` can. Use the tag to reference the program reliably:

```
sudo bpftool prog show tag <tag>
```

Tags let you track program identity across reboots or reloads and enable deterministic comparisons between builds or deployments. Multiple instances can share a tag; the pinned path and `id` remain unique. Use tags in automation to detect if the code changed (CI/CD checks) or to reconcile running artifacts with the source-of-truth.

# The Translated Bytecode

`bytes_xlated` indicates the eBPF bytecode size after verifier processing and kernel-level transformations. To inspect:

```
sudo bpftool prog dump xlated name <name>
```

This shows the logical eBPF instruction stream the kernel will execute (or JIT from). The verifier may alter or reject constructs; the translated view is what the kernel actually accepted. Use this output to confirm map references, function calls, register usage, and to ensure the logical flow matches expectations. It’s the canonical representation for static analysis after verifier policies have been applied.

# The JIT-Compiled Machine Code

For performance, the kernel JIT-compiles eBPF bytecode to native machine code; the `jited` flag and `bytes_jited` quantify that. Inspect JIT output with:

```
sudo bpftool prog dump jited name <name>
```

JIT output is architecture-specific assembly and shows stack usage, register mappings and the real instruction sequence executed by the CPU. JIT improves throughput and latency for hot eBPF paths (e.g., XDP). Confirm the JIT is enabled on the host and consider disabling it only for specialized debugging. Use `bytes_jited` to profile compiled footprint vs. interpreted `bytes_xlated`.

# Attaching to an Event

Program `type` must match the attach point. For an XDP program attach with `bpftool`:

```
sudo bpftool net attach xdp id <id> dev eth0
```

Or use name/tag/pinned path instead of id. Verify attachments:

```
sudo bpftool net list
ip link show
```

Different types map to different hooks: XDP (network ingress), tc (traffic control), tracepoints, kprobes, raw_tracepoints, etc. Ensure interface supports the hook (some drivers or modes restrict XDP). When attaching programmatically use libbpf or `bpf()` syscall wrappers. Always validate the resulting state (attached, jited, driver compatibility) and monitor `trace_pipe` or metrics to confirm expected behavior.

# Global Variables

Global data in eBPF is implemented via maps. Use maps to store counters, readonly data, or state shared between runs or programs. Create and reference maps in C using map definitions; the compiler and loader create kernel map objects. Inspect maps:

```
sudo bpftool map list
sudo bpftool map dump id <id>
```

If compiled with `-g` (BTF), `bpftool` can pretty-print variable names. Without BTF you see raw keys/values. Maps provide durability across invocations and are accessible from both kernel and user-space (via file descriptors). Use maps for rate-limiting, counters, configuration, or lookup tables — design maps for concurrency, bounded memory, and verifier constraints.

# Detaching the Program

Detach a program from an attached hook when you need to stop execution without unloading the artifact:

```
sudo bpftool net detach xdp dev eth0
```

A successful detach produces no output; confirm with `bpftool net list`. Detaching prevents the eBPF program from executing on new events but does not free the loaded program or maps. This is your operational knob for graceful deactivation during testing, rollout, or debugging. For automated workflows, ensure detached programs are handled idempotently and that you verify iface state after detachment.

# Unloading the Program

Unloading removes the program from the kernel by deleting its pinned handle. Remove the pinned object:

```
sudo rm /sys/fs/bpf/hello
```

Then verify the program is gone:

```
sudo bpftool prog show name hello
```

No output means it’s unloaded. There is no direct inverse CLI to `bpftool prog load`, so deleting the pinned file is the standard operational pattern. Remove or destroy associated maps if they are no longer required. Coordinate unloads with detach steps to avoid race conditions and follow change-control procedures to prevent unintended service impact.

# BPF to BPF Calls

Modern eBPF supports function calls between BPF functions. Use `__attribute__((noinline))` to prevent inlining when you need discrete call semantics for demonstration or analysis. Example:

```c
static __attribute__((noinline)) int get_opcode(struct bpf_raw_tracepoint_args *ctx) {
    return ctx->args[1];
}

SEC("raw_tp")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = get_opcode(ctx);
    bpf_printk("Syscall: %d", opcode);
    return 0;
}
```

Inspect translated bytecode to see `call` instructions:

```
sudo bpftool prog dump xlated name hello
```

Calls save state on the limited 512-byte eBPF stack, so depth is constrained; avoid deep recursion. Use BPF-to-BPF calls to factor logic, reduce duplication, and improve maintainability while respecting verifier and stack limits.
