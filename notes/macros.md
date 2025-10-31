# BCC & BPF MACROS

- **`SEC()`**
    * defines a section called xdp that you’ll be able to see in the compiled object file.
    * used to identify different eBPF program types and maps when the eBPF program is loaded into the kernel.

- **`BPF_HASH()`**
    * creates a hash map in eBPF.
    * takes three arguments: the name of the map, the type of the key, and the type of the value.
    * used to store and retrieve data in key-value pairs.

- **`BPF_PERF_OUTPUT()`**
    * creates a perf event output map.
    * used to send data from the eBPF program to user-space applications efficiently.

- **`BPF_PROG_ARRAY()`**
    * creates a program array map.
    * used to store references to other eBPF programs, allowing for dynamic program calls.

- **` RAW_TRACEPOINT_PROBE()`**
    * defines a raw tracepoint probe.
    * used to attach eBPF programs to specific tracepoints in the kernel for monitoring and debugging.

- **`

- **`