# **List of eBPF Helper Functions**

- `bpf_printk()`

   * **Purpose:** Writes messages to the kernel trace buffer.
   * **Usage Context:** Used in the simple “Hello World” example.
   * **Output Location:** `/sys/kernel/debug/tracing/trace_pipe`.
   * **Behavior:** Enables debugging/logging by sending trace output from kernel space.

- `bpf_trace_printk()`

   * **Purpose:** Writes messages to the kernel trace buffer.
   * **Usage Context:** Used in the simple “Hello World” example.
   * **Output Location:** `/sys/kernel/debug/tracing/trace_pipe`.
   * **Behavior:** Enables debugging/logging by sending trace output from kernel space.

    | **Aspect**          | **`bpf_printk()`**                               | **`bpf_trace_printk()`**                        |
    | ------------------- | ------------------------------------------------ | ----------------------------------------------- |
    | **Status**          | Modern, preferred API.                           | Deprecated, legacy API.                         |
    | **Kernel Version**  | Introduced in Linux 5.2+.                        | Pre-5.2 kernels.                                |
    | **Header Location** | `<bpf/bpf_helpers.h>`                            | `<uapi/linux/bpf.h>` (older).                   |
    | **Output Location** | `/sys/kernel/debug/tracing/trace_pipe`           | Same output location.                           |
    | **Format Support**  | Standard `printf`-like format (safer, stricter). | Limited format support (less robust).           |
    | **Verification**    | Better verifier compatibility and type safety.   | May trigger verifier warnings in newer kernels. |
    | **Recommendation**  | Use `bpf_printk()` for all new eBPF programs.    | Avoid unless maintaining legacy code.           |


- `bpf_get_current_pid_tgid()`

   * **Purpose:** Retrieves the process and thread IDs.
   * **Return Value:** 64-bit integer — upper 32 bits = PID, lower 32 bits = TGID.
   * **Usage:** Extracts the process ID of the process that triggered the eBPF program.

- `bpf_get_current_uid_gid()`

   * **Purpose:** Obtains the user ID (UID) and group ID (GID) of the process.
   * **Return Value:** 64-bit integer — lower 32 bits = UID, upper 32 bits = GID.
   * **Usage:** Identifies which user triggered the probe; used for per-user statistics tracking.

- `bpf_get_current_comm()`

   * **Purpose:** Fetches the command name (executable name) of the current process.
   * **Usage:** Populates a string buffer (e.g., `data.command`) with the current process name.
   * **Notes:** Requires passing a pointer to the destination buffer and its size.

- `bpf_probe_read_kernel()`

   * **Purpose:** Safely reads data from kernel memory.
   * **Usage:** Copies data (e.g., the `"Hello World"` message) into a structure before sending it to user space.
   * **Notes:** Prevents invalid memory access when copying kernel data.

- `output.perf_submit()` (via `BPF_PERF_OUTPUT`)

   * **Purpose:** Sends structured data from kernel space to user space through a perf ring buffer.
   * **Usage:** Transfers event data (`struct data_t`) to user space consumers.
   * **Context:** Used for high-performance data communication between eBPF and user-space BCC scripts.

- `bpf_tail_call()`

   * **Purpose:** Performs a tail call to another eBPF program.
   * **Usage Context:** Enables chaining of eBPF programs for modular functionality.
   * **Notes:** Helps in managing program size limits by splitting logic across multiple programs.