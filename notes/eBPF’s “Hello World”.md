# eBPF "Hello World" Example Using BCC (Python)

```python
#!/usr/bin/python
from bcc import BPF

program = r"""
int hello_func(void *ctx) {
    bpf_trace_printk("Hello World!\n");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello_func")
b.trace_print()
```

* **Trigger Event:**
Every time any process invokes `execve()` (i.e., executes a new program), the kernel triggers the attached eBPF function `hello_func()` before the system call executes.
* **Behavior:**
Whenever `execve` is called by any application, the `hello_func()` eBPF program runs and writes a trace line into a kernel pseudofile.

---
## Key Components
### 1. **Helper Function: `bpf_trace_printk()`**
* Purpose: Writes a message to the kernel trace buffer.
* Functionality: Allows eBPF programs to output trace logs.
* Location: `/sys/kernel/debug/tracing/trace_pipe`
### 2. **Helper Functions**
* eBPF programs can invoke a defined set of helper functions to interact with kernel components and system resources.
### 3. **Program Definition**
* The eBPF program is defined as a **string** (`program`) in the Python script.
### 4. **BPF Object Creation**
* The string containing the eBPF code is passed as a parameter when creating a `BPF` object:
    ```python
    b = BPF(text=program)
    ```
### 5. **Attaching to Events**
* eBPF programs must be attached to specific kernel events.
* In this example, the attachment is done using:
    ```python
    b.attach_kprobe(event=syscall, fn_name="hello_func")
    ```
* The event: `execve` syscall.
* The attached function: `hello_func()`.
---
**Outcome:**
Each time a process calls `execve()`, the eBPF function `hello_func()` executes and logs `"Hello World!"` to the kernel trace output.
As soon as the eBPF program is loaded and attached to an event, it gets triggered by events that are being generated from preexisting processes.
---

# eBPF Maps
A map is a data structure that can be accessed from an eBPF program and from userspace. Maps can be used to share data among multiple eBPF programs or to communicate
between a user space application and eBPF code running in the kernel. BPF maps defined in Linux’s **`uapi/linux/bpf.h`** fil. There are Maps for hash tables, perf and ring buffers.

Typical uses include the following:
* User space writing configuration information to be retrieved by an eBPF program
* An eBPF program storing state, for later retrieval by another eBPF program
* An eBPF program writing results or metrics into a map, for retrieval by the userspace app that will present results

Types of Maps:
* sockmaps and devmaps hold information about sockets and network devices and are used by network-related eBPF programs to redirect traffic
* There are map types that are optimized for particular types of operations, such as first-in-first-out queues, first-in-last-out stacks, least-recently-used data storage, longest-prefix matching, and Bloom filters
* There’s even a map of-maps type to support storing information about maps within other maps.

## Hash Table Map
It’s going to populate a hash table with key–value pairs, where the key is a user ID and the value is a counter for the number of times execve is called by a process running under that user ID.

```python
#!/usr/bin/python
from bcc import BPF
import time
program=r"""
BPF_HASH(counter_table);
int hello_func(void *ctx) {
    u64 uid;
    u64 counter=0;
    u64 *p;
    uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p=counter_table.lookup(&uid);
    if(p!=0)
        counter=*p;
    counter++;
    counter_table.update(&uid,&counter);
    return 0;
}
"""
b=BPF(text=program)
syscall=b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall,fn_name="hello_func")
while True:
    time.sleep(2)
    s=""
    for k,v in b["counter_table"].items():
        s+=f"ID {k.value}: {v.value}\t"
    print(s)
```
1. BPF_HASH() is a BCC macro that defines a hash table map
2. bpf_get_current_uid_gid() is a helper function used to obtain the user ID that is running the process that triggered this kprobe event. The user ID is held in the lowest 32 bits of the 64-bit value that gets returned. (The top 32 bits hold the group ID, but that part is masked out.)
3. Then we look for an entry in the hash table with a key matching the user ID. If no such entry exists, we create one with an initial value of zero.
4. Finally, we increment the counter for that user ID.

The hello function executes on every execve syscall trigger.
It retrieves the UID of the calling process, looks up its current execution count in the BPF hash map, increments it, and updates the entry.
In essence, it tracks how many times each user executes a program.


## Perf and Ring Buffer Maps
A ring buffer is memory organized as a circular queue with separate read and write pointers. Data is written with a length header; the write pointer advances accordingly. Reads use the header to determine how much data to consume, advancing the read pointer similarly.

If the read pointer equals the write pointer, there’s no data to read. If a write would surpass the read pointer, data is dropped, and a counter tracks losses. Buffer size must be tuned to handle timing variability between reads and writes.

```python
#!/usr/bin/python
from bcc import BPF
import time
program=r"""
    BPF_PERF_OUTPUT(output);
    struct data_t {
        int pid,uid;
        char command[16], message[12];
    };
    int hello(void *ctx) {
        struct data_t data = {};
        char message[12]="Hello World";
        data.pid=bpf_get_current_pid_tgid() >> 32;
        data.uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;

        bpf_get_current_comm(&data.command, sizeof(data.command));
        bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
        output.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
"""
b=BPF(text=program)
syscall=b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
```

### **Explanation**

* **Perf and ring buffer maps** are designed for **high-performance communication** between eBPF programs running in kernel space and user-space applications.
  BCC’s **`BPF_PERF_OUTPUT`** macro enables us to write structured data directly into a perf ring buffer map for efficient data transfer.

* The **`BPF_PERF_OUTPUT`** macro, defined by BCC, creates a **map** used to send messages from the kernel to user space.
  In this example, the map is named **`output`**.

* Each time the **`hello()`** function executes, it writes one **data structure** to the buffer.
  This structure contains fields for:

  * **Process ID (PID)**
  * **Command name** (the currently running process)
  * **A static message string**

* The variable **`data`** is a local instance of the structure that holds the values to be submitted, while **`message`** stores the string `"Hello World"`.

* The helper function **`bpf_get_current_pid_tgid()`** retrieves the **process ID** of the program that triggered the eBPF function.
  It returns a **64-bit value**, where the **upper 32 bits** contain the PID.

* The helper function **`bpf_get_current_uid_gid()`** obtains the **user ID (UID)** of the process that initiated the syscall.

* Similarly, **`bpf_get_current_comm()`** retrieves the **name of the executable** (or command) that triggered the **`execve`** syscall.
  Since this is a string (not a numeric value), it cannot be directly assigned with `=` in C.
  Instead, the function writes the command name into the structure field by passing the **address reference** `&data.command`.

* In this example, the **message is constant** (“Hello World”) for every event.
  The function **`bpf_probe_read_kernel()`** copies this string safely into the **`data.message`** field within the structure.

* Once all fields are populated (process ID, command name, and message), the call to **`output.perf_submit()`** places the completed data structure into the **perf ring buffer map**, making it accessible to the user-space program for retrieval and display.
