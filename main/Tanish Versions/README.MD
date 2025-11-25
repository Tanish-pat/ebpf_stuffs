## **trace_fs.bpf.c** — eBPF side (kernel space)

This is the part that actually intercepts system calls and manipulates reads with synthetic data.

### **1. License**

```c
char LICENSE[] SEC("license") = "GPL";
```

* Required for eBPF programs. If it’s GPL, some kernel helper functions are allowed.

---

### **2. Event structure**

```c
struct fs_event {
    u64 ts_ns;
    u32 pid;
    char comm[16];
    u8 type; // 1=openat, 2=close
    int fd;
    char filename[256];
};
```

* Represents a filesystem event (open/close).
* Sent to user-space through a **ring buffer**.
* Fields:

  * `ts_ns`: timestamp
  * `pid`: process ID
  * `comm`: process name
  * `type`: event type
  * `fd`: file descriptor (if applicable)
  * `filename`: file path

---

### **3. BPF maps**

#### **a. Ring buffer**

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} r_buffer_fs SEC(".maps");
```

* Used to pass `fs_event` data from kernel to user-space asynchronously.
* Fast and lock-free compared to hash maps.

---

#### **b. Synthetic filesystem map**

```c
struct fake_file_block { char data[4096]; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[256]);   // filename
    __type(value, struct fake_file_block);
    __uint(max_entries, 128);
} synthetic_fs SEC(".maps");
```

* Holds synthetic file content.
* Key: file path
* Value: 4KB of synthetic data
* Used to override what `read()` returns.

---

#### **c. Tracking in-progress reads**

```c
struct read_info {
    u64 buf_ptr;
    int fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);      // pid_tgid
    __type(value, struct read_info);
    __uint(max_entries, 1024);
} read_buffers SEC(".maps");
```

* Tracks each ongoing `read()` (or `pread64()`) so the exit handler knows where to write synthetic data.
* Key: `pid_tgid` (process ID + thread ID)
* Value: buffer pointer and fd

---

#### **d. fd → path mapping**

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);          // fd
    __type(value, char[256]);  // filename
    __uint(max_entries, 512);
} fd_to_path SEC(".maps");
```

* Keeps track of which file descriptor maps to which filename.
* Updated by user-space when files are opened/closed.
* Used to find synthetic file content for a given fd.

---

### **4. Tracepoints / syscall hooks**

#### **a. Open**

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
```

* Hooks `openat()` system calls.
* Reads filename from userspace, constructs an `fs_event`, and submits it to the ring buffer.
* **Does not modify the file**; purely for logging.

#### **b. Close**

```c
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
```

* Hooks `close()` calls.
* Logs the close event.
* Deletes the fd from `fd_to_path` to avoid stale mappings.

---

#### **c. Read/pread64 enter**

```c
SEC("tracepoint/syscalls/sys_enter_read")
SEC("tracepoint/syscalls/sys_enter_pread64")
```

* Captures fd and buffer pointer.
* Saves it in `read_buffers` so the exit handler knows where to write data.

---

#### **d. Read/pread64 exit**

```c
SEC("tracepoint/syscalls/sys_exit_read")
SEC("tracepoint/syscalls/sys_exit_pread64")
```

* Looks up the fd in `fd_to_path`.
* Checks if a synthetic entry exists in `synthetic_fs`.
* If yes, writes synthetic content to the user buffer using `bpf_probe_write_user`.
* Writes in **128-byte chunks**, due to eBPF verifier limitations.
* If synthetic entry missing, writes zeros to the buffer.

**Summary:** This is how “reads sometimes get real data, sometimes synthetic” occurs — if the `synthetic_fs` map does not contain the file, the read is not overwritten.

---

### **5. Key behavior**

* Synthetic override happens **after syscall exits**.
* Only intercepts reads for fds that exist in `fd_to_path`.
* Supports multiple concurrent reads per process using `read_buffers`.

---

## **trace_fs.c** — user-space

This is the CLI/controller that communicates with the BPF program.

---

### **1. Structures**

#### **a. Synthetic file tracking**

```c
struct syn_entry { char path[MAX_PATH]; int fd; };
static struct syn_entry syn_tree[MAX_SYN_FILES];
```

* Mirrors what files are “synthetic”.

#### **b. FD → path mapping**

```c
struct fd_map { int fd; char path[MAX_PATH]; };
static struct fd_map fd_table[MAX_SYN_FILES];
```

* Tracks open file descriptors in user-space.

#### **c. Flags**

```c
static bool erase_mode = false;
```

* Set when user chooses `[e]rase`.
* Used to initialize synthetic_fs entries with zeros to prevent real files from being returned.

---

### **2. BPF skeleton load**

```c
skel = trace_fs_bpf__open();
trace_fs_bpf__load(skel);
trace_fs_bpf__attach(skel);
```

* Opens BPF skeleton, loads maps and programs into the kernel, and attaches tracepoints.

---

### **3. Pinning**

* Checks if pinned map exists at `/sys/fs/bpf/trace_fs/synthetic_fs`.
* `[r]euse`: copies pinned map content into live map.
* `[e]rase`: deletes pinned map, sets `erase_mode = true`.
* When `erase_mode` is true, **all new opens create zeroed synthetic entries**, guaranteeing reads return synthetic data, not real files.

---

### **4. CLI Commands**

#### **a. `o <path>`: open**

* Opens the file with `O_RDONLY`.
* Adds fd → path in BPF (`fd_to_path`).
* Adds entry in `syn_tree`.
* **If erase_mode**, adds zeroed entry to `synthetic_fs`.

#### **b. `c <fd>`: close**

* Removes fd from `fd_to_path` BPF map.
* Removes fd from `syn_tree`.
* Closes fd.

#### **c. `w <fd>`: write synthetic content**

* Updates `synthetic_fs` map with user-provided content.
* Overwrites previously zeroed content if erase_mode.

#### **d. `r <fd>`: read**

* Calls real `read(fd, buf, size)`.
* The eBPF exit hook intercepts and overwrites the buffer with synthetic content if available.
* Otherwise, original content remains.

#### **e. `t`: tree**

* Prints all open synthetic files in `syn_tree`.

---

### **5. Key logic for consistency**

* When erase mode is selected:

  1. Pinned map is deleted.
  2. fd → path BPF map is cleared.
  3. New opens initialize synthetic_fs with zeros.

* This ensures **all reads after erase only see synthetic content**, never touching real files.

---

### **6. Data flow overview**

1. **User-space opens a file** → updates fd_to_path → adds syn_tree → optional zero in synthetic_fs.
2. **Kernel intercepts read()** → looks up fd in fd_to_path → looks up synthetic_fs → overwrites buffer.
3. **User-space reads buffer** → always sees synthetic content (if map exists) or zeros (erase mode).
4. **User writes synthetic content (`w`)** → updates synthetic_fs map.
5. **Close fd** → removes fd from fd_to_path, deletes syn_tree entry.

---

### **Summary**

* `trace_fs.bpf.c`: kernel-level interception and synthetic data injection.
* `trace_fs.c`: user-space CLI, manages fd mappings, pinned maps, synthetic content, and erase/reuse policy.
* `erase_mode` ensures consistent synthetic data reads.
* Ring buffer provides async logging of open/close events.
* Real files appear only if synthetic_fs entry is missing or erase_mode not enforced.

---
