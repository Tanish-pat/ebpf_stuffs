import os
from bcc import BPF

TARGET_PID = os.getpid()

prog = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/limits.h>

struct data_t {
    u32 pid;
    u32 tid;
    int fd;
    int flags;
    int mode;
    u64 count;
    char comm[TASK_COMM_LEN];
    char fname[256];
    char event_type[16];
};

BPF_HASH(seen_files, u64, u8); // Track first write
BPF_PERF_OUTPUT(events);

// File creation
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    if (pid != TARGET_PID) return 0;
    if (!(args->flags & O_CREAT)) return 0;

    struct data_t data = {};
    data.pid = pid;
    data.tid = tid;
    data.fd = -1;
    data.flags = args->flags;
    data.mode = args->mode;
    data.count = 0;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type[0]='C'; data.event_type[1]='R'; data.event_type[2]='E';
    data.event_type[3]='A'; data.event_type[4]='T'; data.event_type[5]='E'; data.event_type[6]='\0';

    const char __user *filename = args->filename;
    if (filename)
        bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// File write
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    if (pid != TARGET_PID) return 0;

    u64 fd = args->fd;
    u8 *exists = seen_files.lookup(&fd);
    if (exists) return 0;
    u8 val = 1;
    seen_files.update(&fd, &val);

    struct data_t data = {};
    data.pid = pid;
    data.tid = tid;
    data.fd = args->fd;
    data.flags = 0;
    data.mode = 0;
    data.count = args->count;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type[0]='W'; data.event_type[1]='R'; data.event_type[2]='I';
    data.event_type[3]='T'; data.event_type[4]='E'; data.event_type[5]='\0';

    data.fname[0]='\0';
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// File deletion
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    if (pid != TARGET_PID) return 0;

    struct data_t data = {};
    data.pid = pid;
    data.tid = tid;
    data.fd = -1;
    data.flags = 0;
    data.mode = 0;
    data.count = 0;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type[0]='D'; data.event_type[1]='E'; data.event_type[2]='L';
    data.event_type[3]='E'; data.event_type[4]='T'; data.event_type[5]='E'; data.event_type[6]='\0';

    const char __user *filename = args->pathname;
    if (filename)
        bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=prog, cflags=[f"-D TARGET_PID={TARGET_PID}", "-w"])

def print_event(cpu, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode("utf-8", "replace")
    fname = event.fname.decode("utf-8", "replace")
    etype = event.event_type.decode("utf-8", "replace")
    fname_str = fname if fname else "EMPTY"
    print(f"[EVENT] {etype} by {comm} (PID={event.pid}, TID={event.tid}, FD={event.fd}, FLAGS={event.flags}, MODE={event.mode}, COUNT={event.count}): FNAME={fname_str}")

b["events"].open_perf_buffer(print_event)

print("Monitoring file events (Ctrl+C to exit)...")

# Example file operations
with open("testfile1.txt", "w") as f:
    f.write("hello")
with open("testfile1.txt", "a") as f:
    f.write("more text")
os.remove("testfile1.txt")

try:
    while True:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    print("Stopped monitoring.")
