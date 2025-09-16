import os
from bcc import BPF

# Get current PID
TARGET_PID = os.getpid()

prog = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fcntl.h>

struct data_t {
    char comm[TASK_COMM_LEN];
    char fname[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != TARGET_PID)  // TARGET_PID injected from Python
        return 0;

    // Only track files created (O_CREAT flag)
    if (!(args->flags & O_CREAT))
        return 0;

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    const char __user *filename = args->filename;
    if (filename)
        bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# Compile BPF program, inject TARGET_PID
b = BPF(text=prog, cflags=[f"-D TARGET_PID={TARGET_PID}", "-w"])

done = False

def print_event(cpu, data, size):
    global done
    event = b["events"].event(data)
    comm = event.comm.decode("utf-8", "replace")
    fname = event.fname.decode("utf-8", "replace")
    print(f"Process {comm} created file: {fname}")
    done = True  # exit after first event

b["events"].open_perf_buffer(print_event, page_cnt=64)

with open("testfile1.txt", "w") as f:
    f.write("hello")
with open("testfile2.txt", "w") as f:
    f.write("hello")

print("Waiting for your process to create a file (filtered)...")
while not done:
    b.perf_buffer_poll()