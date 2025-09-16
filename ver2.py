from bcc import BPF

prog = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    char comm[TASK_COMM_LEN];
    char fname[256];
    char arg0[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    const char __user *filename = (const char __user *)args->filename;
    const char __user *const __user *argv =
        (const char __user *const __user *)args->argv;

    if (filename)
        bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);

    if (argv) {
        const char __user *arg0p = NULL;
        bpf_probe_read_user(&arg0p, sizeof(arg0p), &argv[0]);
        if (arg0p)
            bpf_probe_read_user_str(&data.arg0, sizeof(data.arg0), arg0p);
    }

    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    const char __user *filename = (const char __user *)args->filename;
    const char __user *const __user *argv =
        (const char __user *const __user *)args->argv;

    if (filename)
        bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);

    if (argv) {
        const char __user *arg0p = NULL;
        bpf_probe_read_user(&arg0p, sizeof(arg0p), &argv[0]);
        if (arg0p)
            bpf_probe_read_user_str(&data.arg0, sizeof(data.arg0), arg0p);
    }

    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}
"""

# b = BPF(text=prog)
# b = BPF(text=prog, cflags=["-Wno-duplicate-decl-specifier"])
b = BPF(text=prog, cflags=["-w"])

print("Attaching tracepoints sys_enter_execve and sys_enter_execveat...")
# No need for b.get_syscall_fnname(); tracepoints are explicit
# BPF will compile TRACEPOINT_PROBE macro handlers automatically.

def print_event(cpu, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode("utf-8", "replace")
    fname = event.fname.decode("utf-8", "replace")
    arg0 = event.arg0.decode("utf-8", "replace")
    print(f"{comm} | {fname} | {arg0}")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Exiting.")