// trace_fs.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct fs_event {
    u64 ts_ns; // timestamp in nanoseconds
    u32 pid; // pid of the process
    char comm[16]; // task command name
    u8 type; // 1 = openat, 2 = close
    int fd;  // valid for close
    char filename[256]; // valid for openat
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} r_buffer_fs SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    // args layout for sys_enter: args[0] = dirfd, args[1] = filename (char __user *), ...
    const char *filename_ptr = (const char *)ctx->args[1];
    struct fs_event *e = bpf_ringbuf_reserve(&r_buffer_fs, sizeof(*e), 0); // Allocate space in the ring buffer.
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns(); // Get current kernel time in nanoseconds.
    e->pid = bpf_get_current_pid_tgid() >> 32; // Extract PID from pid_tgid.
    bpf_get_current_comm(e->comm, sizeof(e->comm)); // Get current task command name.
    e->type = 1;
    e->fd = -1;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr); // Safely copies user-space string into kernel space.
    bpf_ringbuf_submit(e, 0); // Push the event to userspace.
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx) {
    // args[0] = fd
    struct fs_event *e = bpf_ringbuf_reserve(&r_buffer_fs, sizeof(*e), 0); // Allocate space in the ring buffer.
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns(); // Get current kernel time in nanoseconds.
    e->pid = bpf_get_current_pid_tgid() >> 32; // Extract PID from pid_tgid.
    bpf_get_current_comm(e->comm, sizeof(e->comm)); // Get current task command name.
    e->type = 2;
    // args[0] fits in int
    e->fd = (int)ctx->args[0];
    // zero filename for close events
    e->filename[0] = '\0';
    bpf_ringbuf_submit(e, 0); // Push the event to userspace.
    return 0;
}