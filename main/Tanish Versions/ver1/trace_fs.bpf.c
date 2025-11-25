// trace_fs.bpf.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct fs_event {
    u64 ts_ns;      // timestamp
    u32 pid;        // pid of process
    char comm[16];  // task comm
    u8 type;        // 1 = openat, 2 = close
    int fd;         // valid for close
    char filename[256]; // valid for openat
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} r_buffer_fs SEC(".maps");


// synthetic user-space files
struct fake_file_block {
    char data[4096];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[256]);
    __type(value, struct fake_file_block);
    __uint(max_entries, 128);
} synthetic_fs SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename_ptr = (const char *)ctx->args[1];
    struct fs_event *e = bpf_ringbuf_reserve(&r_buffer_fs, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->type = 1;
    e->fd = -1;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx) {
    struct fs_event *e = bpf_ringbuf_reserve(&r_buffer_fs, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->type = 2;
    e->fd = (int)ctx->args[0];
    e->filename[0] = '\0';
    bpf_ringbuf_submit(e, 0);
    return 0;
}
