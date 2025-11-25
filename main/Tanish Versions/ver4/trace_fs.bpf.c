// trace_fs.bpf.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Event structure for ring buffer */
struct fs_event {
    u64 ts_ns;      // timestamp
    u32 pid;        // pid of process
    char comm[16];  // task comm
    u8 type;        // 1=openat, 2=close
    int fd;         // valid for close
    char filename[256]; // valid for openat
};

/* Ring buffer map for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} r_buffer_fs SEC(".maps");

/* Synthetic user-space file blocks */
struct fake_file_block {
    char data[4096];
};

/* Synthetic FS map: key = filename, value = file content */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[256]);
    __type(value, struct fake_file_block);
    __uint(max_entries, 128);
} synthetic_fs SEC(".maps");

/* Map to track ongoing reads: key=pid_tgid, value=user buffer pointer + fd */
struct read_info {
    u64 buf_ptr;
    int fd;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);          // pid_tgid
    __type(value, struct read_info);
    __uint(max_entries, 1024);
} read_buffers SEC(".maps");

/* Map to track fd -> filename, updated from user-space via BPF API */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);           // fd
    __type(value, char[256]);   // filename
    __uint(max_entries, 512);
} fd_to_path SEC(".maps");

/* ------------------ helpers ------------------ */

/* safe helper to copy filename from user map value pointer to kernel stack buffer */
static __always_inline int copy_filename_from_map(const char *name_ptr, char *out, int out_sz)
{
    /* name_ptr is a pointer into kernel map value memory; use bpf_probe_read_kernel_str */
    int res = bpf_probe_read_kernel_str(out, out_sz, name_ptr);
    return res;
}

/* ------------------ tracepoints ------------------ */

/* Trace openat syscall */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename_ptr = (const char *)ctx->args[1];
    struct fs_event *e = bpf_ringbuf_reserve(&r_buffer_fs, sizeof(*e), 0);
    if (!e) return 0;

    /* fill event fields */
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->type = 1;
    e->fd = -1;
    /* try to read user filename pointer */
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);

    /* Submit and return (do not touch 'e' after submit) */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Trace close syscall */
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx) {
    /* We must NOT read ringbuf record after submit. So copy needed data into locals
     * before submit, and perform map deletion after we have a local copy of fd. */

    int fd = (int)ctx->args[0];

    /* Reserve ringbuf space and populate it */
    struct fs_event *e = bpf_ringbuf_reserve(&r_buffer_fs, sizeof(*e), 0);
    if (!e) {
        /* If ringbuf unavailable, still remove mapping from fd_to_path to avoid leak.
         * Use fd directly (we don't need the comm/ts for that). */
        bpf_map_delete_elem(&fd_to_path, &fd);
        return 0;
    }

    /* Fill event */
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->type = 2;
    e->fd = fd;
    e->filename[0] = '\0';

    /* Now submit (memory becomes invalid after this) */
    bpf_ringbuf_submit(e, 0);

    /* Use local 'fd' to delete mapping; do NOT dereference 'e' now */
    bpf_map_delete_elem(&fd_to_path, &fd);

    return 0;
}

/* Trace read syscall enter */
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_info info = {};
    info.fd = (int)ctx->args[0]; // fd
    info.buf_ptr = (u64)ctx->args[1]; // user buffer pointer
    bpf_map_update_elem(&read_buffers, &pid_tgid, &info, BPF_ANY);
    bpf_printk("trace_read_enter pid=%d fd=%d buf=%p\n", (u32)(pid_tgid >> 32), info.fd, (void *)info.buf_ptr);
    return 0;
}

/* Trace pread64 syscall enter (glibc often uses pread64) */
SEC("tracepoint/syscalls/sys_enter_pread64")
int trace_pread64_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_info info = {};
    info.fd = (int)ctx->args[0];        // fd
    info.buf_ptr = (u64)ctx->args[1];   // buf pointer
    bpf_map_update_elem(&read_buffers, &pid_tgid, &info, BPF_ANY);
    bpf_printk("trace_pread64_enter pid=%d fd=%d buf=%p\n", (u32)(pid_tgid >> 32), info.fd, (void *)info.buf_ptr);
    return 0;
}

/* Common read exit handler logic (used by both read and pread64 exit) */
static __always_inline int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_info *info = bpf_map_lookup_elem(&read_buffers, &pid_tgid);
    if (!info) return 0;

    /* If syscall returned <= 0, clean up and exit */
    long ret = (long)ctx->ret;
    if (ret <= 0) goto cleanup;

    /* copy fd from map value (it's safe; small scalar) */
    int fd = info->fd;

    /* lookup filename in fd_to_path */
    char *name_ptr = bpf_map_lookup_elem(&fd_to_path, &fd);
    if (!name_ptr) goto cleanup;

    /* copy filename from map memory to stack buffer */
    char key[256] = {};
    if (bpf_probe_read_kernel_str(key, sizeof(key), name_ptr) <= 0)
        goto cleanup;

    struct fake_file_block *blk = bpf_map_lookup_elem(&synthetic_fs, key);
    size_t copy_len = (size_t)ret;
    if (copy_len > sizeof(struct fake_file_block))
        copy_len = sizeof(struct fake_file_block);
    if (!info->buf_ptr) goto cleanup;

    if (blk) {
        bpf_probe_write_user((void *)info->buf_ptr, blk->data, copy_len);
    }

cleanup:
    bpf_map_delete_elem(&read_buffers, &pid_tgid);
    return 0;
}

/* Trace read syscall exit */
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
    return handle_read_exit(ctx);
}

/* Trace pread64 syscall exit */
SEC("tracepoint/syscalls/sys_exit_pread64")
int trace_pread64_exit(struct trace_event_raw_sys_exit *ctx) {
    return handle_read_exit(ctx);
}

char _license[] SEC("license") = "GPL";
