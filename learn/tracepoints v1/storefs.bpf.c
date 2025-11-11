// storefs.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Config limits */
#define PATH_SZ 128
#define DATA_SZ 4096

/* Key types */
struct pidfd_key {
    u64 pid_tgid;
    int fd;
};

/* Value stored for a path */
struct file_blob {
    u32 len;
    u8 data[DATA_SZ];
};

/* Temporary map: pending open stores pathname per pid_tgid while open executes */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64); /* pid_tgid */
    __type(value, char[PATH_SZ]);
} pending_open SEC(".maps");

/* Map: pid+fd -> pathname (so we know which path a write refers to) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct pidfd_key);
    __type(value, char[PATH_SZ]);
} fd_to_path SEC(".maps");

/* Map: pathname -> file_blob (in-kernel overlay content). ephemeral until program unload */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, char[PATH_SZ]);
    __type(value, struct file_blob);
} file_store SEC(".maps");

/* tracepoint: sys_enter_openat(dirfd, pathname, flags, mode) */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    const char *pathname_ptr = (const char *)ctx->args[1];
    u64 pid_tgid = bpf_get_current_pid_tgid();
    char tmp[PATH_SZ];

    if (!pathname_ptr)
        return 0;

    /* read user pathname safely (limit PATH_SZ) */
    if (bpf_probe_read_user_str(tmp, sizeof(tmp), pathname_ptr) <= 0)
        return 0;

    bpf_map_update_elem(&pending_open, &pid_tgid, tmp, BPF_ANY);
    return 0;
}

/* tracepoint: sys_exit_openat (capture returned fd) */
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret_fd = ctx->ret;
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (ret_fd < 0) {
        /* open failed; remove pending */
        bpf_map_delete_elem(&pending_open, &pid_tgid);
        return 0;
    }

    char *pathp = bpf_map_lookup_elem(&pending_open, &pid_tgid);
    if (!pathp)
        return 0;

    struct pidfd_key k = {};
    k.pid_tgid = pid_tgid;
    k.fd = ret_fd;

    /* add fd->path mapping (copy path into value) */
    bpf_map_update_elem(&fd_to_path, &k, pathp, BPF_ANY);

    /* ensure file_store has an entry (zeroed) so reads later succeed */
    struct file_blob zero = {};
    bpf_map_update_elem(&file_store, pathp, &zero, BPF_NOEXIST);

    /* cleanup pending */
    bpf_map_delete_elem(&pending_open, &pid_tgid);
    return 0;
}

/* tracepoint: sys_enter_write(fd, buf, count) */
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct pidfd_key k = {};
    k.pid_tgid = pid_tgid;
    k.fd = fd;

    char *pathp = bpf_map_lookup_elem(&fd_to_path, &k);
    if (!pathp)
        return 0; /* not a tracked fd */

    /* limit copy size */
    size_t to_copy = count;
    if (to_copy > DATA_SZ)
        to_copy = DATA_SZ;

    /* lookup or create blob */
    struct file_blob *blobp = bpf_map_lookup_elem(&file_store, pathp);
    if (!blobp) {
        struct file_blob zero = {};
        bpf_map_update_elem(&file_store, pathp, &zero, BPF_ANY);
        blobp = bpf_map_lookup_elem(&file_store, pathp);
        if (!blobp)
            return 0;
    }

    /* read user buffer into local stack then copy into map value */
    u8 tmp[DATA_SZ];
    if (to_copy == 0)
        return 0;

    if (bpf_probe_read_user(tmp, to_copy, buf) < 0)
        return 0;

    /* write into blob (simple overwrite at offset 0 for PoC) */
    /* In production you may want to support offsets by hooking pwrite/pread or tracking file offsets. */
    __builtin_memcpy(blobp->data, tmp, to_copy);
    blobp->len = to_copy;

    /* update the map with modified blob (not strictly required when pointing to map value, but safe) */
    bpf_map_update_elem(&file_store, pathp, blobp, BPF_ANY);

    return 0;
}

/* tracepoint: sys_enter_close(fd) -> cleanup fd mapping */
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pidfd_key k = {};
    k.pid_tgid = pid_tgid;
    k.fd = fd;

    bpf_map_delete_elem(&fd_to_path, &k);
    return 0;
}