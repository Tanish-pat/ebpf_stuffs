// trace.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct execve_event {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char * filename;
    const char *const * argv;
    const char *const * envp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} r_buffer_execve SEC(".maps");

struct event_execve_user_space {
    u32 pid;
    char comm[16];
    char filename[128];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct execve_event *ctx) {
    struct event_execve_user_space *e;
    const char *filename = ctx->filename;
    char fname[128];
    e = bpf_ringbuf_reserve(&r_buffer_execve, sizeof(*e), 0);
    if(!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename); // safely read the filename string from user memory
    bpf_ringbuf_submit(e, 0);
    return 0;
}
