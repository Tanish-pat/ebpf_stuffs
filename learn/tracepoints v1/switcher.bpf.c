// switcher.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct sched_switch_event {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

struct event {
    char prev_comm[16];
    char next_comm[16];
    int prev_pid;
    int next_pid;
};

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch_event(struct sched_switch_event *ctx) {
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memcpy(e->prev_comm, ctx->prev_comm, 16);
    __builtin_memcpy(e->next_comm, ctx->next_comm, 16);
    e->prev_pid = ctx->prev_pid;
    e->next_pid = ctx->next_pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}