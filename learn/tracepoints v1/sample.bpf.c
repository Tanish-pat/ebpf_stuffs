// sample.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// traces when any process calls execve, observe process execution
SEC("tracepoint/syscalls/sys_enter_execve")
int foo1(void *ctx) {

}

// traces the return value of a syscall, detect syscall failure or error codes
SEC("tracepoint/syscalls/sys_exit_openat")
int foo2(void *ctx) {

}

// fires when kernel switches context between processes, analyze cpu latency and scheduling
SEC("tracepoint/sched/sched_switch")
int foo3(void *ctx) {

}

// fires when a block IO request is issued, monitor IO pattern and device load
SEC("tracepoint/block/block_rq_issue")
int foo4(void *ctx) {

}

//fires when packets are required for transmission, track outgoing network traffic
SEC("tracepoint/net/net_dev_queue")
int foo5(void *ctx) {

}

// fires when physical memory page is allocated, observe kernel memory pressure and allocations
SEC("tracepoint/kmem/mm_page_alloc")
int foo6(void *ctx) {

}

// fires when a process exits, track lifecycle elimination
SEC("tracepoint/sched/sched_process/exit")
int foo7(void *ctx) {

}