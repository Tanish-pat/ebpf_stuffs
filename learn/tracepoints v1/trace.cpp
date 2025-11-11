// trace.cpp
extern "C" {
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
}
#include <iostream>

static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) {
    stop = 1;
}

struct event {
    __u32 pid;
    char comm[16];
    char filename[128];
};
static int handle_event(void *ctx, void *data, size_t len) {
    const struct event *e = static_cast<const struct event*>(data);
    printf("PID=%u COMM=%s FILE=%s\n", e->pid, e->comm, e->filename);
    return 0;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *ring_buffer;
    int err;

    // Set up signal handler for clean exit
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open and load the eBPF ELF file
    obj = bpf_object__open_file("trace.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    // Find the program by section name and attach it
    prog = bpf_object__find_program_by_name(obj, "trace_execve");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        return 1;
    }

    // if (bpf_program__pin(prog, "/sys/fs/bpf/trace_execve_prog")) fprintf(stderr, "Warning: failed to pin program (non-fatal)\n");
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach program\n");
        return 1;
    }
    // if (bpf_link__pin(link, "/sys/fs/bpf/trace_execve_link")) fprintf(stderr, "Warning: failed to pin link (non-fatal)\n");

    printf("eBPF program loaded and attached. Press Ctrl+C to stop.\n");

    /*CODE FOR RING BUFFER*/
    int map_fd = bpf_object__find_map_fd_by_name(obj, "r_buffer_execve");
    ring_buffer = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!ring_buffer) {
        fprintf(stderr, "failed to open ring buffer\n");
        return 1;
    }
    while (!stop)
        ring_buffer__poll(ring_buffer, 10);
    ring_buffer__free(ring_buffer);
    /*ENDS*/

    fprintf(stdout, "Detaching eBPF program in 3...\n"); sleep(1);
    fprintf(stdout, "Detaching eBPF program in 2...\n"); sleep(1);
    fprintf(stdout, "Detaching eBPF program in 1...\n");
    bpf_link__destroy(link);
    bpf_object__close(obj);

    printf("Detached and exiting.\n");
    return 0;
}
