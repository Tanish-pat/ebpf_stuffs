// switcher.cpp
extern "C" {
#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <errno.h>
}
#include <iostream>

static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) {
    stop = 1;
}

struct event {
    char prev_comm[16];
    char next_comm[16];
    int prev_pid;
    int next_pid;
};
static int count = 0;
static int handle_event(void *ctx, void *data, size_t len) {
    const struct event *e = static_cast<const struct event*>(data);
    printf("Switch: %s (%d) -> %s (%d), Count: %d\n", e->prev_comm, e->prev_pid, e->next_comm, e->next_pid, count);
    if (++count >= 10) stop = 1;
    return 0;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb;
    int err;

    // Set up signal handler for clean exit
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open and load the eBPF ELF file
    obj = bpf_object__open_file("switcher.bpf.o", NULL);
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
    prog = bpf_object__find_program_by_name(obj, "trace_sched_switch_event");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach program\n");
        return 1;
    }

    printf("eBPF program loaded and attached. Press Ctrl+C to stop.\n");

    /*CODE FOR RING BUFFER*/
    int map_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to open ring buffer\n");
        return 1;
    }
    while (!stop)
        ring_buffer__poll(rb, 10);
    ring_buffer__free(rb);
    /*ENDS*/

    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("Detached and exiting.\n");
    return 0;
}
