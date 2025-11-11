// multi.cpp
extern "C" {
#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <unistd.h>
}
#include <iostream>

static volatile sig_atomic_t stop = 0;

static void handle_signal(int sig) {
    stop = 1;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog1, *prog2;
    struct bpf_link *link1, *link2;
    int err;

    // Set up signal handler for clean exit
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open and load the eBPF ELF file
    obj = bpf_object__open_file("multi.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }
    // --- PINNING STEP ---
    err = bpf_object__pin_maps(obj, "/sys/fs/bpf/multi");
    if (err) {
        fprintf(stderr, "Failed to pin maps: %d\n", err);
        return 1;
    }
    err = bpf_object__pin_programs(obj, "/sys/fs/bpf/multi");
    if (err) {
        fprintf(stderr, "Failed to pin programs: %d\n", err);
        return 1;
    }
    
    // Find the program by section name and attach it
    prog1 = bpf_object__find_program_by_name(obj, "handle_execve");
    if (!prog1) {
        fprintf(stderr, "Program not found\n");
        return 1;
    }

    link1 = bpf_program__attach(prog1);
    if (libbpf_get_error(link1)) {
        fprintf(stderr, "Failed to attach program\n");
        return 1;
    }

    prog2 = bpf_object__find_program_by_name(obj, "handle_openat");
    if (!prog2) {
        fprintf(stderr, "Program not found\n");
        return 1;
    }

    link2 = bpf_program__attach(prog2);
    if (libbpf_get_error(link2)) {
        fprintf(stderr, "Failed to attach program\n");
        return 1;
    }

    printf("eBPF program loaded and attached. Press Ctrl+C to stop.\n");

    // Keep running until user terminates
    while (!stop)
        sleep(1);

    fprintf(stdout, "Detaching eBPF program in 3...\n");
    sleep(1);
    fprintf(stdout, "Detaching eBPF program in 2...\n");
    sleep(1);
    fprintf(stdout, "Detaching eBPF program in 1...\n");

    bpf_link__destroy(link1); // Detach programs
    bpf_link__destroy(link2);

    bpf_object__unpin_maps(obj, "/sys/fs/bpf/multi"); // Unpin maps
    bpf_object__unpin_programs(obj, "/sys/fs/bpf/multi"); // Unpin programs
    if (rmdir("/sys/fs/bpf/multi") != 0)
        perror("rmdir");
    else
        rmdir("/sys/fs/bpf/multi"); // Remove directory

    bpf_object__close(obj); // Close BPF object

    printf("Detached and exiting.\n");
    return 0;
}
