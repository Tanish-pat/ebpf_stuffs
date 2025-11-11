// trace_fs.cpp
extern "C" {
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
}
#include <iostream>
#include <atomic>

static std::atomic<bool> stop(false);
static void handle_signal(int sig) { stop.store(true); }

struct fs_event {
    uint64_t ts_ns;
    uint32_t pid;
    char comm[16];
    uint8_t type; // 1 openat, 2 close
    int fd;
    char filename[256];
};

static int handle_event(void *ctx, void *data, size_t len) {
    const struct fs_event *e = static_cast<const struct fs_event*>(data);
    if (!e) return 0;
    if (e->type == 1) {
        printf("[OPEN]  pid=%u comm=%s file=%s\n", e->pid, e->comm, e->filename);
    } else if (e->type == 2) {
        printf("[CLOSE] pid=%u comm=%s fd=%d\n", e->pid, e->comm, e->fd);
    } else {
        printf("[UNK] pid=%u comm=%s\n", e->pid, e->comm);
    }
    return 0;
}

int main() {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog_open = NULL, *prog_close = NULL;
    struct bpf_link *link_open = NULL, *link_close = NULL;
    struct ring_buffer *rb = NULL;
    int err, map_fd = -1;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    obj = bpf_object__open_file("build/trace_fs.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    prog_open = bpf_object__find_program_by_name(obj, "trace_openat");
    prog_close = bpf_object__find_program_by_name(obj, "trace_close");
    if (!prog_open || !prog_close) {
        fprintf(stderr, "Required programs not found\n");
        bpf_object__close(obj);
        return 1;
    }

    link_open = bpf_program__attach(prog_open);
    if (libbpf_get_error(link_open)) {
        fprintf(stderr, "Failed to attach openat program\n");
        link_open = NULL;
        goto cleanup;
    }
    link_close = bpf_program__attach(prog_close);
    if (libbpf_get_error(link_close)) {
        fprintf(stderr, "Failed to attach close program\n");
        link_close = NULL;
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "r_buffer_fs");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ring buffer map\n");
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Attached. Listening for openat/close. Press Ctrl+C to exit.\n");
    while (!stop.load())
        ring_buffer__poll(rb, 100);

    printf("Shutting down...\n");

cleanup:
    if (rb) ring_buffer__free(rb);
    if (link_open) bpf_link__destroy(link_open);
    if (link_close) bpf_link__destroy(link_close);
    bpf_object__close(obj);
    return 0;
}