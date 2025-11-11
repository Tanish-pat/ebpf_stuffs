// trace_fs.cpp
extern "C" {
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
}
#include <algorithm>
#include <iostream>
#include <atomic>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>

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

// Global: loader PID used for filtering
static pid_t loader_pid = 0;

static int handle_event(void *ctx, void *data, size_t len) {
    const struct fs_event *e = static_cast<const struct fs_event*>(data);
    if (!e) return 0;

    // Filter: only show events coming from this loader process
    if ((pid_t)e->pid != loader_pid) return 0;

    if (e->type == 1)
        printf("[SELF OPEN]  pid=%u comm=%s file=%s\n", e->pid, e->comm, e->filename);
    else if (e->type == 2)
        printf("[SELF CLOSE] pid=%u comm=%s fd=%d\n", e->pid, e->comm, e->fd);
    else
        printf("[SELF UNKNOWN] pid=%u comm=%s\n", e->pid, e->comm);
    return 0;
}

// small helper to trim leading/trailing whitespace
static inline std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a==std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b-a+1);
}

int main() {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog_open = NULL, *prog_close = NULL;
    struct bpf_link *link_open = NULL, *link_close = NULL;
    struct ring_buffer *rb = NULL;
    int err, map_fd = -1;
    // Keep track of fds opened via oc
    std::vector<int> kept_fds;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    loader_pid = getpid();

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

    printf("Attached. Interactive commands:\n");
    printf("  o <path>   -> open then close (generate open+close)\n");
    printf("  oc <path>  -> open and keep open (returns fd)\n");
    printf("  c <fd>     -> close fd\n");
    printf("  q          -> quit\n");
    printf("Listening for openat/close. Only events from this process (pid=%d) will be shown.\n", loader_pid);

    // Set stdin non-blocking via select() in the loop
    while (!stop.load()) {
        // 1) poll ring buffer (short timeout)
        ring_buffer__poll(rb, 50 /*ms*/);

        // 2) check stdin with select (non-blocking)
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0; // immediate
        int sel = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(STDIN_FILENO, &readfds)) {
            std::string line;
            if (!std::getline(std::cin, line)) {
                // EOF or error
                stop.store(true);
                break;
            }
            line = trim(line);
            if (line.empty()) continue;
            if (line == "q") {
                stop.store(true);
                break;
            }
            // parse commands
            if (line.rfind("o ", 0) == 0) {
                std::string path = trim(line.substr(2));
                if (path.empty()) { printf("usage: o <path>\n"); continue; }
                int fd = open(path.c_str(), O_RDONLY);
                if (fd < 0) {
                    printf("open failed: %s\n", strerror(errno));
                } else {
                    // immediate close to generate close event
                    close(fd);
                    printf("Triggered open+close on %s\n", path.c_str());
                }
            } else if (line.rfind("oc ", 0) == 0) {
                std::string path = trim(line.substr(3));
                if (path.empty()) { printf("usage: oc <path>\n"); continue; }
                int fd = open(path.c_str(), O_RDONLY);
                if (fd < 0) {
                    printf("open failed: %s\n", strerror(errno));
                } else {
                    kept_fds.push_back(fd);
                    printf("Opened (kept) fd=%d for %s\n", fd, path.c_str());
                }
            } else if (line.rfind("c ", 0) == 0) {
                std::string arg = trim(line.substr(2));
                if (arg.empty()) { printf("usage: c <fd>\n"); continue; }
                int fd = atoi(arg.c_str());
                if (fd <= 0) { printf("invalid fd\n"); continue; }
                if (close(fd) == 0) {
                    // remove from kept_fds if present
                    auto it = std::find(kept_fds.begin(), kept_fds.end(), fd);
                    if (it != kept_fds.end()) kept_fds.erase(it);
                    printf("Closed fd=%d\n", fd);
                } else {
                    printf("close failed: %s\n", strerror(errno));
                }
            } else {
                printf("unknown command\n");
            }
        }
        // else no stdin input; loop continues
    }

    printf("Shutting down...\n");

cleanup:
    // close any kept fds we didn't explicitly close
    for (int fd : kept_fds) {
        close(fd);
    }
    if (rb) ring_buffer__free(rb);
    if (link_open) bpf_link__destroy(link_open);
    if (link_close) bpf_link__destroy(link_close);
    bpf_object__close(obj);
    return 0;
}

// // trace_fs.cpp
// extern "C" {
// #include <bpf/libbpf.h>
// #include <signal.h>
// #include <unistd.h>
// #include <stdio.h>
// #include <stdlib.h>
// }
// #include <iostream>
// #include <atomic>

// static std::atomic<bool> stop(false);
// static void handle_signal(int sig) { stop.store(true); }

// struct fs_event {
//     uint64_t ts_ns;
//     uint32_t pid;
//     char comm[16];
//     uint8_t type; // 1 openat, 2 close
//     int fd;
//     char filename[256];
// };

// static int handle_event(void *ctx, void *data, size_t len) {
//     const struct fs_event *e = static_cast<const struct fs_event*>(data);
//     if (!e) return 0;
//     if (e->type == 1) {
//         printf("[OPEN]  pid=%u comm=%s file=%s\n", e->pid, e->comm, e->filename);
//     } else if (e->type == 2) {
//         printf("[CLOSE] pid=%u comm=%s fd=%d\n", e->pid, e->comm, e->fd);
//     } else {
//         printf("[UNK] pid=%u comm=%s\n", e->pid, e->comm);
//     }
//     return 0;
// }

// int main() {
//     struct bpf_object *obj = NULL;
//     struct bpf_program *prog_open = NULL, *prog_close = NULL;
//     struct bpf_link *link_open = NULL, *link_close = NULL;
//     struct ring_buffer *rb = NULL;
//     int err, map_fd = -1;

//     signal(SIGINT, handle_signal);
//     signal(SIGTERM, handle_signal);

//     obj = bpf_object__open_file("build/trace_fs.bpf.o", NULL);
//     if (libbpf_get_error(obj)) {
//         fprintf(stderr, "Failed to open BPF object\n");
//         return 1;
//     }

//     err = bpf_object__load(obj);
//     if (err) {
//         fprintf(stderr, "Failed to load BPF object: %d\n", err);
//         bpf_object__close(obj);
//         return 1;
//     }

//     prog_open = bpf_object__find_program_by_name(obj, "trace_openat");
//     prog_close = bpf_object__find_program_by_name(obj, "trace_close");
//     if (!prog_open || !prog_close) {
//         fprintf(stderr, "Required programs not found\n");
//         bpf_object__close(obj);
//         return 1;
//     }

//     link_open = bpf_program__attach(prog_open);
//     if (libbpf_get_error(link_open)) {
//         fprintf(stderr, "Failed to attach openat program\n");
//         link_open = NULL;
//         goto cleanup;
//     }
//     link_close = bpf_program__attach(prog_close);
//     if (libbpf_get_error(link_close)) {
//         fprintf(stderr, "Failed to attach close program\n");
//         link_close = NULL;
//         goto cleanup;
//     }

//     map_fd = bpf_object__find_map_fd_by_name(obj, "r_buffer_fs");
//     if (map_fd < 0) {
//         fprintf(stderr, "Failed to find ring buffer map\n");
//         goto cleanup;
//     }

//     rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
//     if (!rb) {
//         fprintf(stderr, "Failed to create ring buffer\n");
//         goto cleanup;
//     }

//     printf("Attached. Listening for openat/close. Press Ctrl+C to exit.\n");
//     while (!stop.load())
//         ring_buffer__poll(rb, 100);

//     printf("Shutting down...\n");

// cleanup:
//     if (rb) ring_buffer__free(rb);
//     if (link_open) bpf_link__destroy(link_open);
//     if (link_close) bpf_link__destroy(link_close);
//     bpf_object__close(obj);
//     return 0;
// }