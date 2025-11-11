#include <bpf/libbpf.h>
#include <csignal>
#include <unistd.h>
#include <iostream>
#include <atomic>
#include <string>
#include <vector>
#include <algorithm>
#include <fcntl.h>
#include <sys/select.h>
#include <cerrno>
#include <cstring>
#include <memory>
using namespace std;

struct fs_event {
    uint64_t ts_ns;
    uint32_t pid;
    char comm[16];
    uint8_t type; // 1 openat, 2 close
    int fd;
    char filename[256];
};

static atomic<bool> stop(false);
static pid_t loader_pid = 0;

void handle_signal(int) { stop.store(true); }

static int handle_event(void*, void* data, size_t) {
    const auto* e = static_cast<const fs_event*>(data);
    if (!e || static_cast<pid_t>(e->pid) != loader_pid) return 0;
    switch (e->type) {
        case 1:
            cout << "[SELF OPEN]  pid=" << e->pid << " comm=" << e->comm << " file=" << e->filename << '\n'; break;
        case 2:
            cout << "[SELF CLOSE] pid=" << e->pid << " comm=" << e->comm << " fd=" << e->fd << '\n'; break;
        default:
            cout << "[SELF UNKNOWN] pid=" << e->pid << " comm=" << e->comm << '\n';
    }
    return 0;
}

static string trim(const string& s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

int main() {
    loader_pid = getpid();
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    unique_ptr<bpf_object, decltype(&bpf_object__close)> obj(
        bpf_object__open_file("build/trace_fs.bpf.o", nullptr),
        &bpf_object__close);

    if (libbpf_get_error(obj.get())) {
        cerr << "Failed to open BPF object\n";
        return 1;
    }

    if (int err = bpf_object__load(obj.get()); err) {
        cerr << "Failed to load BPF object: " << err << '\n';
        return 1;
    }

    bpf_program* prog_open = bpf_object__find_program_by_name(obj.get(), "trace_openat");
    bpf_program* prog_close = bpf_object__find_program_by_name(obj.get(), "trace_close");
    if (!prog_open || !prog_close) {
        cerr << "Required programs not found\n";
        return 1;
    }

    unique_ptr<bpf_link, decltype(&bpf_link__destroy)> link_open(
        bpf_program__attach(prog_open), &bpf_link__destroy);
    if (libbpf_get_error(link_open.get())) {
        cerr << "Failed to attach openat program\n";
        return 1;
    }

    unique_ptr<bpf_link, decltype(&bpf_link__destroy)> link_close(
        bpf_program__attach(prog_close), &bpf_link__destroy);
    if (libbpf_get_error(link_close.get())) {
        cerr << "Failed to attach close program\n";
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj.get(), "r_buffer_fs");
    if (map_fd < 0) {
        cerr << "Failed to find ring buffer map\n";
        return 1;
    }

    unique_ptr<ring_buffer, decltype(&ring_buffer__free)> rb(
        ring_buffer__new(map_fd, handle_event, nullptr, nullptr),
        &ring_buffer__free);

    if (!rb) {
        cerr << "Failed to create ring buffer\n";
        return 1;
    }

    cout << "Attached. Interactive commands:\n"
                << "  oc <path>   -> open then close (generate open+close)\n"
                << "  o <path>  -> open and keep open (returns fd)\n"
                << "  c <fd>     -> close fd\n"
                << "  q          -> quit\n"
                << "Listening for openat/close. Only events from this process (pid="
                << loader_pid << ") will be shown.\n";

    vector<int> kept_fds;

    while (!stop.load()) {
        ring_buffer__poll(rb.get(), 50);
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        timeval tv{0, 0};

        if (select(STDIN_FILENO + 1, &read_fds, nullptr, nullptr, &tv) > 0 &&
            FD_ISSET(STDIN_FILENO, &read_fds)) {
            string line;
            if (!getline(cin, line)) {
                stop.store(true);
                break;
            }
            line = trim(line);
            if (line.empty()) continue;
            if (line == "q") break;
            if (line.starts_with("oc ")) {
                string path = trim(line.substr(3));
                if (path.empty()) { cout << "usage: oc <path>\n"; continue; }
                int fd = open(path.c_str(), O_RDONLY);
                if (fd < 0)
                    cerr << "open failed: " << strerror(errno) << '\n';
                else {
                    close(fd);
                    cout << "Triggered open+close on " << path << '\n';
                }
            } else if (line.starts_with("o ")) {
                string path = trim(line.substr(2));
                if (path.empty()) { cout << "usage: o <path>\n"; continue; }
                int fd = open(path.c_str(), O_RDONLY);
                if (fd < 0)
                    cerr << "open failed: " << strerror(errno) << '\n';
                else {
                    kept_fds.push_back(fd);
                    cout << "Opened (kept) fd=" << fd << " for " << path << '\n';
                }
            } else if (line.starts_with("c ")) {
                string arg = trim(line.substr(2));
                if (arg.empty()) { cout << "usage: c <fd>\n"; continue; }
                int fd = stoi(arg);
                if (fd <= 0) {
                    cout << "invalid fd\n";
                    continue;
                }
                if (close(fd) == 0) {
                    kept_fds.erase(remove(kept_fds.begin(), kept_fds.end(), fd), kept_fds.end());
                    cout << "Closed fd=" << fd << '\n';
                } else {
                    cerr << "close failed: " << strerror(errno) << '\n';
                }
            } else {
                cout << "unknown command\n";
            }
        }
    }

    cout << "Shutting down...\n";
    for (int fd : kept_fds) close(fd);
    return 0;
}