// storefs_loader.cpp
extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
}
#include <iostream>
#include <vector>
#include <string>
#include <dirent.h>
#include <cstring>
#include <cstdlib>

static volatile sig_atomic_t stop = 0;
static void handle_signal(int) { stop = 1; }

static std::vector<std::string> list_files_cwd() {
    std::vector<std::string> out;
    DIR *d = opendir(".");
    if (!d) return out;
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_type == DT_REG) out.emplace_back(ent->d_name);
    }
    closedir(d);
    return out;
}

int main() {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    struct bpf_object *obj = nullptr;
    int err;

    obj = bpf_object__open_file("storefs.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        std::cerr << "failed to open BPF object\n";
        return 1;
    }
    err = bpf_object__load(obj);
    if (err) {
        std::cerr << "failed to load BPF object: " << err << "\n";
        return 1;
    }

    /* Attach programs (libbpf autoloads tracepoints by section names) */
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__attach(prog) == NULL) {
            // When attach returns NULL it's an error (libbpf returns error pointer)
            // But different libbpf versions behave differently; check libbpf_get_error
            struct bpf_link *link = bpf_program__attach(prog);
            if (libbpf_get_error(link)) {
                std::cerr << "prog attach failed\n";
            } else {
                // ok
            }
        }
    }

    /* find map fds */
    int map_fd_store = bpf_object__find_map_fd_by_name(obj, "file_store");
    if (map_fd_store < 0) {
        std::cerr << "failed to find file_store map\n";
        return 1;
    }

    int map_fd_fd2path = bpf_object__find_map_fd_by_name(obj, "fd_to_path");
    int map_fd_pending = bpf_object__find_map_fd_by_name(obj, "pending_open");
    (void)map_fd_fd2path; (void)map_fd_pending;

    std::cout << "storefs loaded. Commands:\n"
              << "  list          - list regular files in cwd\n"
              << "  open <n>      - open file by index (triggers openat syscall)\n"
              << "  write <n>     - write text to open file (uses write syscall)\n"
              << "  show <path>   - read stored copy from kernel map and print\n"
              << "  exit\n";

    std::vector<std::string> files = list_files_cwd();
    for (;;) {
        if (stop) break;
        std::cout << "> ";
        std::string cmd;
        if (! (std::cin >> cmd)) break;
        if (cmd == "list") {
            files = list_files_cwd();
            for (size_t i = 0; i < files.size(); ++i) {
                std::cout << i << ": " << files[i] << "\n";
            }
        } else if (cmd == "open") {
            int idx;
            std::cin >> idx;
            if (idx < 0 || (size_t)idx >= files.size()) { std::cout << "invalid\n"; continue; }
            int fd = open(files[idx].c_str(), O_RDWR | O_CREAT, 0644);
            if (fd < 0) { perror("open"); continue; }
            std::cout << "Opened fd=" << fd << " for " << files[idx] << ". Keep it open or close later with 'closefd' (not provided).\n";
            // we intentionally don't close fd so writes will map to this fd
        } else if (cmd == "write") {
            int idx;
            std::cin >> idx;
            if (idx < 0 || (size_t)idx >= files.size()) { std::cout << "invalid\n"; continue; }
            std::string rest;
            std::getline(std::cin, rest); // consume rest of line
            std::cout << "Enter text, end with EOF (Ctrl-D):\n";
            std::string text, line;
            while (std::getline(std::cin, line)) {
                text += line;
                text.push_back('\n');
            }
            // attempt to open the file and write (this will fire the write syscall and BPF will capture)
            int fd = open(files[idx].c_str(), O_WRONLY);
            if (fd < 0) { perror("open for write"); continue; }
            ssize_t w = write(fd, text.data(), text.size());
            if (w < 0) perror("write");
            close(fd);
            std::cout << "Wrote " << w << " bytes (captured by BPF)\n";
            // after Ctrl-D, std::cin will be EOF; re-open stdin
            clearerr(stdin);
        } else if (cmd == "show") {
            std::string path;
            std::cin >> path;
            if (path.empty()) { std::cout << "need path\n"; continue; }

            /* prepare key */
            char key[128];
            memset(key, 0, sizeof(key));
            strncpy(key, path.c_str(), sizeof(key)-1);

            struct {
                uint32_t len;
                unsigned char data[4096];
            } value;
            memset(&value, 0, sizeof(value));

            int res = bpf_map_lookup_elem(map_fd_store, key, &value);
            if (res == 0) {
                std::cout << "Stored (" << value.len << " bytes):\n";
                std::cout.write((const char*)value.data, value.len);
                std::cout << "\n";
            } else {
                std::cout << "No stored data for path or lookup failed\n";
            }
        } else if (cmd == "exit") {
            break;
        } else {
            std::cout << "unknown\n";
        }
    }

    // cleanup: close bpf object
    bpf_object__close(obj);
    return 0;
}