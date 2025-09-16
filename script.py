#!/usr/bin/env python3
# script.py
# Requirements: python3-bcc (BCC). Run as root.

import os
import threading
import time
import datetime
from bcc import BPF

TARGET_PID = os.getpid()  # monitor this Python process by default

# --- eBPF program (tracepoints) ---
prog = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fcntl.h>
#include <linux/sched.h>

#define FNAME_LEN 128
#define EVENT_TYPE_LEN 16

struct data_t {
    u32 pid;
    u32 tid;
    int fd;
    int flags;
    int mode;
    u64 count;
    u64 ts_ns;
    char comm[TASK_COMM_LEN];
    char fname[FNAME_LEN];
    char event_type[EVENT_TYPE_LEN];
};

struct open_req_t {
    int flags;
    int mode;
    u64 ts_ns;
    char fname[FNAME_LEN];
};

struct fd_info_t {
    int flags;
    int mode;
    char fname[FNAME_LEN];
};

BPF_HASH(open_tmp, u64, struct open_req_t);
BPF_HASH(fd_info, u64, struct fd_info_t);
BPF_PERF_OUTPUT(events);

static inline u64 tgfd_key(u64 pid_tgid, int fd) {
    return ((pid_tgid & 0xffffffff00000000ULL) | (u32)fd);
}

/* enter openat: stash args in map keyed by pid_tgid */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;

    struct open_req_t req = {};
    req.flags = args->flags;
    req.mode = args->mode;
    req.ts_ns = bpf_ktime_get_ns();

    const char __user *filename = args->filename;
    if (filename)
        bpf_probe_read_user_str(&req.fname, sizeof(req.fname), filename);
    else
        req.fname[0] = '\0';

    open_tmp.update(&pid_tgid, &req);
    return 0;
}

/* exit openat: get returned fd, save fd->name mapping, and emit event */
TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;

    struct open_req_t *reqp = open_tmp.lookup(&pid_tgid);
    if (!reqp) return 0;

    int ret = args->ret; /* file descriptor or negative error */
    if (ret >= 0) {
        struct fd_info_t info = {};
        info.flags = reqp->flags;
        info.mode = reqp->mode;
        bpf_probe_read_kernel_str(&info.fname, sizeof(info.fname), reqp->fname);

        u64 key = tgfd_key(pid_tgid, ret);
        fd_info.update(&key, &info);

        struct data_t ev = {};
        ev.pid = pid;
        ev.tid = (u32) bpf_get_current_pid_tgid();
        ev.fd = ret;
        ev.flags = reqp->flags;
        ev.mode = reqp->mode;
        ev.count = 0;
        ev.ts_ns = reqp->ts_ns;
        bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
        bpf_probe_read_kernel_str(&ev.fname, sizeof(ev.fname), reqp->fname);

        if (reqp->flags & O_CREAT) {
            ev.event_type[0]='C'; ev.event_type[1]='R'; ev.event_type[2]='E';
            ev.event_type[3]='A'; ev.event_type[4]='T'; ev.event_type[5]='E';
            ev.event_type[6]='\0';
        } else {
            ev.event_type[0]='O'; ev.event_type[1]='P'; ev.event_type[2]='E';
            ev.event_type[3]='N'; ev.event_type[4]='\0';
        }
        events.perf_submit(args, &ev, sizeof(ev));
    }
    open_tmp.delete(&pid_tgid);
    return 0;
}

/* write: map fd->name and emit WRITE or WRITE_APP, ignore fd <= 2 */
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;

    int fd = args->fd;
    if (fd <= 2) return 0;

    u64 key = tgfd_key(pid_tgid, fd);
    struct fd_info_t *inf = fd_info.lookup(&key);

    struct data_t ev = {};
    ev.pid = pid;
    ev.tid = (u32) bpf_get_current_pid_tgid();
    ev.fd = fd;
    ev.count = args->count;
    ev.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    if (inf) {
        ev.flags = inf->flags;
        ev.mode = inf->mode;
        bpf_probe_read_kernel_str(&ev.fname, sizeof(ev.fname), inf->fname);
        if (inf->flags & O_APPEND) {
            ev.event_type[0]='W'; ev.event_type[1]='R'; ev.event_type[2]='I';
            ev.event_type[3]='T'; ev.event_type[4]='_'; ev.event_type[5]='A';
            ev.event_type[6]='P'; ev.event_type[7]='P'; ev.event_type[8]='\0';
        } else {
            ev.event_type[0]='W'; ev.event_type[1]='R'; ev.event_type[2]='I';
            ev.event_type[3]='T'; ev.event_type[4]='E'; ev.event_type[5]='\0';
        }
    } else {
        ev.flags = 0;
        ev.mode = 0;
        ev.fname[0] = '\0';
        ev.event_type[0]='W'; ev.event_type[1]='R'; ev.event_type[2]='I';
        ev.event_type[3]='T'; ev.event_type[4]='E'; ev.event_type[5]='\0';
    }
    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* pwrite64: same as write */
TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;

    int fd = args->fd;
    if (fd <= 2) return 0;

    u64 key = tgfd_key(pid_tgid, fd);
    struct fd_info_t *inf = fd_info.lookup(&key);

    struct data_t ev = {};
    ev.pid = pid;
    ev.tid = (u32) bpf_get_current_pid_tgid();
    ev.fd = fd;
    ev.count = args->count;
    ev.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    if (inf) {
        ev.flags = inf->flags;
        ev.mode = inf->mode;
        bpf_probe_read_kernel_str(&ev.fname, sizeof(ev.fname), inf->fname);
        if (inf->flags & O_APPEND) {
            ev.event_type[0]='W'; ev.event_type[1]='R'; ev.event_type[2]='I';
            ev.event_type[3]='T'; ev.event_type[4]='_'; ev.event_type[5]='A';
            ev.event_type[6]='P'; ev.event_type[7]='P'; ev.event_type[8]='\0';
        } else {
            ev.event_type[0]='W'; ev.event_type[1]='R'; ev.event_type[2]='I';
            ev.event_type[3]='T'; ev.event_type[4]='E'; ev.event_type[5]='\0';
        }
    } else {
        ev.flags = 0;
        ev.mode = 0;
        ev.fname[0] = '\0';
        ev.event_type[0]='W'; ev.event_type[1]='R'; ev.event_type[2]='I';
        ev.event_type[3]='T'; ev.event_type[4]='E'; ev.event_type[5]='\0';
    }
    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* close: drop fd->name mapping */
TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;

    int fd = args->fd;
    if (fd <= 2) return 0;
    u64 key = tgfd_key(pid_tgid, fd);
    fd_info.delete(&key);
    return 0;
}

/* unlink/unlinkat -> DELETE event */
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;

    struct data_t ev = {};
    ev.pid = pid;
    ev.tid = (u32) bpf_get_current_pid_tgid();
    ev.fd = -1;
    ev.flags = 0;
    ev.mode = 0;
    ev.count = 0;
    ev.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    const char __user *pathname = args->pathname;
    if (pathname)
        bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), pathname);
    else
        ev.fname[0] = '\0';

    ev.event_type[0]='D'; ev.event_type[1]='E'; ev.event_type[2]='L';
    ev.event_type[3]='E'; ev.event_type[4]='T'; ev.event_type[5]='E';
    ev.event_type[6]='\0';

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;

    struct data_t ev = {};
    ev.pid = pid;
    ev.tid = (u32) bpf_get_current_pid_tgid();
    ev.fd = args->dfd;
    ev.flags = 0;
    ev.mode = 0;
    ev.count = 0;
    ev.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    const char __user *pathname = args->pathname;
    if (pathname)
        bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), pathname);
    else
        ev.fname[0] = '\0';

    ev.event_type[0]='D'; ev.event_type[1]='E'; ev.event_type[2]='L';
    ev.event_type[3]='E'; ev.event_type[4]='T'; ev.event_type[5]='E';
    ev.event_type[6]='\0';

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

# compile and inject TARGET_PID
b = BPF(text=prog, cflags=[f"-D TARGET_PID={TARGET_PID}", "-w"])

# --- Python-side filesystem view and helpers ---
import os as _os
import json
from collections import defaultdict

# In-memory view:
# file_index: abs_path -> metadata dict { 'fds': set(), 'flags': int, 'mode': int, 'last_write': ts_ns, 'bytes_written': int }
file_index = {}
# fd_map: (pid, fd) -> abs_path
fd_map = {}
# map lock
state_lock = threading.Lock()

# helpers to normalize path reported by eBPF to absolute path (best-effort)
def norm_event_path(raw):
    if not raw:
        return ""
    path = raw.decode("utf-8", "replace").strip("\x00")
    if path == "":
        return ""
    if path.startswith("/"):
        return os.path.normpath(path)
    # relative path: resolve against current working directory of this monitor
    return os.path.normpath(os.path.join(os.getcwd(), path))

# flag decoding for readability
FLAG_BITS = [
    ("O_CREAT", getattr(_os, "O_CREAT", 0)),
    ("O_EXCL", getattr(_os, "O_EXCL", 0)),
    ("O_TRUNC", getattr(_os, "O_TRUNC", 0)),
    ("O_APPEND", getattr(_os, "O_APPEND", 0)),
    ("O_CLOEXEC", getattr(_os, "O_CLOEXEC", 0)),
    ("O_RDONLY", getattr(_os, "O_RDONLY", 0)),
    ("O_WRONLY", getattr(_os, "O_WRONLY", 0)),
    ("O_RDWR", getattr(_os, "O_RDWR", 0)),
    ("O_NONBLOCK", getattr(_os, "O_NONBLOCK", 0)),
]

def decode_flags(flags):
    if not flags:
        return ""
    parts = []
    accmode = getattr(_os, "O_ACCMODE", 3)
    mode = flags & accmode
    if mode == getattr(_os, "O_RDONLY", 0):
        parts.append("O_RDONLY")
    elif mode == getattr(_os, "O_WRONLY", 0):
        parts.append("O_WRONLY")
    else:
        parts.append("O_RDWR")
    for name, bit in FLAG_BITS:
        if bit and (flags & bit) and name not in ("O_RDONLY","O_WRONLY","O_RDWR"):
            parts.append(name)
    return "|".join(parts)

def ts_to_str(ts_ns):
    return datetime.datetime.fromtimestamp(ts_ns / 1e9).strftime("%Y-%m-%d %H:%M:%S.%f")

# update local state from an incoming event
def handle_event_record(ev):
    pid = ev.pid
    fd = ev.fd
    raw_fname = ev.fname
    fname = norm_event_path(raw_fname)
    etype = ev.event_type.decode("utf-8", "replace").strip("\x00")
    ts_ns = ev.ts_ns or int(time.time() * 1e9)
    count = ev.count or 0
    flags = ev.flags
    mode = ev.mode

    key_fd = (pid, fd)

    with state_lock:
        if etype in ("CREATE", "OPEN"):
            # record fd -> filename mapping
            if fd >= 0:
                fd_map[key_fd] = fname
                # update file_index entry
                meta = file_index.get(fname, {"fds": set(), "flags": flags, "mode": mode, "last_write": None, "bytes_written": 0})
                meta["fds"].add(fd)
                meta["flags"] = flags
                meta["mode"] = mode
                file_index[fname] = meta
        elif etype.startswith("WRITE"):
            # attempt to find filename: first try event fname, then fd_map
            if fname:
                path = fname
            else:
                path = fd_map.get(key_fd, "")
            if path:
                meta = file_index.get(path, {"fds": set(), "flags": flags, "mode": mode, "last_write": None, "bytes_written": 0})
                meta["last_write"] = ts_ns
                meta["bytes_written"] = meta.get("bytes_written", 0) + int(count)
                file_index[path] = meta
                # ensure fd is tracked
                if fd >= 0:
                    meta["fds"].add(fd)
                    fd_map[key_fd] = path
        elif etype == "DELETE":
            # remove from index; unlink may be relative, normalize
            if fname:
                path = fname
                if path in file_index:
                    del file_index[path]
                # remove any fd_map entries that point to this path
                keys_to_remove = [k for k, v in fd_map.items() if v == path]
                for k in keys_to_remove:
                    del fd_map[k]
        # close is handled in BPF (fd_info deleted) but we should remove fd mapping on close events (we'll get no explicit CLOSE event record; if present, handle here)
        # Note: BPF does not submit a perf event for close; it only deletes kernel map entry. To keep user map consistent, we might track close via sys_enter_close tracepoint that emits events (not currently implemented).
    # end with state update

# callback for perf buffer
def print_and_update(cpu, data, size):
    ev = b["events"].event(data)
    # print enriched log, then update the in-memory view
    comm = ev.comm.decode("utf-8", "replace").strip("\x00")
    raw_fname = ev.fname
    fname = norm_event_path(raw_fname)
    etype = ev.event_type.decode("utf-8", "replace").strip("\x00")
    ts = ts_to_str(ev.ts_ns) if ev.ts_ns else time.strftime("%Y-%m-%d %H:%M:%S")
    flags_str = decode_flags(ev.flags) if ev.flags else ""
    mode = ev.mode
    pid = ev.pid
    tid = ev.tid
    fd = ev.fd
    count = ev.count

    # readable logging
    if etype == "CREATE":
        print(f"[EVENT] CREATE_FILE by {comm} (PID={pid}, TID={tid}, FD={fd}, FLAGS={flags_str}, MODE={mode}, TIME={ts}): FNAME={fname}")
    elif etype == "OPEN":
        print(f"[EVENT] OPEN_FILE by {comm} (PID={pid}, TID={tid}, FD={fd}, FLAGS={flags_str}, MODE={mode}, TIME={ts}): FNAME={fname}")
    elif etype.startswith("WRITE"):
        label = "WRITE_APPEND" if "APP" in etype else "WRITE"
        print(f"[EVENT] {label} by {comm} (PID={pid}, TID={tid}, FD={fd}, COUNT={count}, TIME={ts}): FNAME={fname}")
    elif etype == "DELETE":
        print(f"[EVENT] DELETE by {comm} (PID={pid}, TID={tid}, FD={fd}, TIME={ts}): FNAME={fname}")
    else:
        print(f"[EVENT] {etype} by {comm} (PID={pid}, TID={tid}, FD={fd}, FLAGS={flags_str}, MODE={mode}, COUNT={count}, TIME={ts}): FNAME={fname}")

    # update internal view
    handle_event_record(ev)

# attach perf buffer
b["events"].open_perf_buffer(print_and_update, page_cnt=64)

# poller thread: keeps consuming events so interactive UI can run concurrently
stop_event = threading.Event()

def perf_poller():
    while not stop_event.is_set():
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break
        except Exception:
            # tolerate intermittent errors
            time.sleep(0.1)

# start poller thread
poller = threading.Thread(target=perf_poller, daemon=True)
poller.start()

# --- Interactive CLI (simulator) ---
def add_file_entry_for_path(path):
    """Ensure file_index has an entry (used for simulator-created files)."""
    abspath = os.path.normpath(os.path.abspath(path))
    with state_lock:
        if abspath not in file_index:
            file_index[abspath] = {"fds": set(), "flags": 0, "mode": 0, "last_write": None, "bytes_written": 0}

def ls(dirpath=None):
    dirpath = dirpath or os.getcwd()
    dirpath = os.path.normpath(os.path.abspath(dirpath))
    with state_lock:
        entries = [p for p in file_index.keys() if os.path.dirname(p) == dirpath]
    print(f"Listing for {dirpath}:")
    if not entries:
        print("  (empty)")
    else:
        for p in sorted(entries):
            meta = file_index.get(p, {})
            bw = meta.get("bytes_written", 0)
            lw = ts_to_str(meta["last_write"]) if meta.get("last_write") else "-"
            print(f"  {os.path.basename(p)}  bytes_written={bw} last_write={lw}")

def tree(root=None):
    root = root or os.getcwd()
    root = os.path.normpath(os.path.abspath(root))
    # build map dir -> files
    with state_lock:
        dir_map = {}
        for p in file_index.keys():
            d = os.path.dirname(p)
            dir_map.setdefault(d, []).append(os.path.basename(p))
    # walk directories (only those present)
    dirs = sorted(dir_map.keys())
    for d in dirs:
        if d.startswith(root):
            rel = os.path.relpath(d, root)
            indent = "" if rel == "." else f"{rel}/"
            print(f"{d}:")
            for f in sorted(dir_map[d]):
                print(f"    {f}")

def cmd_create(path):
    abspath = os.path.normpath(os.path.abspath(path))
    # create via Python IO so eBPF sees it
    with open(abspath, "w") as fh:
        fh.write("")  # create empty
    # we may get events from eBPF; add provisional entry to reduce race
    add_file_entry_for_path(abspath)
    print(f"Created {abspath}")

def cmd_write(path, text, append=False):
    abspath = os.path.normpath(os.path.abspath(path))
    mode = "a" if append else "w"
    with open(abspath, mode) as fh:
        fh.write(text)
    add_file_entry_for_path(abspath)
    print(f"Wrote to {abspath} ({'append' if append else 'write'})")

def cmd_open(path):
    abspath = os.path.normpath(os.path.abspath(path))
    if not os.path.exists(abspath):
        print("File does not exist.")
        return
    with open(abspath, "r") as fh:
        content = fh.read()
    print(f"--- {abspath} contents ---")
    print(content)
    print("--- EOF ---")

def cmd_delete(path):
    abspath = os.path.normpath(os.path.abspath(path))
    if not os.path.exists(abspath):
        print("File does not exist on disk. Removing from view if present.")
    else:
        os.remove(abspath)
    # removal will be observed by eBPF unlink event; remove provisional
    with state_lock:
        if abspath in file_index:
            del file_index[abspath]
    print(f"Deleted {abspath} (or scheduled)")

def status():
    with state_lock:
        print("Monitored files:")
        if not file_index:
            print("  (none)")
            return
        for p, m in file_index.items():
            fds = ",".join(str(x) for x in sorted(m.get("fds", []))) if m.get("fds") else "-"
            bw = m.get("bytes_written", 0)
            lw = ts_to_str(m["last_write"]) if m.get("last_write") else "-"
            print(f"  {p} fd={fds} bytes_written={bw} last_write={lw}")

def help_text():
    print("Commands:")
    print("  ls [dir]             - list files in directory (monitor view)")
    print("  tree [root]          - show simple tree of monitored directories")
    print("  create <path>        - create file (touch) via Python IO")
    print("  write <path> <text>  - overwrite file with text")
    print("  append <path> <text> - append text to file")
    print("  open <path>          - print file contents (Python IO)")
    print("  delete <path>        - delete file")
    print("  status               - print internal monitored state")
    print("  exit                 - quit")

# initial message
print(f"Monitoring file ops for PID={TARGET_PID}. Interactive shell started.")
print("NOTE: This monitor observes operations performed by this process. Use the commands below to exercise.")
help_text()

# interactive loop
try:
    while True:
        cmdline = input("efs> ").strip()
        if not cmdline:
            continue
        parts = cmdline.split()
        cmd = parts[0].lower()
        args = parts[1:]
        if cmd == "ls":
            if args:
                ls(args[0])
            else:
                ls()
        elif cmd == "tree":
            tree(args[0] if args else None)
        elif cmd == "create" and len(args) == 1:
            cmd_create(args[0])
        elif cmd == "write" and len(args) >= 2:
            path = args[0]
            text = " ".join(args[1:])
            cmd_write(path, text, append=False)
        elif cmd == "append" and len(args) >= 2:
            path = args[0]
            text = " ".join(args[1:])
            cmd_write(path, text, append=True)
        elif cmd == "open" and len(args) == 1:
            cmd_open(args[0])
        elif cmd == "delete" and len(args) == 1:
            cmd_delete(args[0])
        elif cmd == "status":
            status()
        elif cmd == "help":
            help_text()
        elif cmd in ("exit", "quit"):
            break
        else:
            print("Unknown command or wrong args. Type 'help' for usage.")
finally:
    # shutdown
    stop_event.set()
    poller.join(timeout=1.0)
    print("Monitor stopped. Exiting.")