#!/usr/bin/env python3

import os
import time
import datetime
from bcc import BPF

TARGET_PID = os.getpid()  # change to specific PID if you want to monitor another process

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

    struct open_req_t req;
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
        struct fd_info_t info;
        info.flags = reqp->flags;
        info.mode = reqp->mode;
        /* copy name from req (map) into info */
        bpf_probe_read_kernel_str(&info.fname, sizeof(info.fname), reqp->fname);

        u64 key = tgfd_key(pid_tgid, ret);
        fd_info.update(&key, &info);

        struct data_t ev;
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

/* write: map fd->name and emit WRITE or WRITE_APP, ignore fd <= 2 (stdin/out/err) */
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;

    int fd = args->fd;
    if (fd <= 2) return 0; /* skip stdin/stdout/stderr to avoid monitor self-noise */

    u64 key = tgfd_key(pid_tgid, fd);
    struct fd_info_t *inf = fd_info.lookup(&key);

    struct data_t ev;
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

    struct data_t ev;
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

    struct data_t ev;
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

    struct data_t ev;
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

# helpers for pretty output
import os as _os
FLAG_NAMES = [
    ("O_RDONLY", getattr(_os, "O_RDONLY", 0)),
    ("O_WRONLY", getattr(_os, "O_WRONLY", 1)),
    ("O_RDWR",   getattr(_os, "O_RDWR", 2)),
]
EXTRA_FLAG_BITS = [
    ("O_CREAT", getattr(_os, "O_CREAT", 0)),
    ("O_EXCL", getattr(_os, "O_EXCL", 0)),
    ("O_NOCTTY", getattr(_os, "O_NOCTTY", 0)),
    ("O_TRUNC", getattr(_os, "O_TRUNC", 0)),
    ("O_APPEND", getattr(_os, "O_APPEND", 0)),
    ("O_DIRECTORY", getattr(_os, "O_DIRECTORY", 0)),
    ("O_CLOEXEC", getattr(_os, "O_CLOEXEC", 0)),
]

def decode_flags(flags):
    try:
        acc = flags & getattr(_os, "O_ACCMODE", 3)
    except Exception:
        acc = flags & 3
    mode_str = "O_RDONLY" if acc == getattr(_os, "O_RDONLY", 0) else ("O_WRONLY" if acc == getattr(_os, "O_WRONLY",1) else "O_RDWR")
    extras = []
    for name, val in EXTRA_FLAG_BITS:
        if val != 0 and (flags & val):
            extras.append(name)
    return "|".join([mode_str] + extras) if extras else mode_str

def ts_to_str(ts_ns):
    return datetime.datetime.fromtimestamp(ts_ns / 1e9).strftime("%H:%M:%S.%f")

def print_event(cpu, data, size):
    ev = b["events"].event(data)
    comm = ev.comm.decode("utf-8", "replace").strip("\x00")
    fname = ev.fname.decode("utf-8", "replace").strip("\x00")
    etype = ev.event_type.decode("utf-8", "replace").strip("\x00")
    ts = ts_to_str(ev.ts_ns) if ev.ts_ns else time.strftime("%H:%M:%S")
    flags_str = decode_flags(ev.flags) if ev.flags else ""
    mode = ev.mode
    pid = ev.pid
    tid = ev.tid
    fd = ev.fd
    count = ev.count

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

b["events"].open_perf_buffer(print_event, page_cnt=64)

print(f"Monitoring file ops for PID={TARGET_PID}. Press Ctrl-C to exit.")

with open("testfile1.txt", "w") as f:
    f.write("hello")
with open("testfile1.txt", "a") as f:
    f.write("more text")
os.remove("testfile1.txt")

try:
    while True:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    print("Stopping monitor.")