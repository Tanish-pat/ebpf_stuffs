from bcc import BPF
# eBPF program (C code embedded in Python)
prog = """
int trace_execve(void *ctx) {
    bpf_trace_printk("execve called\\n");
    return 0;
}
"""
# Load and attach
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_execve")
print("Tracing execve syscalls... Ctrl-C to end.")
# Print output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"{ts} {task} [{pid}]: {msg}")
    except KeyboardInterrupt:
        break