### **1. Load an eBPF Program**

```bash
sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello
```

Loads an eBPF object file into the kernel and pins it at `/sys/fs/bpf/hello`.

---

### **2. List All Loaded eBPF Programs**

```bash
sudo bpftool prog list
```

Displays all currently loaded eBPF programs and their metadata.

---

### **3. Inspect a Specific Program**

```bash
sudo bpftool prog show id 540 --pretty
sudo bpftool prog show name hello
sudo bpftool prog show tag d35b94b4c0c10efb
sudo bpftool prog show pinned /sys/fs/bpf/hello
```

Shows details (type, size, memory lock, JIT status, etc.) for a specific program by ID, name, tag, or pinned path.

---

### **4. Examine Program Bytecode and Machine Code**

```bash
sudo bpftool prog dump xlated name hello
sudo bpftool prog dump jited name hello
```

Displays the translated eBPF bytecode and the JIT-compiled native instructions.

---

### **5. Attach and Detach the Program**

```bash
sudo bpftool net attach xdp id 540 dev eth0
sudo bpftool net list
sudo bpftool net detach xdp dev eth0
```

Attaches the eBPF program to a network interface (XDP hook), verifies attachment, and detaches it.

---

### **6. View Program Trace Logs**

```bash
sudo bpftool prog tracelog
```

Displays runtime output (e.g., `bpf_printk()` messages) from running eBPF programs.

---

### **7. Inspect Maps Used by Programs**

```bash
sudo bpftool map list
sudo bpftool map dump name hello.bss
sudo bpftool map dump id 165
sudo bpftool map dump name hello.rodata
sudo bpftool map dump id 166
```

Lists kernel eBPF maps and shows their contents (variables, counters, strings, etc.).

---

### **8. Unload a Program**

```bash
sudo rm /sys/fs/bpf/hello
sudo bpftool prog list
```

Removes the pinned eBPF program from the filesystem, unloading it from the kernel.

---

### **9. Experiment with Another Program**

```bash
sudo bpftool prog load hello-func.bpf.o /sys/fs/bpf/hello
sudo bpftool prog list name hello
sudo bpftool prog dump xlated name hello
```

Loads and inspects another eBPF program (with function calls) for deeper understanding.

---
