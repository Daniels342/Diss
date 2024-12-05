from bcc import BPF
import os

# Get absolute path to the shared library
library_path = os.path.abspath("./linked_list_lib.so")

# Minimal BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>

int trace_insert(struct pt_regs *ctx) {
    bpf_trace_printk("insert called\\n");
    return 0;
}
"""

# Compile and load the BPF program
b = BPF(text=bpf_program)

# Attach the program to the `insert` function
b.attach_uprobe(name=library_path, sym="insert", fn_name="trace_insert")

# Print BPF trace output
print("Tracing insert()... Hit Ctrl-C to end.")
b.trace_print()


