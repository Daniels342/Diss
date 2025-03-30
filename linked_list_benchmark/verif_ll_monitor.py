#!/usr/bin/env python3
from bcc import BPF
import argparse, time

parser = argparse.ArgumentParser(description="Runtime verification of verif-optimised linked list insert operations")
parser.add_argument("binary", help="Path to the verif-optimised binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

bpf_program = r"""
#include <uapi/linux/ptrace.h>

struct entry_t {
    u64 head_addr;
    int inserted_val;
    u64 old_head;
};
BPF_HASH(entryinfo, u32, struct entry_t);

// Define the node structure that we read from user space.
struct verif_node {
    int data;
    u64 next;  // assuming pointers are 64-bit; if 32-bit adjust accordingly.
    // We don't need next_free for the verification checks.
};

int on_insert_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct entry_t val = {};
    val.head_addr = PT_REGS_PARM1(ctx);
    val.inserted_val = PT_REGS_PARM2(ctx);
    u64 old_head = 0;
    // Read the value of the head pointer before insertion.
    bpf_probe_read_user(&old_head, sizeof(old_head), (void*)val.head_addr);
    val.old_head = old_head;
    entryinfo.update(&tid, &val);
    return 0;
}

int on_insert_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct entry_t *st = entryinfo.lookup(&tid);
    if (!st) return 0;
    u64 new_head = 0;
    // Read the updated head pointer from the stored head_addr.
    bpf_probe_read_user(&new_head, sizeof(new_head), (void*)st->head_addr);
    if (!new_head) { 
        entryinfo.delete(&tid);
        return 0;
    }
    // Read the entire node structure in one go.
    struct verif_node node = {};
    bpf_probe_read_user(&node, sizeof(node), (void*)new_head);
    // Verify that the node's data is what we expect.
    if (node.data != st->inserted_val || node.next != st->old_head) {
        entryinfo.delete(&tid);
        return 0;
    }
    entryinfo.delete(&tid);
    return 0;
}
"""

b = BPF(text=bpf_program)
b.attach_uprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_return")
print("Attached to verif_optimised_insert probes. Ctrl+C to exit.")
try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    print("Exiting...")
