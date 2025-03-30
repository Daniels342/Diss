#!/usr/bin/env python3
from bcc import BPF
import time, argparse

parser = argparse.ArgumentParser(description="Runtime verification of verif-optimised linked list insert operations")
parser.add_argument("binary", help="Path to the verif-optimised binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

# eBPF C program:
# - We define a simple doubly linked list node structure with 'next' and 'prev' pointers.
# - The kretprobe (attached to the return of the insert function) reads the inserted node
#   and checks the following invariants:
#     1. The new node must be inserted at the head, so new_node->prev must be 0.
#     2. If new_node->next exists, then new_node->next->prev must equal new_node.
#
# The program uses bpf_probe_read() for safe access and prints a trace message only on
# invariant violations.
bpf_text = r"""
#include <uapi/linux/ptrace.h>
struct node {
    int data;
    u64 next;      // pointer to next node
    u64 prev;      // pointer to previous node
    u64 next_free; // pointer to free list
};

// This uretprobe function runs after verif_optimised_insert returns.
// The first parameter of verif_optimised_insert is a pointer to the head pointer.
// After insertion, *head should point to the newly inserted node.
// We then verify:
//  1. The inserted node's 'prev' pointer is 0 (i.e. inserted at the head).
//  2. If inserted node->next exists, then its 'prev' pointer should equal the address of the inserted node.
int retprobe_insert(struct pt_regs *ctx) {
    // Get pointer to head (first argument)
    u64 head_ptr_addr = (u64)PT_REGS_PARM1(ctx);
    u64 new_node_addr = 0;

    // Read the head pointer from memory; after insert, *head should be the new node.
    if (bpf_probe_read(&new_node_addr, sizeof(new_node_addr), (void*)head_ptr_addr) != 0)
        return 0;
    if (new_node_addr == 0)
        return 0;

    // Read the inserted node's data.
    struct node new_node = {};
    if (bpf_probe_read(&new_node, sizeof(new_node), (void*)new_node_addr) != 0)
        return 0;

    // Check invariant: inserted node should be at the head, so its 'prev' must be 0.
    if (new_node.prev != 0) {
        bpf_trace_printk("Invariant violation: inserted node is not at head (prev != 0)\\n");
    }

    // Check invariant: if new_node->next exists, then new_node->next->prev must equal new_node_addr.
    if (new_node.next != 0) {
        struct node next_node = {};
        if (bpf_probe_read(&next_node, sizeof(next_node), (void*)new_node.next) != 0)
            return 0;
        if (next_node.prev != new_node_addr) {
            bpf_trace_printk("Invariant violation: new->next->prev != new (after insert)\\n");
        }
    }
    return 0;
}
"""

# Load the BPF program.
b = BPF(text=bpf_text)

# Attach a kretprobe to the insertion function (assumed here to be named "insert_node").
# The kretprobe executes after the function returns, so we check the list state after the insert.
b.attach_uretprobe(name=args.binary, sym="verif_optimised_insert", fn_name="retprobe_insert")
print("Monitoring linked list insertions (post-return verification)... Press Ctrl-C to exit.")
try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%s" % (msg))
except KeyboardInterrupt:
    pass
