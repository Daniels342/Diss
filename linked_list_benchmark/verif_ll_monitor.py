#!/usr/bin/env python3
from bcc import BPF
import time

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
struct node {
    u64 next;
    u64 prev;
    int value;
};

int retprobe_insert(struct pt_regs *ctx) {
    // Retrieve the pointer to the new node from the first parameter.
    struct node *new_node = (struct node *)PT_REGS_PARM1(ctx);
    struct node n = {};
    
    // Safely copy the new node's content.
    if (bpf_probe_read(&n, sizeof(n), new_node) != 0)
        return 0;

    // Check that the new node is inserted at the head:
    // Its 'prev' pointer must be 0.
    if (n.prev != 0) {
        bpf_trace_printk("Invariant violation: inserted node is not at head (prev != 0)\\n");
    }
    
    // If the node has a next pointer, verify that the next node's 'prev' points back to new_node.
    if (n.next != 0) {
        struct node next_node = {};
        if (bpf_probe_read(&next_node, sizeof(next_node), (void *)n.next) != 0)
            return 0;
        if (next_node.prev != (u64)new_node) {
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
b.attach_kretprobe(event="insert_node", fn_name="retprobe_insert")

print("Monitoring linked list insertions (post-return verification)... Press Ctrl-C to exit.")
try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%s" % (msg))
except KeyboardInterrupt:
    pass
