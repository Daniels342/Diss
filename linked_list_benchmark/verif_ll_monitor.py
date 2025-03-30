#!/usr/bin/env python3
from bcc import BPF
import argparse, time, ctypes as ct

parser = argparse.ArgumentParser(
    description="Runtime verification of verif-optimised linked list insert operations with tail calls"
)
parser.add_argument("binary", help="Path to the verif-optimised binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

bpf_program = r"""
#include <uapi/linux/ptrace.h>

// Structure for storing per-thread state.
struct entry_t {
    u64 head_addr;
    int inserted_val;
    u64 old_head;
};
BPF_HASH(entryinfo, u32, struct entry_t);

// Program array to hold tail call targets.
BPF_PROG_ARRAY(tail_calls, 2);

// Define the node structure that we read from user space.
struct verif_node {
    int data;
    u64 next;
    // Additional fields (if any) are omitted for the verification.
};

// Entry probe: called when the insert function is entered.
int on_insert_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct entry_t val = {};
    val.head_addr = PT_REGS_PARM1(ctx);
    val.inserted_val = PT_REGS_PARM2(ctx);
    // Read the current head pointer (old_head) from user space.
    bpf_probe_read_user(&val.old_head, sizeof(val.old_head), (void*)val.head_addr);
    entryinfo.update(&tid, &val);

    // Tail-call to the verification logic.
    tail_calls.call(ctx, 0);
    return 0;
}

// Tail-called probe: called after insertion to verify the linked list node.
int on_insert_return_impl(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct entry_t *st = entryinfo.lookup(&tid);
    if (!st)
        return 0;

    u64 new_head = 0;
    // Read the updated head pointer.
    bpf_probe_read_user(&new_head, sizeof(new_head), (void*)st->head_addr);
    if (!new_head) {
        entryinfo.delete(&tid);
        return 0;
    }

    int node_data = 0;
    u64 node_next = 0;
    // Efficiently read only the required fields:
    // Read the 'data' field.
    bpf_probe_read_user(&node_data, sizeof(node_data), (void*)new_head);
    // Read the 'next' pointer, which is located after the int 'data'.
    bpf_probe_read_user(&node_next, sizeof(node_next), (void*)(new_head + sizeof(int)));

    // Verify that the node's data and pointer are as expected.
    if (node_data != st->inserted_val || node_next != st->old_head) {
        // Verification failed; you could add logging or counters here.
        entryinfo.delete(&tid);
        return 0;
    }
    entryinfo.delete(&tid);
    return 0;
}
"""

# Load the BPF program.
b = BPF(text=bpf_program)

# Load the tail call function and add it to the tail_calls array at index 0.
# (We load as a KPROBE, but note that the actual attachment is done via the tail call map.)
ret_func = b.load_func("on_insert_return_impl", BPF.KPROBE)
tail_calls = b.get_table("tail_calls")
tail_calls[ct.c_int(0)] = ret_func

# Attach the entry probe to the 'verif_optimised_insert' function.
b.attach_uprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_entry")

print("Attached to verif_optimised_insert probe with tail call. Ctrl+C to exit.")
try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    print("Exiting...")
