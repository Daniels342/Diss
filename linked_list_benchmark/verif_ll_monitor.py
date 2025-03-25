#!/usr/bin/env python3
from bcc import BPF
import argparse
import time

parser = argparse.ArgumentParser(description="Runtime verification of verif-optimised linked list operations")
parser.add_argument("binary", help="Path to the verif-optimised linked list binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

# BPF program for verifying insert and delete operations with a deletion hook.
bpf_program = r"""
#include <uapi/linux/ptrace.h>

// Structure to capture insert parameters.
struct entry_t {
    u64 head_addr;    // Address of the head pointer (first parameter)
    int inserted_val; // Inserted value (for insert probe)
    u64 old_head;     // Value of *head before insert
};

// Structure to capture deletion context as gathered in the deletion probe.
struct del_entry_t {
    u64 head_addr;     // Address of the head pointer
    int target_val;    // Value intended for deletion
    u64 found;         // 1 if a node with target value is found, else 0.
    u64 pred;          // Pointer to predecessor node (0 if deletion is at head)
    u64 node_to_delete;// Pointer to the node that should be deleted.
    u64 next_after;    // The next pointer from the node to delete (i.e. expected new link)
};

// New structure to capture hook information from delete_node_info.
struct hook_del_t {
    u64 pred;
    u64 target;
    u64 succ;
};

BPF_HASH(entryinfo, u32, struct entry_t);
BPF_HASH(delinfo, u32, struct del_entry_t);
BPF_HASH(hookinfo, u32, struct hook_del_t);

//
// Probe for verif_optimised_insert entry
//
int on_insert_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t val = {};

    // Assume signature: void verif_optimised_insert(OptimisedNode** head, int data)
    val.head_addr = PT_REGS_PARM1(ctx);
    val.inserted_val = PT_REGS_PARM2(ctx);

    // Read the old head pointer from user space.
    u64 old_head = 0;
    bpf_probe_read_user(&old_head, sizeof(old_head), (void*)val.head_addr);
    val.old_head = old_head;

    entryinfo.update(&tid, &val);
    return 0;
}

//
// Probe for verif_optimised_insert return
//
int on_insert_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t *st = entryinfo.lookup(&tid);
    if (!st) return 0;

    u64 new_head_ptr = 0;
    bpf_probe_read_user(&new_head_ptr, sizeof(new_head_ptr), (void*)st->head_addr);
    if (new_head_ptr == 0) {
        bpf_trace_printk("ERROR: verif_optimised_insert: new head is NULL (tid %d)\\n", tid);
        entryinfo.delete(&tid);
        return 0;
    }

    int new_node_data = 0;
    bpf_probe_read_user(&new_node_data, sizeof(new_node_data), (void*)new_head_ptr);
    if (new_node_data != st->inserted_val) {
        bpf_trace_printk("ERROR: verif_optimised_insert: data mismatch: new node data %d != inserted %d (tid %d)\\n",
            new_node_data, st->inserted_val, tid);
        entryinfo.delete(&tid);
        return 0;
    }

    u64 new_node_next = 0;
    // Assuming the 'next' pointer is at offset 8.
    bpf_probe_read_user(&new_node_next, sizeof(new_node_next), (void*)(new_head_ptr + 8));
    if (new_node_next != st->old_head) {
        bpf_trace_printk("ERROR: verif_optimised_insert: new node's next pointer 0x%lx != old head 0x%lx (tid %d)\\n",
            new_node_next, st->old_head, tid);
        entryinfo.delete(&tid);
        return 0;
    }

    entryinfo.delete(&tid);
    return 0;
}

//
// Probe for verif_optimised_delete entry (existing bounded scan).
//
int on_delete_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_entry_t dval = {};
    dval.head_addr = PT_REGS_PARM1(ctx);
    dval.target_val = PT_REGS_PARM2(ctx);
    dval.found = 0;

    // Read the current head pointer from user memory.
    u64 head_ptr = 0;
    bpf_probe_read_user(&head_ptr, sizeof(head_ptr), (void*)dval.head_addr);
    if (head_ptr == 0) {
        // Empty list; nothing to verify.
        delinfo.update(&tid, &dval);
        return 0;
    }

    // Check if the head node is the one to be deleted.
    int node_val = 0;
    bpf_probe_read_user(&node_val, sizeof(node_val), (void*)head_ptr);
    if (node_val == dval.target_val) {
        dval.found = 1;
        dval.pred = 0; // indicates deletion at head
        dval.node_to_delete = head_ptr;
        // Read the next pointer (offset 8).
        bpf_probe_read_user(&dval.next_after, sizeof(dval.next_after), (void*)(head_ptr + 8));
        delinfo.update(&tid, &dval);
        return 0;
    }

    // Otherwise, traverse a bounded number of nodes (limit 10 iterations).
    u64 curr = head_ptr;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        u64 next_ptr = 0;
        bpf_probe_read_user(&next_ptr, sizeof(next_ptr), (void*)(curr + 8));
        if (next_ptr == 0) break;
        int next_val = 0;
        bpf_probe_read_user(&next_val, sizeof(next_val), (void*)next_ptr);
        if (next_val == dval.target_val) {
            dval.found = 1;
            dval.pred = curr;
            dval.node_to_delete = next_ptr;
            bpf_probe_read_user(&dval.next_after, sizeof(dval.next_after), (void*)(next_ptr + 8));
            break;
        }
        curr = next_ptr;
    }
    delinfo.update(&tid, &dval);
    return 0;
}

//
// New probe: hook for deletion information.
// This hook is called when the node to delete is found.
// It receives the predecessor, target, and successor pointers.
int on_delete_hook(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct hook_del_t hinfo = {};
    hinfo.pred = PT_REGS_PARM1(ctx);
    hinfo.target = PT_REGS_PARM2(ctx);
    hinfo.succ = PT_REGS_PARM3(ctx);
    hookinfo.update(&tid, &hinfo);
    return 0;
}

//
// Probe for verif_optimised_delete return: verify that deletion updated the pointers correctly.
// It uses both the original delinfo and the hook information if available.
int on_delete_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_entry_t *dval = delinfo.lookup(&tid);
    if (!dval) return 0;

    // First, if we have hook info, use it for verification.
    struct hook_del_t *hinfo = hookinfo.lookup(&tid);
    if (hinfo) {
        if (hinfo->pred == 0) {
            // Deletion at head; re-read the head pointer.
            u64 new_head = 0;
            bpf_probe_read_user(&new_head, sizeof(new_head), (void*)dval->head_addr);
            if (new_head != hinfo->succ) {
                bpf_trace_printk("ERROR: delete hook: head deletion: new head 0x%lx != expected 0x%lx (tid %d)\\n",
                    new_head, hinfo->succ, tid);
            }
        } else {
            // Deletion in the middle; re-read the predecessor's next pointer.
            u64 new_link = 0;
            bpf_probe_read_user(&new_link, sizeof(new_link), (void*)(hinfo->pred + 8));
            if (new_link != hinfo->succ) {
                bpf_trace_printk("ERROR: delete hook: mid deletion: pred->next 0x%lx != expected 0x%lx (tid %d)\\n",
                    new_link, hinfo->succ, tid);
            }
        }
        hookinfo.delete(&tid);
    }
    
    // Fallback check: using our original delinfo method.
    if (dval->found) {
        if (dval->pred == 0) {
            // Deletion at head; re-read the head pointer.
            u64 new_head = 0;
            bpf_probe_read_user(&new_head, sizeof(new_head), (void*)dval->head_addr);
            if (new_head != dval->next_after) {
                bpf_trace_printk("ERROR: verif_optimised_delete: head deletion: new head 0x%lx != expected 0x%lx (tid %d)\\n",
                    new_head, dval->next_after, tid);
            }
        } else {
            // Deletion in the middle; re-read the predecessor's next pointer.
            u64 new_link = 0;
            bpf_probe_read_user(&new_link, sizeof(new_link), (void*)(dval->pred + 8));
            if (new_link != dval->next_after) {
                bpf_trace_printk("ERROR: verif_optimised_delete: mid deletion: pred->next 0x%lx != expected 0x%lx (tid %d)\\n",
                    new_link, dval->next_after, tid);
            }
        }
    }
    delinfo.delete(&tid);
    return 0;
}
"""

# Load BPF program.
b = BPF(text=bpf_program)

# Attach probes for verif_optimised_insert.
b.attach_uprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_return")

# Attach probes for verif_optimised_delete.
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_return")

# Attach probe for the deletion hook.
b.attach_uprobe(name=args.binary, sym="delete_node_info", fn_name="on_delete_hook")

print("Attached to verif_optimised_insert, verif_optimised_delete, and delete_node_info hook. Ctrl+C to exit.")
try:
    while True:
        time.sleep(5)
        # To view trace output, run:
        # sudo cat /sys/kernel/debug/tracing/trace_pipe
except KeyboardInterrupt:
    print("Exiting...")
