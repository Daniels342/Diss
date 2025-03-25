#!/usr/bin/env python3
from bcc import BPF
import argparse
import time

parser = argparse.ArgumentParser(description="BCC-based monitoring for linked list operations with deletion verification")
parser.add_argument("binary", help="Path to the verif-optimised linked list binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

# BPF program: counting probes plus deletion verification.
bpf_program = r"""
#include <uapi/linux/ptrace.h>

// Structure to hold deletion hook information.
struct del_info_t {
    u64 pred;   // Predecessor node pointer (NULL if deletion at head)
    u64 target; // Pointer to the node that is to be deleted
    u64 succ;   // Expected successor pointer (i.e. target->next)
};

BPF_HASH(insert_count, u64);
BPF_HASH(delete_count, u64);
BPF_HASH(search_count, u64);
BPF_HASH(delete_info, u32, struct del_info_t);

//
// Counting probes for insert, delete, search
//
int trace_insert(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *value = insert_count.lookup(&key);
    if (value) {
        (*value)++;
    } else {
        u64 init_val = 1;
        insert_count.update(&key, &init_val);
    }
    return 0;
}

int trace_delete(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *value = delete_count.lookup(&key);
    if (value) {
        (*value)++;
    } else {
        u64 init_val = 1;
        delete_count.update(&key, &init_val);
    }
    return 0;
}

int trace_search(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *value = search_count.lookup(&key);
    if (value) {
        (*value)++;
    } else {
        u64 init_val = 1;
        search_count.update(&key, &init_val);
    }
    return 0;
}

//
// New probe for deletion hook: delete_node_info(pred, target, succ)
// This hook is inserted in the C code at the moment the node to delete is found.
//
int trace_delete_info(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_info_t info = {};
    info.pred = PT_REGS_PARM1(ctx);
    info.target = PT_REGS_PARM2(ctx);
    info.succ = PT_REGS_PARM3(ctx);
    delete_info.update(&tid, &info);
    return 0;
}

//
// Uretprobe for verif_optimised_delete: verify pointer consistency after deletion.
//
int verify_delete(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_info_t *info = delete_info.lookup(&tid);
    if (!info)
        return 0;
    
    // The first parameter of verif_optimised_delete is the address of the head pointer.
    u64 head_addr = PT_REGS_PARM1(ctx);
    if (info->pred == 0) {
        // Deletion at head: re-read the new head pointer.
        u64 new_head = 0;
        bpf_probe_read_user(&new_head, sizeof(new_head), (void*)head_addr);
        if (new_head != info->succ) {
            bpf_trace_printk("ERROR: Head deletion: new head 0x%lx != expected succ 0x%lx (tid %d)\\n", new_head, info->succ, tid);
        }
    } else {
        // Deletion in middle: re-read the predecessor's next pointer.
        u64 new_next = 0;
        bpf_probe_read_user(&new_next, sizeof(new_next), (void*)(info->pred + 8));
        if (new_next != info->succ) {
            bpf_trace_printk("ERROR: Mid deletion: pred->next 0x%lx != expected succ 0x%lx (tid %d)\\n", new_next, info->succ, tid);
        }
    }
    delete_info.delete(&tid);
    return 0;
}
"""

b = BPF(text=bpf_program)
binary_path = args.binary

# Attach counting uprobes for insert, delete, search for baseline or optimised variants.
try:
    b.attach_uprobe(name=binary_path, sym="baseline_insert", fn_name="trace_insert")
except Exception:
    pass
try:
    b.attach_uprobe(name=binary_path, sym="optimised_insert", fn_name="trace_insert")
except Exception:
    pass

try:
    b.attach_uprobe(name=binary_path, sym="baseline_delete", fn_name="trace_delete")
except Exception:
    pass
try:
    b.attach_uprobe(name=binary_path, sym="optimised_delete", fn_name="trace_delete")
except Exception:
    pass

try:
    b.attach_uprobe(name=binary_path, sym="baseline_search", fn_name="trace_search")
except Exception:
    pass
try:
    b.attach_uprobe(name=binary_path, sym="optimised_search", fn_name="trace_search")
except Exception:
    pass

try:
    b.attach_uprobe(name=binary_path, sym="delete_node_info", fn_name="trace_delete_info")
except Exception:
    pass

try:
    b.attach_uretprobe(name=binary_path, sym="verif_optimised_delete", fn_name="verify_delete")
except Exception:
    pass

print("Tracing linked list operations with deletion verification... Press Ctrl-C to end.")
try:
    while True:
        time.sleep(5)
        # For live tracing output, run: sudo cat /sys/kernel/debug/tracing/trace_pipe
except KeyboardInterrupt:
    pass

insert_total = sum(v.value for v in b.get_table("insert_count").values())
delete_total = sum(v.value for v in b.get_table("delete_count").values())
search_total = sum(v.value for v in b.get_table("search_count").values())

print("Insert calls: {}".format(insert_total))
print("Delete calls: {}".format(delete_total))
print("Search calls: {}".format(search_total))
