#!/usr/bin/env python3
from bcc import BPF

program = r"""
#include <uapi/linux/ptrace.h>

struct entry_t {
    u64 head_addr;
    int data_val;
    u64 old_head;
};

BPF_HASH(entryinfo, u32, struct entry_t);

int on_insert_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t val = {};

    val.head_addr = PT_REGS_PARM1(ctx);
    val.data_val  = PT_REGS_PARM2(ctx);

    u64 old_head = 0;
    bpf_probe_read_user(&old_head, 8, (void*)val.head_addr);
    val.old_head = old_head;

    entryinfo.update(&tid, &val);
    return 0;
}

int on_insert_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t *st = entryinfo.lookup(&tid);
    if (!st) return 0;

    u64 new_head_ptr = 0;
    bpf_probe_read_user(&new_head_ptr, 8, (void*)st->head_addr);
    if (!new_head_ptr) {
        bpf_trace_printk("ERROR: head is NULL\\n");
        entryinfo.delete(&tid);
        return 0;
    }

    int node_data = 0;
    bpf_probe_read_user(&node_data, 4, (void*)new_head_ptr);
    if (node_data != st->data_val) {
        bpf_trace_printk("ERROR: data mismatch. %d != %d\\n", node_data, st->data_val);
        entryinfo.delete(&tid);
        return 0;
    }

    u64 nxt = 0;
    bpf_probe_read_user(&nxt, 8, (void*)(new_head_ptr + 8));
    if (nxt != st->old_head) {
        bpf_trace_printk("ERROR: new_node->next != old head\\n");
        entryinfo.delete(&tid);
        return 0;
    }

    entryinfo.delete(&tid);
    return 0;
}
"""

b = BPF(text=program)
bin_path = "./linked_list_app"
b.attach_uprobe(name=bin_path, sym="insert", fn_name="on_insert_entry")
b.attach_uretprobe(name=bin_path, sym="insert", fn_name="on_insert_return")

print("Attached to insert. Ctrl+C to exit.")
b.trace_print()

