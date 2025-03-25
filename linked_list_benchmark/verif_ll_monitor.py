#!/usr/bin/env python3
from bcc import BPF
import argparse, time

parser = argparse.ArgumentParser(description="Runtime verification of verif-optimised linked list operations")
parser.add_argument("binary", help="Path to the verif-optimised binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

bpf_program = r"""
#include <uapi/linux/ptrace.h>
struct entry_t { u64 head_addr; int inserted_val; u64 old_head; };
struct del_entry_t { u64 head_addr; int target_val; u64 found; u64 pred; u64 node_to_delete; u64 next_after; };
struct hook_del_t { u64 pred; u64 target; u64 succ; };
BPF_HASH(entryinfo, u32, struct entry_t);
BPF_HASH(delinfo, u32, struct del_entry_t);
BPF_HASH(hookinfo, u32, struct hook_del_t);

int on_insert_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t val = {};
    val.head_addr = PT_REGS_PARM1(ctx);
    val.inserted_val = PT_REGS_PARM2(ctx);
    u64 old_head = 0;
    bpf_probe_read_user(&old_head, sizeof(old_head), (void*)val.head_addr);
    val.old_head = old_head;
    entryinfo.update(&tid, &val);
    return 0;
}
int on_insert_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t *st = entryinfo.lookup(&tid);
    if (!st) return 0;
    u64 new_head_ptr = 0;
    bpf_probe_read_user(&new_head_ptr, sizeof(new_head_ptr), (void*)st->head_addr);
    if (!new_head_ptr) {
        bpf_trace_printk("ERROR: verif_optimised_insert: new head is NULL (tid %d)\\n", tid);
        entryinfo.delete(&tid);
        return 0;
    }
    int new_node_data = 0;
    bpf_probe_read_user(&new_node_data, sizeof(new_node_data), (void*)new_head_ptr);
    if (new_node_data != st->inserted_val) {
        bpf_trace_printk("ERROR: verif_optimised_insert: data mismatch: %d != %d (tid %d)\\n",
                          new_node_data, st->inserted_val, tid);
        entryinfo.delete(&tid);
        return 0;
    }
    u64 new_node_next = 0;
    bpf_probe_read_user(&new_node_next, sizeof(new_node_next), (void*)(new_head_ptr + 8));
    if (new_node_next != st->old_head) {
        bpf_trace_printk("ERROR: verif_optimised_insert: new node's next 0x%lx != old head 0x%lx (tid %d)\\n",
                          new_node_next, st->old_head, tid);
        entryinfo.delete(&tid);
        return 0;
    }
    entryinfo.delete(&tid);
    return 0;
}
int on_delete_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_entry_t dval = {};
    dval.head_addr = PT_REGS_PARM1(ctx);
    dval.target_val = PT_REGS_PARM2(ctx);
    dval.found = 0;
    u64 head_ptr = 0;
    bpf_probe_read_user(&head_ptr, sizeof(head_ptr), (void*)dval.head_addr);
    if (!head_ptr) { delinfo.update(&tid, &dval); return 0; }
    int node_val = 0;
    bpf_probe_read_user(&node_val, sizeof(node_val), (void*)head_ptr);
    if (node_val == dval.target_val) {
        dval.found = 1;
        dval.pred = 0;
        dval.node_to_delete = head_ptr;
        bpf_probe_read_user(&dval.next_after, sizeof(dval.next_after), (void*)(head_ptr + 8));
    }
    delinfo.update(&tid, &dval);
    return 0;
}
int on_delete_hook(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct hook_del_t hinfo = {};
    hinfo.pred = PT_REGS_PARM1(ctx);
    hinfo.target = PT_REGS_PARM2(ctx);
    hinfo.succ = PT_REGS_PARM3(ctx);
    hookinfo.update(&tid, &hinfo);
    return 0;
}
int on_delete_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct hook_del_t *hinfo = hookinfo.lookup(&tid);
    if (!hinfo) return 0;
    if (hinfo->pred == 0) {
        struct del_entry_t *dval = delinfo.lookup(&tid);
        if (!dval) { hookinfo.delete(&tid); return 0; }
        u64 new_head = 0;
        bpf_probe_read_user(&new_head, sizeof(new_head), (void*)dval->head_addr);
        if (new_head != hinfo->succ)
            bpf_trace_printk("ERROR: delete hook: head deletion: 0x%lx != 0x%lx (tid %d)\\n", new_head, hinfo->succ, tid);
    } else {
        u64 new_link = 0;
        bpf_probe_read_user(&new_link, sizeof(new_link), (void*)(hinfo->pred + 8));
        if (new_link != hinfo->succ)
            bpf_trace_printk("ERROR: delete hook: mid deletion: 0x%lx != 0x%lx (tid %d)\\n", new_link, hinfo->succ, tid);
    }
    hookinfo.delete(&tid);
    return 0;
}
"""
b = BPF(text=bpf_program)
b.attach_uprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_return")
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_return")
b.attach_uprobe(name=args.binary, sym="delete_node_info", fn_name="on_delete_hook")
print("Attached to verif_optimised_insert, verif_optimised_delete, and delete_node_info hook. Ctrl+C to exit.")
try:
    while(1): time.sleep(5)
except KeyboardInterrupt:
    print("Exiting...")
