#!/usr/bin/env python3
from bcc import BPF
import argparse, time

parser = argparse.ArgumentParser(description="Runtime verification of verif-optimised linked list operations")
parser.add_argument("binary", help="Path to the verif-optimised binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#ifndef PT_REGS_R8
#define PT_REGS_R8(ctx) ((ctx)->r8)
#endif

#ifndef PT_REGS_RAX
#define PT_REGS_RAX(ctx) ((ctx)->ax)
#endif


struct entry_t { u64 head_addr; int inserted_val; u64 old_head; };
struct del_hook_t { u64 head_addr; int target_val; u64 pred; u64 next_after; };
// Combined hash: if deletion candidate is found, update this structure via the hook.
BPF_HASH(entryinfo, u32, struct entry_t);
BPF_HASH(delhook, u32, struct del_hook_t);

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
    u64 new_head = 0;
    bpf_probe_read_user(&new_head, sizeof(new_head), (void*)st->head_addr);
    if (!new_head) { entryinfo.delete(&tid); return 0; }
    int new_val = 0;
    bpf_probe_read_user(&new_val, sizeof(new_val), (void*)new_head);
    if (new_val != st->inserted_val) { entryinfo.delete(&tid); return 0; }
    u64 new_next = 0;
    bpf_probe_read_user(&new_next, sizeof(new_next), (void*)(new_head + 8));
    if (new_next != st->old_head) { entryinfo.delete(&tid); return 0; }
    entryinfo.delete(&tid);
    return 0;
}
int on_delete_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t d = {};
    d.head_addr = PT_REGS_PARM1(ctx);
    d.target_val = PT_REGS_PARM2(ctx);
    // Check if head node is the target.
    u64 head = 0;
    bpf_probe_read_user(&head, sizeof(head), (void*)d.head_addr);
    if (!head) { return 0; }
    int val = 0;
    bpf_probe_read_user(&val, sizeof(val), (void*)head);
    if (val == d.target_val) {
        d.pred = 0;
        bpf_probe_read_user(&d.next_after, sizeof(d.next_after), (void*)(head + 8));
        delhook.update(&tid, &d);
    }
    return 0;
}
// Hook for non-head deletion: invoked from C when node is found.
int on_delete_hook(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t d = {};
    // Assume that at our chosen offset:
    // R8 holds the previous node pointer (prev)
    // RAX holds candidate->next (the successor pointer)
    // Optionally, candidate pointer is in RDX (if needed, we can add it to the structure)
    d.pred = PT_REGS_R8(ctx);       // Previous node pointer.
    d.next_after = PT_REGS_RAX(ctx);  // Candidate->next, i.e. the expected new link.
    // d.target_val and d.head_addr can be set from function arguments if needed,
    // but if our goal is to verify the update of prev->next, these two registers suffice.
    delhook.update(&tid, &d);
    return 0;
}
int on_delete_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t *d = delhook.lookup(&tid);
    if (!d) return 0;
    if (d->pred == 0) {
        u64 new_head = 0;
        bpf_probe_read_user(&new_head, sizeof(new_head), (void*)d->head_addr);
        if (new_head != d->next_after)
            bpf_trace_printk("ERROR: head deletion: 0x%lx != 0x%lx (tid %d)\\n", new_head, d->next_after, tid);
    } else {
        u64 new_link = 0;
        bpf_probe_read_user(&new_link, sizeof(new_link), (void*)(d->pred + 8));
        if (new_link != d->next_after)
            bpf_trace_printk("ERROR: mid deletion: 0x%lx != 0x%lx (tid %d)\\n", new_link, d->next_after, tid);
    }
    delhook.delete(&tid);
    return 0;
}
"""
b = BPF(text=bpf_program)
b.attach_uprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_return")
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_entry")
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_hook", sym_off=0x35)
b.attach_uretprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_return")
print("Attached to verif_optimised_insert, verif_optimised_delete, and delete_node_info hook. Ctrl+C to exit.")
try:
    while(1): time.sleep(5)
except KeyboardInterrupt:
    print("Exiting...")