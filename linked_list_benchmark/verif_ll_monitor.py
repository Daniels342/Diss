#!/usr/bin/env python3
from bcc import BPF
import argparse, time

parser = argparse.ArgumentParser(
    description="Runtime verification of verif-optimised linked list operations"
)
parser.add_argument("binary", help="Path to the verif-optimised binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

bpf_program = r"""
#include <uapi/linux/ptrace.h>

#define PT_REGS_RAX(ctx) ((ctx)->rax)
#define PT_REGS_R8(ctx)  ((ctx)->r8)

struct entry_t { 
    u64 head_addr; 
    int inserted_val; 
    u64 old_head; 
};

struct del_hook_t { 
    u64 head_addr; 
    int target_val; 
    u64 pred; 
    u64 next_after; 
};

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

/* 
   Revised on_delete_hook: Capture state from registers.
   At the chosen offset in optimised_delete:
   - PT_REGS_R8(ctx) holds 'prev'
   - PT_REGS_RAX(ctx) holds candidate->next (the successor pointer)
*/
int on_delete_hook(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t d = {};
    d.pred = PT_REGS_R8(ctx);       // previous node pointer.
    d.next_after = PT_REGS_RAX(ctx);  // candidate->next, expected successor.
    // Optionally, you can capture the head pointer and target value from the function arguments,
    // but for this example, we focus on the register values.
    // For instance, if head pointer is in PT_REGS_PARM1(ctx) and target in PT_REGS_PARM2(ctx):
    d.head_addr = PT_REGS_PARM1(ctx);
    d.target_val = PT_REGS_PARM2(ctx);
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
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_hook", sym_off=0x35)
b.attach_uretprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_return")
print("Attached to verif_optimised_insert and verif_optimised_delete probes. Ctrl+C to exit.")
try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    print("Exiting...")
