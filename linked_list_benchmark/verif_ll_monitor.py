#!/usr/bin/env python3
from bcc import BPF
import argparse, time

parser = argparse.ArgumentParser(description="Runtime verification of verif-optimised linked list insert operations")
parser.add_argument("binary", help="Path to the verif-optimised binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

bpf_program = r"""
#include <uapi/linux/ptrace.h>
struct entry_t { u64 head_addr; int inserted_val; u64 old_head; };
BPF_HASH(entryinfo, u32, struct entry_t);

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
    if (!new_head) {
        bpf_trace_printk("ERROR: new head is NULL (tid %d)\\n", tid);
        entryinfo.delete(&tid);
        return 0;
    }
    int new_data = 0;
    bpf_probe_read_user(&new_data, sizeof(new_data), (void*)new_head);
    if (new_data != st->inserted_val) {
        bpf_trace_printk("ERROR: data mismatch: %d != %d (tid %d)\\n", new_data, st->inserted_val, tid);
        entryinfo.delete(&tid);
        return 0;
    }
    u64 new_next = 0;
    bpf_probe_read_user(&new_next, sizeof(new_next), (void*)(new_head + 8));
    if (new_next != st->old_head) {
        bpf_trace_printk("ERROR: new node's next 0x%lx != old head 0x%lx (tid %d)\\n", new_next, st->old_head, tid);
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