#!/usr/bin/env python3
from bcc import BPF
import argparse, time

parser = argparse.ArgumentParser(
    description="Capture non-head deletion state in optimised_delete using register values"
)
parser.add_argument("binary", help="Path to the binary (e.g., ./main_optimised)")
args = parser.parse_args()

# Based on disassembly, we choose an offset just after candidate->next is loaded.
# Adjust this value (in hex) as needed; here we use 0x17B0.
OFFSET = 0x17B0

bpf_program = r"""
#define __TARGET_ARCH_x86
#include <uapi/linux/ptrace.h>
#include <linux/uaccess.h>
struct del_state_t {
    u64 prev;          // Previous node pointer (expected in R8)
    u64 candidate;     // Candidate node pointer (expected in RDX)
    u64 candidate_next;// Candidate->next value (expected in RAX)
};
BPF_HASH(del_state, u32, struct del_state_t);

int probe_delete_state(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_state_t state = {};
    state.prev = PT_REGS_R8(ctx);         // Capture prev
    state.candidate = PT_REGS_RDX(ctx);     // Capture candidate
    state.candidate_next = PT_REGS_RAX(ctx);  // Capture candidate->next
    del_state.update(&tid, &state);
    return 0;
}

int probe_delete_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_state_t *state = del_state.lookup(&tid);
    if (!state)
        return 0;
    u64 final_prev_next = 0;
    // Read the updated pointer from memory: prev->next.
    bpf_probe_read_user(&final_prev_next, sizeof(final_prev_next), (void*)(state->prev + 8));
    if (final_prev_next != state->candidate_next) {
        bpf_trace_printk("ERROR: post-delete: prev->next 0x%lx != candidate_next 0x%lx (tid %d)\\n",
                           final_prev_next, state->candidate_next, tid);
    }
    del_state.delete(&tid);
    return 0;
}
"""

b = BPF(text=bpf_program, debug=4)
# Attach the uprobe at the specified offset in optimised_delete.
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="probe_delete_state", sym_off=0x35)
b.attach_uretprobe(name=args.binary, sym="verif_optimised_delete", fn_name="probe_delete_return")

print("Attached uprobe at offset 0x%x and uretprobe to optimised_delete." % OFFSET)
try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    print("Exiting...")