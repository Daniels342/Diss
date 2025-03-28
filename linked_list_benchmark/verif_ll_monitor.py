#!/usr/bin/env python3
from bcc import BPF
import argparse, time, subprocess

parser = argparse.ArgumentParser(
    description="Hook into optimised_delete at a specific offset to capture deletion state"
)
parser.add_argument("binary", help="Path to the binary (e.g., ./main_optimised)")
args = parser.parse_args()

# Set the offset relative to the start of optimised_delete.
# For example, if the disassembly of optimised_delete shows that at 0x1780 the function starts
# and candidate->next is loaded at 0x17ad, then you might choose an offset of 0x17B0.
# Adjust OFFSET accordingly.
OFFSET = 0x17B0

# Try to get the base address of optimised_delete from the binary.
# This requires that the binary is not stripped and has symbols.
try:
    base_addr = BPF.get_user_function_addr(args.binary, "optimised_delete")
except Exception as e:
    print("Error obtaining base address for optimised_delete:", e)
    exit(1)

target_addr = base_addr + (OFFSET - 0x1780)  # Adjust offset relative to function start.
print("Base address of optimised_delete: 0x%x" % base_addr)
print("Attaching probe at absolute address: 0x%x" % target_addr)

bpf_program = r"""
#include <uapi/linux/ptrace.h>
struct del_state_t {
    u64 prev;           // Previous node pointer (from R8)
    u64 candidate;      // Candidate node pointer (from RDX)
    u64 candidate_next; // Candidate->next (from RAX)
};
BPF_HASH(del_state, u32, struct del_state_t);

int probe_delete_state(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_state_t state = {};
    state.prev = PT_REGS_R8(ctx);         // Expect prev in R8.
    state.candidate = PT_REGS_RDX(ctx);     // Candidate in RDX.
    state.candidate_next = PT_REGS_RAX(ctx);  // Candidate->next in RAX.
    del_state.update(&tid, &state);
    return 0;
}

int probe_delete_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_state_t *state = del_state.lookup(&tid);
    if (!state)
        return 0;
    u64 final_prev_next = 0;
    bpf_probe_read_user(&final_prev_next, sizeof(final_prev_next), (void*)(state->prev + 8));
    if (final_prev_next != state->candidate_next) {
        bpf_trace_printk("ERROR: deletion: prev->next 0x%lx != candidate_next 0x%lx (tid %d)\\n",
                           final_prev_next, state->candidate_next, tid);
    }
    del_state.delete(&tid);
    return 0;
}
"""

b = BPF(text=bpf_program)
# Attach uprobe at the computed absolute address.
b.attach_uprobe(name=args.binary, addr=target_addr, fn_name="probe_delete_state")
b.attach_uretprobe(name=args.binary, sym="optimised_delete", fn_name="probe_delete_return")

print("Attached probe at 0x%x (offset adjusted) in optimised_delete." % target_addr)
try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    print("Exiting...")
