#!/usr/bin/env python3
from bcc import BPF
import argparse, time, subprocess

parser = argparse.ArgumentParser(
    description="Hook into optimised_delete at a specific offset to capture deletion state"
)
parser.add_argument("binary", help="Path to the binary (e.g., ./main_optimised)")
args = parser.parse_args()

# Set the relative offset from the start of optimised_delete.
# Based on your disassembly, if the function starts at 0x1770 and candidate->next is loaded at 0x17ad,
# then a relative offset of about 0x3D should capture the state just after that load.
RELATIVE_OFFSET = 0x3D

def get_symbol_base(binary, symbol):
    try:
        cmd = "nm -D {} | grep ' T {}$'".format(binary, symbol)
        out = subprocess.check_output(cmd, shell=True).decode('utf-8')
        base_str = out.split()[0]
        return int(base_str, 16)
    except subprocess.CalledProcessError:
        print("Error: Could not find symbol", symbol)
        exit(1)

base_addr = get_symbol_base(args.binary, "optimised_delete")
target_addr = base_addr + RELATIVE_OFFSET
print("Base address of optimised_delete: 0x%x" % base_addr)
print("Attaching probe at absolute address: 0x%x" % target_addr)

bpf_program = r"""
#include <uapi/linux/ptrace.h>
struct del_state_t {
    u64 prev;           // Previous node pointer (expected in R8)
    u64 candidate;      // Candidate node pointer (expected in RDX)
    u64 candidate_next; // Candidate->next (expected in RAX)
};
BPF_HASH(del_state, u32, struct del_state_t);

int probe_delete_state(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_state_t state = {};
    state.prev = PT_REGS_R8(ctx);
    state.candidate = PT_REGS_RDX(ctx);
    state.candidate_next = PT_REGS_RAX(ctx);
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
# Attach a uprobe at the absolute address computed above.
b.attach_uprobe(name=args.binary, addr=target_addr, fn_name="probe_delete_state")
# Attach a uretprobe to the entire function for post-deletion verification.
b.attach_uretprobe(name=args.binary, sym="optimised_delete", fn_name="probe_delete_return")

print("Attached probe at offset 0x%x (absolute 0x%x) in optimised_delete." % (RELATIVE_OFFSET, target_addr))
try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    print("Exiting...")
