#!/usr/bin/env python3
from bcc import BPF
import argparse, time

parser = argparse.ArgumentParser(description="Verify linked list length via BCC with 2-second throttle")
parser.add_argument("binary", help="Path to the binary with linked list functions (e.g., ./main_verif_optimised)")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/ptrace.h>

#ifndef PT_REGS_RAX
#define PT_REGS_RAX(ctx) ((ctx)->ax)
#endif

#ifndef PT_REGS_PARM1
#define PT_REGS_PARM1(ctx) ((ctx)->di)
#endif

#define MAX_LEN 1000
#define TWO_SECONDS 2000000000ULL

// Map to hold the expected length (one element at key 0)
BPF_ARRAY(expected_len, int, 1);
// Map to store the last time a length check was performed (in ns)
BPF_ARRAY(last_check, u64, 1);

// Temporary maps to store head pointer arguments, keyed by thread ID.
BPF_HASH(ins_args, u32, u64);
BPF_HASH(del_args, u32, u64);

// Helper function: traverse the linked list starting from head_addr and count nodes (bounded by MAX_LEN).
// Performs a length check only if at least 2 seconds have passed since the last check.
static inline int check_list_length(u64 head_addr) {
    // Throttle the check: allow a check only every 2 seconds.
    u64 now = bpf_ktime_get_ns();
    u32 key = 0;
    u64 *prev = last_check.lookup(&key);
    if (prev && (now - *prev < TWO_SECONDS)) {
        return 0; // Skip check if less than 2 seconds have passed.
    }
    // Update the timestamp.
    u64 new_ts = now;
    last_check.update(&key, &new_ts);

    int count = 0;
    u64 curr = 0;
    // Read the head pointer from user-space.
    bpf_probe_read_user(&curr, sizeof(curr), (void *)head_addr);

    // Traverse the list with a bounded loop.
#pragma unroll
    for (int i = 0; i < MAX_LEN; i++) {
        if (curr == 0)
            break;  // end of list reached
        count++;
        u64 next = 0;
        // Assuming node layout: [0-7 bytes]: data, [8-15 bytes]: pointer to next node.
        bpf_probe_read_user(&next, sizeof(next), (void *)(curr + 8));
        curr = next;
    }

    // Retrieve the expected length from the map.
    int *exp = expected_len.lookup(&key);
    if (exp && count != *exp) {
        bpf_trace_printk("ERROR: Linked list length mismatch! Expected %d, Found %d\\n", *exp, count);
    }
    return 0;
}

// Uprobe: capture the head pointer argument for insert.
int on_insert_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 head_addr = PT_REGS_PARM1(ctx);
    ins_args.update(&tid, &head_addr);
    return 0;
}

// Uretprobe for insert: increment expected length and check list length.
int on_insert_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 *phead = ins_args.lookup(&tid);
    if (!phead)
        return 0;

    int key = 0;
    int *exp = expected_len.lookup(&key);
    int new_len = 0;
    if (exp) {
        new_len = *exp + 1;
    } else {
        new_len = 1;
    }
    expected_len.update(&key, &new_len);

    // Perform length check (if allowed by throttling)
    check_list_length(*phead);
    ins_args.delete(&tid);
    return 0;
}

// Uprobe: capture the head pointer argument for delete.
int on_delete_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 head_addr = PT_REGS_PARM1(ctx);
    del_args.update(&tid, &head_addr);
    return 0;
}

// Uretprobe for delete: if delete was successful (returns 1), decrement expected length and check the list length.
int on_delete_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    int ret = PT_REGS_RAX(ctx);
    u64 *phead = del_args.lookup(&tid);
    if (!phead)
        return 0;
    if (ret == 1) {
        int key = 0;
        int *exp = expected_len.lookup(&key);
        int new_len = 0;
        if (exp) {
            new_len = *exp - 1;
            expected_len.update(&key, &new_len);
        }
        // Perform length check (if allowed by throttling)
        check_list_length(*phead);
    }
    del_args.delete(&tid);
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)

# Attach probes to the target binary functions.
b.attach_uprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_return")
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_return")

print("Probes attached. Monitoring linked list length (throttled to one check per 2 seconds). Ctrl+C to exit.")

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%s" % (msg))
    except KeyboardInterrupt:
        print("Exiting...")
        exit()
