#!/usr/bin/env python3
from bcc import BPF
import argparse, time, csv

parser = argparse.ArgumentParser(description="Verify linked list length via BCC with 2-second throttle and probe timing")
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

#define MAX_LEN 50000
#define TWO_SECONDS 1000000000ULL

// --- Timing instrumentation ---
// Structure to aggregate probe timings.
struct probe_stat {
    u64 total_time;
};
// Create an array with 4 elements (one per probe below).
BPF_ARRAY(probe_stats, struct probe_stat, 4);

// Helper: record elapsed time from a given starting timestamp.
static inline void record_probe(u32 idx, u64 start_ns) {
    u64 now = bpf_ktime_get_ns();
    u64 delta = now - start_ns;
    u32 key = idx;
    struct probe_stat *ps = probe_stats.lookup(&key);
    if (ps) {
        __sync_fetch_and_add(&ps->total_time, delta);
    }
}
#define BEGIN_PROBE() u64 __probe_start = bpf_ktime_get_ns();
#define END_PROBE(idx) record_probe(idx, __probe_start);

// --- End timing instrumentation ---

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
    bpf_trace_printk("List length check: expected %d, found %d\\n", exp ? *exp : -1, count);
    if (exp && count != *exp) {
        bpf_trace_printk("ERROR: Linked list length mismatch! Expected %d, Found %d\\n", *exp, count);
    }
    u64 new_ts = now;
    last_check.update(&key, &new_ts);
    return 0;
}

// Uprobe: capture the head pointer argument for insert.
int on_insert_entry(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    u64 head_addr = PT_REGS_PARM1(ctx);
    ins_args.update(&tid, &head_addr);
    END_PROBE(0);
    return 0;
}

// Uretprobe for insert: increment expected length and check list length.
int on_insert_return(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    u64 *phead = ins_args.lookup(&tid);
    if (!phead) {
        END_PROBE(1);
        return 0;
    }
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
    END_PROBE(1);
    return 0;
}

// Uprobe: capture the head pointer argument for delete.
int on_delete_entry(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    u64 head_addr = PT_REGS_PARM1(ctx);
    del_args.update(&tid, &head_addr);
    END_PROBE(2);
    return 0;
}

// Uretprobe for delete: if delete was successful (returns 1), decrement expected length and check the list length.
int on_delete_return(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    int ret = PT_REGS_RAX(ctx);
    u64 *phead = del_args.lookup(&tid);
    if (!phead) {
        END_PROBE(3);
        return 0;
    }
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
    END_PROBE(3);
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

# Process trace output; run until interrupted.
try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%s" % (msg))
except KeyboardInterrupt:
    print("Exiting...")

# --- After exit, retrieve and aggregate probe timings ---
print("Aggregated probe timings:")
probe_stats = b.get_table("probe_stats")
combined_total = 0
for k, v in probe_stats.items():
    print("Probe %d: %d ns" % (k.value, v.total_time))
    combined_total += v.total_time;
print("Combined total time for all probes: %d ns (%.6f seconds)" % (combined_total, combined_total/1e9))

# --- Write the combined total time to a CSV file ---
csv_file = "combined_total_time_length1.csv"
with open(csv_file, "w", newline="") as f:
    fieldnames = ["combined_total_time_ns", "combined_total_time_seconds"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerow({
        "combined_total_time_ns": combined_total,
        "combined_total_time_seconds": combined_total/1e9
    })
print("Combined total time has been written to '%s'" % csv_file)
