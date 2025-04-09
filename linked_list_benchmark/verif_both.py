#!/usr/bin/env python3
from bcc import BPF
import argparse, time, sys, csv

parser = argparse.ArgumentParser(
    description="Combined runtime verification with aggregated eBPF probe timing (total time only)"
)
parser.add_argument("binary", help="Path to the target binary (e.g., ./main_verif_optimised)")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/ptrace.h>

// --- Macros for register access (x86_64) ---
#ifndef PT_REGS_RAX
#define PT_REGS_RAX(ctx) ((ctx)->ax)
#endif

#ifndef PT_REGS_PARM1
#define PT_REGS_PARM1(ctx) ((ctx)->di)
#endif

#ifndef PT_REGS_PARM2
#define PT_REGS_PARM2(ctx) ((ctx)->si)
#endif

#ifndef PT_REGS_PARM3
#define PT_REGS_PARM3(ctx) ((ctx)->dx)
#endif

// --- Configuration ---
#define MAX_LEN 1000
#define TWO_SECONDS 15000000000ULL

// --- Probe indices ---
#define IDX_INSERT_ENTRY 0
#define IDX_INSERT_RETURN 1
#define IDX_DELETE_ENTRY 2
#define IDX_DELETE_HOOK 3
#define IDX_DELETE_RETURN 4

// --- Structure to aggregate probe timings (total time only) ---
struct probe_stat {
    u64 total_time;
};

// --- Map for timing aggregation ---
// Create an array with 5 elements (one per probe).
BPF_ARRAY(probe_stats, struct probe_stat, 5);

// --- Inline function to record probe time ---
static inline void record_probe(u32 idx, u64 start_ns) {
    u64 end_ns = bpf_ktime_get_ns();
    u64 delta = end_ns - start_ns;
    u32 key = idx;
    struct probe_stat *ps = probe_stats.lookup(&key);
    if (ps) {
        __sync_fetch_and_add(&ps->total_time, delta);
    }
}

// --- Macros for probe timing ---
#define BEGIN_PROBE() u64 __probe_start = bpf_ktime_get_ns();
#define END_PROBE(idx) record_probe(idx, __probe_start)

// --- Maps for length checking ---
BPF_ARRAY(expected_len, int, 1);
BPF_ARRAY(last_check, u64, 1);
BPF_HASH(ins_args, u32, u64); // For insert: store head pointer (for length check)
BPF_HASH(del_args, u32, u64); // For delete: store head pointer (for length check)

// --- Maps and structures for property checking ---
struct entry_t {
    u64 head_addr;
    int inserted_val;
    u64 old_head;
};
BPF_HASH(entryinfo, u32, struct entry_t);

struct del_hook_t {
    u64 head_addr;
    int target_val;
    u64 pred;
    u64 next_after;
};
BPF_HASH(delhook, u32, struct del_hook_t);

// --- Helper: Traverse the list and check length (throttled to once every 2 seconds) ---
static inline int check_list_length(u64 head_addr) {
    u64 now = bpf_ktime_get_ns();
    u32 key = 0;
    u64 *prev = last_check.lookup(&key);
    if (prev && (now - *prev < TWO_SECONDS)) {
        return 0; // Throttled: less than 2 seconds since last check.
    }
    int count = 0;
    u64 curr = 0;
    bpf_probe_read_user(&curr, sizeof(curr), (void *)head_addr);

#pragma unroll
    for (int i = 0; i < MAX_LEN; i++) {
        if (curr == 0)
            break; // end of list reached
        count++;
        u64 next = 0;
        // Assumes node layout: first 8 bytes is data; next 8 bytes is pointer to next node.
        bpf_probe_read_user(&next, sizeof(next), (void *)(curr + 8));
        curr = next;
    }
    int *exp = expected_len.lookup(&key);
    if (exp && count != *exp) {
        bpf_trace_printk("ERROR: Linked list length mismatch! Expected %d, Found %d\\n", *exp, count);
    }
    u64 new_ts = now;
    last_check.update(&key, &new_ts);
    return 0;
}

// ====================================================
// Insert Probes (combined property and length checking)
// ====================================================

int on_insert_entry(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    u64 head_addr = PT_REGS_PARM1(ctx);
    // For length checking:
    ins_args.update(&tid, &head_addr);
    // For property checking:
    struct entry_t val = {};
    val.head_addr = head_addr;
    val.inserted_val = PT_REGS_PARM2(ctx);
    u64 old_head = 0;
    bpf_probe_read_user(&old_head, sizeof(old_head), (void*)head_addr);
    val.old_head = old_head;
    entryinfo.update(&tid, &val);
    END_PROBE(IDX_INSERT_ENTRY);
    return 0;
}

int on_insert_return(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    // --- Property checking ---
    struct entry_t *st = entryinfo.lookup(&tid);
    if (st) {
        u64 new_head = 0;
        bpf_probe_read_user(&new_head, sizeof(new_head), (void*)st->head_addr);
        if (!new_head) {
            entryinfo.delete(&tid);
        } else {
            int new_val = 0;
            bpf_probe_read_user(&new_val, sizeof(new_val), (void*)new_head);
            if (new_val != st->inserted_val) {
                bpf_trace_printk("ERROR: Insert property: inserted value mismatch\\n");
            }
            u64 new_next = 0;
            bpf_probe_read_user(&new_next, sizeof(new_next), (void*)(new_head + 8));
            if (new_next != st->old_head) {
                bpf_trace_printk("ERROR: Insert property: next pointer mismatch\\n");
            }
        }
        entryinfo.delete(&tid);
    }

    // --- Length checking ---
    u64 *phead = ins_args.lookup(&tid);
    if (phead) {
        int key = 0;
        int *exp = expected_len.lookup(&key);
        int new_len = 0;
        if (exp) {
            new_len = *exp + 1;
        } else {
            new_len = 1;
        }
        expected_len.update(&key, &new_len);
        check_list_length(*phead);
        ins_args.delete(&tid);
    }
    END_PROBE(IDX_INSERT_RETURN);
    return 0;
}

// ====================================================
// Delete Probes (combined property and length checking)
// ====================================================

int on_delete_entry(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    // For property checking:
    struct del_hook_t d = {};
    d.head_addr = PT_REGS_PARM1(ctx);
    d.target_val = PT_REGS_PARM2(ctx);
    u64 head = 0;
    bpf_probe_read_user(&head, sizeof(head), (void*)d.head_addr);
    if (head) {
        int val = 0;
        bpf_probe_read_user(&val, sizeof(val), (void*)head);
        if (val == d.target_val) {
            d.pred = 0;
            bpf_probe_read_user(&d.next_after, sizeof(d.next_after), (void*)(head + 8));
            delhook.update(&tid, &d);
        }
    }
    // For length checking:
    del_args.update(&tid, &d.head_addr);
    END_PROBE(IDX_DELETE_ENTRY);
    return 0;
}

int on_delete_hook(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t d = {};
    d.pred = PT_REGS_PARM1(ctx);
    d.next_after = PT_REGS_PARM3(ctx);
    delhook.update(&tid, &d);
    END_PROBE(IDX_DELETE_HOOK);
    return 0;
}

int on_delete_return(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    // --- Property checking ---
    struct del_hook_t *d = delhook.lookup(&tid);
    if (d) {
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
    }

    // --- Length checking ---
    int ret = PT_REGS_RAX(ctx);
    u64 *phead = del_args.lookup(&tid);
    if (phead && ret == 1) {
        int key = 0;
        int *exp = expected_len.lookup(&key);
        int new_len = 0;
        if (exp) {
            new_len = *exp - 1;
            expected_len.update(&key, &new_len);
        }
        check_list_length(*phead);
    }
    del_args.delete(&tid);
    END_PROBE(IDX_DELETE_RETURN);
    return 0;
}
"""

# Load the combined BPF program.
b = BPF(text=bpf_text)

# Attach probes to the target binary functions.
b.attach_uprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_return")
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_entry")
b.attach_uprobe(name=args.binary, sym="deletion_instrumentation", fn_name="on_delete_hook")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_return")

print("Probes attached. Monitoring linked list properties and length (throttled to one check per 2 seconds).")
print("Press Ctrl+C to stop and print aggregated probe timings.")

try:
    time.sleep(1000) 
except KeyboardInterrupt:
    print("Exiting and printing aggregated probe timings...\n")

# --- Print aggregated timings from the probe_stats map ---
print("Aggregated probe timings:")
probe_stats = b.get_table("probe_stats")

# Define a mapping of index to human-readable names.
probe_names = {
    0: "on_insert_entry",
    1: "on_insert_return",
    2: "on_delete_entry",
    3: "on_delete_hook",
    4: "on_delete_return"
}

combined_total = 0
# Prepare a list of dictionaries to write to CSV.
rows = []

for k, v in probe_stats.items():
    idx = int(k.value)
    total_time = v.total_time
    combined_total += total_time
    name = probe_names.get(idx, "unknown")
    time_sec = total_time / 1e9
    print("Probe %-20s: total time = %d ns (%.6f seconds)" % (name, total_time, time_sec))
    rows.append({
        "probe_name": name,
        "total_time_ns": total_time,
        "total_time_seconds": time_sec
    })

print("Combined total time for all probes: %d ns (%.6f seconds)" % (combined_total, combined_total/1e9))

# --- Write the results to a CSV file ---
csv_file = "combined_total_time_both15.csv"
with open(csv_file, "w", newline="") as f:
    # Define the column names.
    fieldnames = ["combined_total_time_ns", "combined_total_time_seconds"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerow({
        "combined_total_time_ns": combined_total,
        "combined_total_time_seconds": combined_total / 1e9
    })

print("Combined total time has been written to '%s'" % csv_file)