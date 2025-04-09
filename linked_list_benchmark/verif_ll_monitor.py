#!/usr/bin/env python3
from bcc import BPF
import argparse, time, csv

parser = argparse.ArgumentParser(
    description="Runtime verification of verif-optimised linked list operations with function timing"
)
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

// --- Aggregated probe timing definitions ---
struct probe_stat {
    u64 total_time;
};
// Create an array with 5 elements (one per probe function).
BPF_ARRAY(probe_stats, struct probe_stat, 5);
static inline void record_probe(u32 idx, u64 start_ns) {
    u64 end_ns = bpf_ktime_get_ns();
    u64 delta = end_ns - start_ns;
    u32 key = idx;
    struct probe_stat *ps = probe_stats.lookup(&key);
    if (ps) {
        __sync_fetch_and_add(&ps->total_time, delta);
    }
}
#define BEGIN_PROBE() u64 __probe_start = bpf_ktime_get_ns();
#define END_PROBE(idx) record_probe(idx, __probe_start)

// --- Structures and maps for the original functionality ---
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

// --- Probe functions with added timing instrumentation ---
// Probe indices:
//   0: on_insert_entry
//   1: on_insert_return
//   2: on_delete_entry
//   3: on_delete_hook
//   4: on_delete_return

int on_insert_entry(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t val = {};
    val.head_addr = PT_REGS_PARM1(ctx);
    val.inserted_val = PT_REGS_PARM2(ctx);
    u64 old_head = 0;
    bpf_probe_read_user(&old_head, sizeof(old_head), (void*)val.head_addr);
    val.old_head = old_head;
    entryinfo.update(&tid, &val);
    END_PROBE(0);
    return 0;
}

int on_insert_return(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t *st = entryinfo.lookup(&tid);
    if (!st) { END_PROBE(1); return 0; }
    u64 new_head = 0;
    bpf_probe_read_user(&new_head, sizeof(new_head), (void*)st->head_addr);
    if (!new_head) { entryinfo.delete(&tid); END_PROBE(1); return 0; }
    int new_val = 0;
    bpf_probe_read_user(&new_val, sizeof(new_val), (void*)new_head);
    if (new_val != st->inserted_val) { entryinfo.delete(&tid); END_PROBE(1); return 0; }
    u64 new_next = 0;
    bpf_probe_read_user(&new_next, sizeof(new_next), (void*)(new_head + 8));
    if (new_next != st->old_head) { entryinfo.delete(&tid); END_PROBE(1); return 0; }
    entryinfo.delete(&tid);
    END_PROBE(1);
    return 0;
}

int on_delete_entry(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t d = {};
    d.head_addr = PT_REGS_PARM1(ctx);
    d.target_val = PT_REGS_PARM2(ctx);
    u64 head = 0;
    bpf_probe_read_user(&head, sizeof(head), (void*)d.head_addr);
    if (!head) { END_PROBE(2); return 0; }
    int val = 0;
    bpf_probe_read_user(&val, sizeof(val), (void*)head);
    if (val == d.target_val) {
        d.pred = 0;
        bpf_probe_read_user(&d.next_after, sizeof(d.next_after), (void*)(head + 8));
        delhook.update(&tid, &d);
    }
    END_PROBE(2);
    return 0;
}

int on_delete_hook(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t d = {};
    d.pred = PT_REGS_PARM1(ctx);
    d.next_after = PT_REGS_PARM3(ctx);
    delhook.update(&tid, &d);
    END_PROBE(3);
    return 0;
}

int on_delete_return(struct pt_regs *ctx) {
    BEGIN_PROBE();
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t *d = delhook.lookup(&tid);
    if (!d) { END_PROBE(4); return 0; }
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
    END_PROBE(4);
    return 0;
}
"""

b = BPF(text=bpf_program)
b.attach_uprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_entry")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_insert", fn_name="on_insert_return")
b.attach_uprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_entry")
b.attach_uprobe(name=args.binary, sym="deletion_instrumentation", fn_name="on_delete_hook")
b.attach_uretprobe(name=args.binary, sym="verif_optimised_delete", fn_name="on_delete_return")

print("Attached to verif_optimised_insert, verif_optimised_delete, and deletion_instrumentation hook. Ctrl+C to exit.")
try:
    time.sleep(1000)
except KeyboardInterrupt:
    print("Exiting...")

# --- Retrieve and aggregate probe timings from the BPF map ---
print("Aggregated probe timings:")
probe_stats = b.get_table("probe_stats")
combined_total = 0
for k, v in probe_stats.items():
    combined_total += v.total_time
print("Combined total time for all probes: %d ns (%.6f seconds)" % (combined_total, combined_total/1e9))

# --- Write the combined total time to a CSV file ---
csv_file = "combined_total_time_props_onlyInsert.csv"
with open(csv_file, "w", newline="") as f:
    fieldnames = ["combined_total_time_ns", "combined_total_time_seconds"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerow({
        "combined_total_time_ns": combined_total,
        "combined_total_time_seconds": combined_total/1e9
    })
print("Combined total time has been written to '%s'" % csv_file)
