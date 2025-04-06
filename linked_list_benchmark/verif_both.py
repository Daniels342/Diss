#!/usr/bin/env python3
from bcc import BPF
import argparse, time

parser = argparse.ArgumentParser(
    description="Combined runtime verification of linked list properties and length (throttled)"
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
#define TWO_SECONDS 2000000000ULL

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
    u64 new_ts = now;
    last_check.update(&key, &new_ts);

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
    return 0;
}

// ====================================================
// Insert Probes (combined property and length checking)
// ====================================================

// Uprobe for insert: record both the head pointer (for length check)
// and property details (head pointer, inserted value, and old head value).
int on_insert_entry(struct pt_regs *ctx) {
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
    return 0;
}

// Uretprobe for insert: perform property verification and update expected length.
int on_insert_return(struct pt_regs *ctx) {
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
    return 0;
}

// ====================================================
// Delete Probes (combined property and length checking)
// ====================================================

// Uprobe for delete: record the head pointer for length check and, for property checking,
// capture deletion parameters.
int on_delete_entry(struct pt_regs *ctx) {
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
    return 0;
}

// Uprobe for deletion instrumentation (dummy hook): update deletion properties.
int on_delete_hook(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct del_hook_t d = {};
    d.pred = PT_REGS_PARM1(ctx);
    d.next_after = PT_REGS_PARM3(ctx);
    delhook.update(&tid, &d);
    return 0;
}

// Uretprobe for delete: perform property checks and update expected length if delete was successful.
int on_delete_return(struct pt_regs *ctx) {
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

print("Probes attached. Monitoring linked list properties and length (throttled to one check per 2 seconds). Ctrl+C to exit.")

# Read and print trace messages.
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%s" % (msg))
    except KeyboardInterrupt:
        print("Exiting...")
        exit()
