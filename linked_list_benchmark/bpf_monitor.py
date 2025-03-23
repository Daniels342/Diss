#!/usr/bin/env python3
from bcc import BPF
import argparse
import time

parser = argparse.ArgumentParser(description="BCC-based monitoring for linked list operations")
parser.add_argument("binary", help="Path to the benchmark binary (e.g., ./main_baseline or ./main_optimised)")
args = parser.parse_args()

# BPF program: Count function calls for insert, delete, and search.
bpf_program = """
#include <uapi/linux/ptrace.h>
BPF_HASH(insert_count, u64);
BPF_HASH(delete_count, u64);
BPF_HASH(search_count, u64);

int trace_insert(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *value = insert_count.lookup(&key);
    if (value) {
        (*value)++;
    } else {
        u64 init_val = 1;
        insert_count.update(&key, &init_val);
    }
    return 0;
}

int trace_delete(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *value = delete_count.lookup(&key);
    if (value) {
        (*value)++;
    } else {
        u64 init_val = 1;
        delete_count.update(&key, &init_val);
    }
    return 0;
}

int trace_search(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *value = search_count.lookup(&key);
    if (value) {
        (*value)++;
    } else {
        u64 init_val = 1;
        search_count.update(&key, &init_val);
    }
    return 0;
}
"""

b = BPF(text=bpf_program)
binary_path = args.binary

# Attach to the appropriate symbols for both baseline and optimised builds.
try:
    b.attach_uprobe(name=binary_path, sym="baseline_insert", fn_name="trace_insert")
except Exception:
    pass
try:
    b.attach_uprobe(name=binary_path, sym="optimised_insert", fn_name="trace_insert")
except Exception:
    pass

try:
    b.attach_uprobe(name=binary_path, sym="baseline_delete", fn_name="trace_delete")
except Exception:
    pass
try:
    b.attach_uprobe(name=binary_path, sym="optimised_delete", fn_name="trace_delete")
except Exception:
    pass

try:
    b.attach_uprobe(name=binary_path, sym="baseline_search", fn_name="trace_search")
except Exception:
    pass
try:
    b.attach_uprobe(name=binary_path, sym="optimised_search", fn_name="trace_search")
except Exception:
    pass

print("Tracing linked list operations... Press Ctrl-C to end.")
try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    pass

insert_total = sum(v.value for v in b.get_table("insert_count").values())
delete_total = sum(v.value for v in b.get_table("delete_count").values())
search_total = sum(v.value for v in b.get_table("search_count").values())

print("Insert calls: {}".format(insert_total))
print("Delete calls: {}".format(delete_total))
print("Search calls: {}".format(search_total))
