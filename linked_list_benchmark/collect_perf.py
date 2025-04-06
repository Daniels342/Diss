#!/usr/bin/env python3
import subprocess
import csv
import re
import time
import argparse

def run_perf(binary):
    # Run "perf stat" on the given binary.
    # We capture stdout (from the binary) and stderr (from perf).
    cmd = ["perf", "stat", "--inherit", "-e", "cache-misses,cycles,instructions,branch-misses", binary]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr

def parse_perf_output(stderr):
    """
    Parse the stderr output from perf stat.
    Expected lines:
        55,848      cache-misses
        30,278,943,377      cycles
        7,324,503,196      instructions              #    0.24  insn per cycle
        782,558      branch-misses
        9.570737064 seconds time elapsed
        9.478479000 seconds user
        0.092024000 seconds sys
    """
    patterns = {
        "cache_misses": r"^\s*([\d,]+)\s+cache-misses",
        "cycles": r"^\s*([\d,]+)\s+cycles",
        "instructions": r"^\s*([\d,]+)\s+instructions",
        "branch_misses": r"^\s*([\d,]+)\s+branch-misses",
        "elapsed": r"^\s*([\d\.]+)\s+seconds\s+time elapsed",
        "user": r"^\s*([\d\.]+)\s+seconds\s+user",
        "sys": r"^\s*([\d\.]+)\s+seconds\s+sys",
    }
    data = {}
    for line in stderr.splitlines():
        for key, pattern in patterns.items():
            m = re.search(pattern, line)
            if m:
                val = m.group(1).replace(",", "")
                if key in ("elapsed", "user", "sys"):
                    data[key] = float(val)
                else:
                    data[key] = int(val)
    return data

def parse_stdout(stdout):
    """
    Parse the binary’s stdout.
    Expected lines (example):
        Total Operations: 120453
        Insertions: 40688, Time spent: 0.0240 seconds
        Searches: 39763, Time spent: 4.8856 seconds
        Deletions: 40002, Time spent: 4.4994 seconds
    """
    data = {}
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Total Operations:"):
            parts = line.split(":")
            data["total_operations"] = int(parts[1].strip())
        elif line.startswith("Insertions:"):
            m = re.search(r"Insertions:\s*([\d]+),\s*Time spent:\s*([\d\.]+)", line)
            if m:
                data["insertions"] = int(m.group(1))
                data["insert_time"] = float(m.group(2))
        elif line.startswith("Searches:"):
            m = re.search(r"Searches:\s*([\d]+),\s*Time spent:\s*([\d\.]+)", line)
            if m:
                data["searches"] = int(m.group(1))
                data["search_time"] = float(m.group(2))
        elif line.startswith("Deletions:"):
            m = re.search(r"Deletions:\s*([\d]+),\s*Time spent:\s*([\d\.]+)", line)
            if m:
                data["deletions"] = int(m.group(1))
                data["delete_time"] = float(m.group(2))
    return data

def main():
    parser = argparse.ArgumentParser(description="Collect performance data for linked list benchmarks")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs per version")
    parser.add_argument("--output", type=str, default="results.csv", help="Output CSV file")
    args = parser.parse_args()

    # Define the three binary versions. Adjust paths as needed.
    versions = {
        "baseline": "./main_baseline",
        "optimised": "./main_optimised",
        "verif": "./main_verif_optimised"
    }

    fieldnames = [
        "Version", "Run",
        "total_operations", "insertions", "insert_time", 
        "searches", "search_time", "deletions", "delete_time",
        "cache_misses", "cycles", "instructions", "branch_misses",
        "elapsed", "user", "sys", "IPC"
    ]

    with open(args.output, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for version, binary in versions.items():
            for run in range(1, args.runs+1):
                print(f"Running {version}, run {run}...")
                stdout, stderr = run_perf(binary)
                perf_data = parse_perf_output(stderr)
                run_data = parse_stdout(stdout)
                ipc = ""
                if "instructions" in perf_data and "cycles" in perf_data and perf_data["cycles"] != 0:
                    ipc = perf_data["instructions"] / perf_data["cycles"]
                row = {
                    "Version": version,
                    "Run": run,
                    **run_data,
                    **perf_data,
                    "IPC": ipc
                }
                writer.writerow(row)
                # Optionally pause briefly between runs.
                time.sleep(0.5)

    print("Data collection complete. Results written to", args.output)

if __name__ == "__main__":
    main()
