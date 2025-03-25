#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import argparse

def plot_with_error(x, y_mean, y_std, title, ylabel, filename):
    plt.figure(figsize=(8,6))
    positions = np.arange(len(x))
    plt.bar(positions, y_mean, yerr=y_std, align='center', alpha=0.7, capsize=10)
    plt.xticks(positions, x)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.savefig(filename)
    plt.show()

def main():
    parser = argparse.ArgumentParser(description="Graph performance data from CSV")
    parser.add_argument("--csv", type=str, default="results.csv", help="Input CSV file with performance data")
    args = parser.parse_args()
    
    # Load CSV data.
    df = pd.read_csv(args.csv)
    
    # Derived metrics.
    # Throughput: operations per second
    df["ops_per_sec"] = df["total_operations"] / df["elapsed"]
    
    # Cache misses per operation.
    df["cache_misses_per_op"] = df["cache_misses"] / df["total_operations"]
    
    # Instructions per second and cycles per second.
    df["instr_per_sec"] = df["instructions"] / df["elapsed"]
    df["cycles_per_sec"] = df["cycles"] / df["elapsed"]
    
    # Group data by Version and compute mean and standard deviation.
    grouped = df.groupby("Version").agg({
        "IPC": ["mean", "std"],
        "ops_per_sec": ["mean", "std"],
        "cache_misses_per_op": ["mean", "std"],
        "elapsed": ["mean", "std"],
        "instr_per_sec": ["mean", "std"],
        "cycles_per_sec": ["mean", "std"],
    }).reset_index()
    grouped.columns = ['Version', 'IPC_mean', 'IPC_std', 
                       'ops_mean', 'ops_std', 
                       'cache_op_mean', 'cache_op_std', 
                       'elapsed_mean', 'elapsed_std',
                       'instr_sec_mean', 'instr_sec_std',
                       'cycles_sec_mean', 'cycles_sec_std']
    
    # Plot Average IPC by Version.
    plot_with_error(grouped['Version'], grouped['IPC_mean'], grouped['IPC_std'],
                    "Average IPC by Version", "Instructions per Cycle (IPC)", "ipc_by_version.png")
    
    # Plot Throughput (Operations per Second) by Version.
    plot_with_error(grouped['Version'], grouped['ops_mean'], grouped['ops_std'],
                    "Average Throughput by Version", "Operations per Second", "throughput_by_version.png")
    
    # Plot Cache Misses per Operation by Version.
    plot_with_error(grouped['Version'], grouped['cache_op_mean'], grouped['cache_op_std'],
                    "Average Cache Misses per Operation by Version", "Cache Misses per Operation", "cache_misses_per_op.png")
    
    # Plot Instructions per Second by Version.
    plot_with_error(grouped['Version'], grouped['instr_sec_mean'], grouped['instr_sec_std'],
                    "Average Instructions per Second by Version", "Instructions per Second", "instr_sec_by_version.png")
    
    # Plot Cycles per Second by Version.
    plot_with_error(grouped['Version'], grouped['cycles_sec_mean'], grouped['cycles_sec_std'],
                    "Average Cycles per Second by Version", "Cycles per Second", "cycles_sec_by_version.png")
    
    # Optionally, print aggregated data for review.
    print(grouped)

if __name__ == "__main__":
    main()

