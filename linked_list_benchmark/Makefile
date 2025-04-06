# Makefile for Linked List Benchmark

# Use gcc with aggressive optimisation and architecture-specific tuning.
CC = gcc
CFLAGS = -O3 -march=native -Wall -g

# Default target builds all three versions.
all: baseline optimised verif

# Targets for each version.
baseline: main_baseline
optimised: main_optimised
verif: main_verif_optimised

# Build the baseline binary.
main_baseline: main_baseline.o workload.o baseline_linked_list.o
	$(CC) $(CFLAGS) -o main_baseline main_baseline.o workload.o baseline_linked_list.o

# Build the optimised binary.
main_optimised: main_optimised.o workload_optimised.o optimised_linked_list.o
	$(CC) $(CFLAGS) -o main_optimised main_optimised.o workload_optimised.o optimised_linked_list.o

# Build the verifiable optimised binary.
main_verif_optimised: main_verif_optimised.o workload_verif.o verif_optimised_linked_list.o
	$(CC) $(CFLAGS) -o main_verif_optimised main_verif_optimised.o workload_verif.o verif_optimised_linked_list.o

# Compile main.o for baseline.
main_baseline.o: main.c list_interface.h workload.h
	$(CC) $(CFLAGS) -c main.c -o main_baseline.o

# Compile main.o for optimised version.
main_optimised.o: main.c list_interface.h workload.h
	$(CC) $(CFLAGS) -DUSE_OPTIMISED -c main.c -o main_optimised.o

# Compile main.o for verifiable optimised version.
main_verif_optimised.o: main.c list_interface.h workload.h
	$(CC) $(CFLAGS) -DUSE_VERIF_OPTIMISED -c main.c -o main_verif_optimised.o

# Compile workload.o (common to baseline).
workload.o: workload.c workload.h list_interface.h
	$(CC) $(CFLAGS) -c workload.c

# Compile workload.o for optimised version.
workload_optimised.o: workload.c workload.h list_interface.h
	$(CC) $(CFLAGS) -DUSE_OPTIMISED -c workload.c -o workload_optimised.o

# Compile workload.o for verifiable version.
workload_verif.o: workload.c workload.h list_interface.h
	$(CC) $(CFLAGS) -DUSE_VERIF_OPTIMISED -c workload.c -o workload_verif.o

# Compile baseline linked list.
baseline_linked_list.o: baseline_linked_list.c baseline_linked_list.h
	$(CC) $(CFLAGS) -c baseline_linked_list.c

# Compile optimised linked list.
optimised_linked_list.o: optimised_linked_list.c optimised_linked_list.h
	$(CC) $(CFLAGS) -c optimised_linked_list.c

# Compile verifiable optimised linked list.
verif_optimised_linked_list.o: verif_optimised_linked_list.c verif_optimised_linked_list.h
	$(CC) $(CFLAGS) -c verif_optimised_linked_list.c

clean:
	rm -f *.o main_baseline main_optimised main_verif_optimised main_baseline.o main_optimised.o main_verif_optimised.o workload_optimised.o workload_verif.o
