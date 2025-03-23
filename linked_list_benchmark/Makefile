# Makefile for Linked List Benchmark

# Use gcc with aggressive optimisation and architecture-specific tuning.
CC = gcc
CFLAGS = -O3 -march=native -Wall -g

# Uncomment and use these flags for PGO if desired:
# For the initial run to generate profiling data:
# CFLAGS_PGO_GEN = -O3 -march=native -Wall -g -fprofile-generate
# For the final build using the profiling data:
# CFLAGS_PGO_USE = -O3 -march=native -Wall -g -fprofile-use

all: baseline optimised

baseline: main_baseline
optimised: main_optimised

main_baseline: main_baseline.o workload.o baseline_linked_list.o
	$(CC) $(CFLAGS) -o main_baseline main_baseline.o workload.o baseline_linked_list.o

main_optimised: main_optimised.o workload_optimised.o optimised_linked_list.o
	$(CC) $(CFLAGS) -o main_optimised main_optimised.o workload_optimised.o optimised_linked_list.o

main_baseline.o: main.c list_interface.h workload.h
	$(CC) $(CFLAGS) -c main.c -o main_baseline.o

main_optimised.o: main.c list_interface.h workload.h
	$(CC) $(CFLAGS) -DUSE_OPTIMISED -c main.c -o main_optimised.o

workload.o: workload.c workload.h list_interface.h
	$(CC) $(CFLAGS) -c workload.c

workload_optimised.o: workload.c workload.h list_interface.h
	$(CC) $(CFLAGS) -DUSE_OPTIMISED -c workload.c -o workload_optimised.o

baseline_linked_list.o: baseline_linked_list.c baseline_linked_list.h
	$(CC) $(CFLAGS) -c baseline_linked_list.c

optimised_linked_list.o: optimised_linked_list.c optimised_linked_list.h
	$(CC) $(CFLAGS) -c optimised_linked_list.c

clean:
	rm -f *.o main_baseline main_optimised main_baseline.o main_optimised.o workload_optimised.o
