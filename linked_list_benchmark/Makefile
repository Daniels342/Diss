CC = gcc
CFLAGS = -O2 -Wall -g

all: baseline optimised

baseline: main_baseline
optimised: main_optimised

main_baseline: main_baseline.o workload.o baseline_linked_list.o
	$(CC) $(CFLAGS) -o main_baseline main_baseline.o workload.o baseline_linked_list.o

main_optimised: main_optimised.o workload.o optimised_linked_list.o
	$(CC) $(CFLAGS) -o main_optimised main_optimised.o workload.o optimised_linked_list.o

main_baseline.o: main.c list_interface.h workload.h
	$(CC) $(CFLAGS) -c main.c -o main_baseline.o

main_optimised.o: main.c list_interface.h workload.h
	$(CC) $(CFLAGS) -DUSE_OPTIMISED -c main.c -o main_optimised.o

workload.o: workload.c workload.h list_interface.h
	$(CC) $(CFLAGS) -c workload.c

baseline_linked_list.o: baseline_linked_list.c baseline_linked_list.h
	$(CC) $(CFLAGS) -c baseline_linked_list.c

optimised_linked_list.o: optimised_linked_list.c optimised_linked_list.h
	$(CC) $(CFLAGS) -c optimised_linked_list.c

clean:
	rm -f *.o main_baseline main_optimised main_baseline.o main_optimised.o
