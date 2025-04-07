#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "workload.h"
#include "list_interface.h"

// Returns a random value between min and max (inclusive)
int random_in_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

void run_workload(Node** head, int insert_percentage, int search_percentage, int delete_percentage, int duration_seconds) {
    int total_operations = 0;
    int insert_count = 0, search_count = 0, delete_count = 0;
    double insert_time = 0.0, search_time = 0.0, delete_time = 0.0;
    
    // Set up cycling for insertion and deletion.
    int insert_value = 1;
    // Start deletions at a different value so they don't always target the head.
    int delete_value = 251;  
    
    // Get the starting time using time(NULL)
    time_t start_time = time(NULL);
    time_t current_time = start_time;

    struct timespec op_start, op_end;
    double diff = 0.0;

    // Loop until the elapsed time (in seconds) is at least duration_seconds.
    while ((current_time - start_time) < duration_seconds) {
        // --- Insert Operation ---
        clock_gettime(CLOCK_MONOTONIC, &op_start);
        list_insert(head, insert_value);
        clock_gettime(CLOCK_MONOTONIC, &op_end);
        diff = (op_end.tv_sec - op_start.tv_sec) + (op_end.tv_nsec - op_start.tv_nsec) / 1e9;
        insert_time += diff;
        insert_count++;
        total_operations++;

        // Cycle the insert_value between 1 and 500.
        insert_value++;
        if (insert_value > 500) {
            insert_value = 1;
        }

        // --- Delete Operation ---
        clock_gettime(CLOCK_MONOTONIC, &op_start);
        int result = list_delete(head, delete_value);
        clock_gettime(CLOCK_MONOTONIC, &op_end);
        diff = (op_end.tv_sec - op_start.tv_sec) + (op_end.tv_nsec - op_start.tv_nsec) / 1e9;
        if (result) { // Only count deletion if it succeeds.
            delete_time += diff;
            delete_count++;
        }
        total_operations++;

        // Cycle the delete_value between 1 and 500.
        delete_value++;
        if (delete_value > 500) {
            delete_value = 1;
        }

        // --- Random Search Operation ---
        int random_val = random_in_range(1, 10000);
        clock_gettime(CLOCK_MONOTONIC, &op_start);
        list_search(*head, random_val);
        clock_gettime(CLOCK_MONOTONIC, &op_end);
        diff = (op_end.tv_sec - op_start.tv_sec) + (op_end.tv_nsec - op_start.tv_nsec) / 1e9;
        search_time += diff;
        search_count++;
        total_operations++;

        // Update current time using time(NULL)
        current_time = time(NULL);
    }

    printf("Total Operations: %d\n", total_operations);
    printf("Insertions: %d, Time spent: %.4f seconds\n", insert_count, insert_time);
    printf("Searches: %d, Time spent: %.4f seconds\n", search_count, search_time);
    printf("Deletions: %d, Time spent: %.4f seconds\n", delete_count, delete_time);
}
