#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "workload.h"
#include "list_interface.h"

int random_in_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

void run_workload(Node** head, int insert_percentage, int search_percentage, int delete_percentage, int duration_seconds) {
    int total_operations = 0;
    int insert_count = 0, search_count = 0, delete_count = 0;
    double insert_time = 0.0;
    double search_time = 0.0;
    double delete_time = 0.0;
    
    // Compute the current length from the pre-populated list.
    int current_length = 300;

    // Use clock_gettime for high-resolution timing.
    struct timespec start_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    double elapsed_sec = 0.0;

    while (elapsed_sec < duration_seconds) {
        int operation_choice = rand() % 100;
        int random_value = random_in_range(1, 10000);
        struct timespec op_start, op_end;
        double diff = 0.0;

        if (operation_choice < insert_percentage) {
            // Only insert if the list length is below 1000.
            if (current_length < 1000) {
                clock_gettime(CLOCK_MONOTONIC, &op_start);
                list_insert(head, random_value);
                clock_gettime(CLOCK_MONOTONIC, &op_end);
                diff = (op_end.tv_sec - op_start.tv_sec) + (op_end.tv_nsec - op_start.tv_nsec) / 1e9;
                insert_time += diff;
                insert_count++;
                current_length++;  // update counter
            }
        } else if (operation_choice < insert_percentage + search_percentage) {
            clock_gettime(CLOCK_MONOTONIC, &op_start);
            list_search(*head, random_value);
            clock_gettime(CLOCK_MONOTONIC, &op_end);
            diff = (op_end.tv_sec - op_start.tv_sec) + (op_end.tv_nsec - op_start.tv_nsec) / 1e9;
            search_time += diff;
            search_count++;
        } else if (operation_choice < insert_percentage + search_percentage + delete_percentage) {
            clock_gettime(CLOCK_MONOTONIC, &op_start);
            // If deletion succeeds, update current_length.
            if (list_delete(head, random_value)) {
                current_length--;
            }
            clock_gettime(CLOCK_MONOTONIC, &op_end);
            diff = (op_end.tv_sec - op_start.tv_sec) + (op_end.tv_nsec - op_start.tv_nsec) / 1e9;
            delete_time += diff;
            delete_count++;
        }
        total_operations++;

        // Update elapsed time.
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        elapsed_sec = (current_time.tv_sec - start_time.tv_sec) +
                      (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
    }

    printf("Total Operations: %d\n", total_operations);
    printf("Insertions: %d, Time spent: %.4f seconds\n", insert_count, insert_time);
    printf("Searches: %d, Time spent: %.4f seconds\n", search_count, search_time);
    printf("Deletions: %d, Time spent: %.4f seconds\n", delete_count, delete_time);
}
