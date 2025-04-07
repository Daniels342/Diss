#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "workload.h"
#include "list_interface.h"

// Returns a random value between min and max (inclusive)
int random_in_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

// Helper function to get the current user CPU time in seconds.
double get_user_time() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage failed");
        exit(1);
    }
    return usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6;
}

void run_workload(Node** head, int insert_percentage, int search_percentage, int delete_percentage, int duration_seconds) {
    int total_operations = 0;
    int insert_count = 0, search_count = 0, delete_count = 0;
    double insert_time = 0.0, search_time = 0.0, delete_time = 0.0;
    
    // Set up cycling for insertion and deletion.
    int insert_value = 1;
    // Start deletions at a different value so they don't always target the head.
    int delete_value = 251;  
    
    // Use get_user_time for high-resolution user CPU timing.
    double start_time = get_user_time();
    double elapsed_sec = 0.0;
    double op_start, op_end, diff;
    
    while (elapsed_sec < duration_seconds) {
        // --- Insert Operation ---
        op_start = get_user_time();
        list_insert(head, insert_value);
        op_end = get_user_time();
        diff = op_end - op_start;
        insert_time += diff;
        insert_count++;
        total_operations++;
    
        // Cycle the insert_value between 1 and 500.
        insert_value++;
        if (insert_value > 500) {
            insert_value = 1;
        }
    
        // --- Delete Operation ---
        op_start = get_user_time();
        int result = list_delete(head, delete_value);
        op_end = get_user_time();
        diff = op_end - op_start;
        // Only count deletion if it succeeds.
        if (result) {
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
        op_start = get_user_time();
        list_search(*head, random_val);
        op_end = get_user_time();
        diff = op_end - op_start;
        search_time += diff;
        search_count++;
        total_operations++;
    
        // Update elapsed time.
        double current_time = get_user_time();
        elapsed_sec = current_time - start_time;
    }
    
    printf("Total Operations: %d\n", total_operations);
    printf("Insertions: %d, User CPU time spent: %.4f seconds\n", insert_count, insert_time);
    printf("Searches: %d, User CPU time spent: %.4f seconds\n", search_count, search_time);
    printf("Deletions: %d, User CPU time spent: %.4f seconds\n", delete_count, delete_time);
}
