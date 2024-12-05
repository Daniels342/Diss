#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "linked_list.h"

int random_in_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

void run_workload(Node** head, int insert_percentage, int search_percentage, int delete_percentage, int duration_seconds) {
    int total_operations = 0;
    int insert_count = 0, search_count = 0, delete_count = 0;
    clock_t insert_time = 0;
    clock_t search_time = 0;
    clock_t delete_time = 0;

    time_t start_time = time(NULL);
    time_t current_time;
    
    while ((current_time = time(NULL)) - start_time < duration_seconds) {
        int operation_choice = rand() % 100;
        int random_value = random_in_range(1, 10000);
        
        if (operation_choice < insert_percentage) {
            clock_t start = clock();
            insert(head, random_value);
            clock_t end = clock();
            insert_time += end - start;
            insert_count++;
        } else if (operation_choice < insert_percentage + search_percentage) {
            clock_t start = clock();
            search(*head, random_value);
            clock_t end = clock();
            search_time += end - start;
            search_count++;
        } else if (operation_choice < insert_percentage + search_percentage + delete_percentage) {
            clock_t start = clock();
            delete(head, random_value);
            clock_t end = clock();
            delete_time += end - start;
            delete_count++;
        }
        total_operations++;
    }

    printf("Total Operations: %d\n", total_operations);
    printf("Insertions: %d, Time spent: %.4f seconds\n", insert_count, (double)insert_time / CLOCKS_PER_SEC);
    printf("Searches: %d, Time spent: %.4f seconds\n", search_count, (double)search_time / CLOCKS_PER_SEC);
    printf("Deletions: %d, Time spent: %.4f seconds\n", delete_count, (double)delete_time / CLOCKS_PER_SEC);
}
