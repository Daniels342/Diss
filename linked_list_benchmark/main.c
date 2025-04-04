#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "list_interface.h"
#include "workload.h"

int random_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

int main() {
    int num_initial = 1000000;
    int duration = 60;
    int insert_percent = 100, search_percent = 0, delete_percent = 0;

    srand(time(NULL));
    
    Node* head = NULL;
    // Pre-populate the list with random values.
    for (int i = 0; i < num_initial; i++) {
        int random_value = random_range(1, 10000);
        list_insert(&head, random_value);
    }
    
    run_workload(&head, insert_percent, search_percent, delete_percent, duration);
    
    // Free allocated memory.
#ifdef USE_OPTIMISED
    list_free_all();
#else
    list_free_all(&head);
#endif

    return 0;
}
