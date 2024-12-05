#include <stdio.h>
#include <stdlib.h> 
#include <time.h>  
#include "list.h"        // Linux-style linked list macros (include a user-space copy of linux/list.h)
#include "workload_linux.h"    // Your workload generator with Linux list implementation

int random_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

// Initialize list and run workload
int main() {
    struct list_head my_list;    // Define the list head for Linux-style list
    INIT_LIST_HEAD(&my_list);    // Initialize the list head

    // Seed random number generator
    srand(time(NULL));

    // Insert 1,000,000 random values into the list
    for (int i = 0; i < 1000000; i++) {
        int random_value = random_range(1, 10000);
        
        // Create a new list item and add it to the list
        struct list_item* new_item = create_item(random_value);
        list_add(&new_item->list, &my_list);  // Add to the beginning of the list
    }

    // Run workload with the specified percentages for insert, search, delete, and duration
    run_workload(&my_list, 34, 33, 33, 10);

    // Free all items after workload is complete
    struct list_item *entry, *temp;
    list_for_each_entry_safe(entry, temp, &my_list, list) {
        delete_item(entry);
    }

    return 0;
}

