#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "list.h" // Include a copy of linux/list.h for user-space testing

struct list_item {
    int value;
    struct list_head list;
};

// Function to create a new list item
struct list_item* create_item(int value) {
    struct list_item* item = malloc(sizeof(struct list_item));
    item->value = value;
    INIT_LIST_HEAD(&item->list);
    return item;
}

// Helper function to remove and free an item
void delete_item(struct list_item* item) {
    list_del(&item->list);
    free(item);
}

// Random value generator in range
int random_in_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

