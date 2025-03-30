#ifndef OPTIMISED_LINKED_LIST_H
#define OPTIMISED_LINKED_LIST_H

#include <stdlib.h>

#define CACHE_LINE_SIZE 64

typedef struct OptimisedNode {
    int data;
    struct OptimisedNode* next;
    struct OptimisedNode* prev;  // Added for doubly linked list support.
    struct OptimisedNode* next_free;
} OptimisedNode;

typedef struct OptimisedChunk {
    OptimisedNode* chunk;
    struct OptimisedChunk* next;
} OptimisedChunk;

void optimised_insert(OptimisedNode** head, int data);
void optimised_delete(OptimisedNode** head, int data);
void optimised_show(OptimisedNode* head);
OptimisedNode* optimised_search(OptimisedNode* head, int data);
void optimised_free_all();
void optimised_allocate_pool_chunk();

void delete_node_info(void *pred, void *target, void *succ);

#endif
