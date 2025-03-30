#ifndef OPTIMISED_LINKED_LIST_H
#define OPTIMISED_LINKED_LIST_H

#include <stdlib.h>

#define CACHE_LINE_SIZE 64

#define CACHE_LINE_SIZE 64

typedef struct OptimisedNode {
    int data;                           // 4 bytes
    struct OptimisedNode* next;         // 8 bytes
    struct OptimisedNode* prev;         // 8 bytes
    struct OptimisedNode* next_free;    // 8 bytes
    // Total without padding: 4 + 8 + 8 + 8 = 28 bytes.
    // Padding needed: 64 - 28 = 36 bytes.
    char padding[64 - (sizeof(int) + 3 * sizeof(void*))];
} OptimisedNode __attribute__((aligned(CACHE_LINE_SIZE)));

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
