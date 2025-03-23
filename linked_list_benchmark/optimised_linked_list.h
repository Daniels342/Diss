#ifndef OPTIMISED_LINKED_LIST_H
#define OPTIMISED_LINKED_LIST_H

#include <stdalign.h>  // for C11 alignas, if available

#define CACHE_LINE_SIZE 64

// Option 1 (C11):
typedef struct OptimisedNode {
    int data;
    struct OptimisedNode* next;
    struct OptimisedNode* next_free;
} OptimisedNode alignas(CACHE_LINE_SIZE);

// Option 2 (GNU style):
// typedef struct OptimisedNode {
//     int data;
//     struct OptimisedNode* next;
//     struct OptimisedNode* next_free;
// } OptimisedNode __attribute__((aligned(CACHE_LINE_SIZE)));

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

#endif
