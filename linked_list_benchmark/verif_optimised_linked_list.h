#ifndef VERIF_OPTIMISED_LINKED_LIST_H
#define VERIF_OPTIMISED_LINKED_LIST_H

#include <stdlib.h>

#define CACHE_LINE_SIZE 64

typedef struct VerifOptimisedNode {
    int data;
    struct VerifOptimisedNode* next;
    struct VerifOptimisedNode* next_free;
} VerifOptimisedNode __attribute__((aligned(CACHE_LINE_SIZE)));

typedef struct VerifOptimisedChunk {
    VerifOptimisedNode* chunk;
    struct VerifOptimisedChunk* next;
} VerifOptimisedChunk;

void verif_optimised_insert(VerifOptimisedNode** head, int data);
int verif_optimised_delete(VerifOptimisedNode** head, int data);
void verif_optimised_show(VerifOptimisedNode* head);
VerifOptimisedNode* verif_optimised_search(VerifOptimisedNode* head, int data);
void verif_optimised_free_all();
void verif_optimised_allocate_pool_chunk();

void delete_node_info(void *pred, void *target, void *succ);

#endif