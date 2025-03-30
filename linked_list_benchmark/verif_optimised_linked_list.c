#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "verif_optimised_linked_list.h"  // Updated header file name
#include <emmintrin.h>

#define NODE_CHUNK_SIZE 100000

/* Global pool variables for verif optimised version */
VerifOptimisedNode* verif_optimised_node_pool = NULL;
VerifOptimisedChunk* verif_optimised_pool_chunks = NULL;

/* Branch prediction macros */
#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

void verif_optimised_allocate_pool_chunk() {
    VerifOptimisedNode* new_chunk = NULL;
    if (posix_memalign((void**)&new_chunk, CACHE_LINE_SIZE, NODE_CHUNK_SIZE * sizeof(VerifOptimisedNode)) != 0) {
        printf("Aligned memory allocation failed\n");
        exit(1);
    }
    VerifOptimisedChunk* new_pool_chunk = (VerifOptimisedChunk*)malloc(sizeof(VerifOptimisedChunk));
    if (new_pool_chunk == NULL) {
        printf("Memory allocation failed for chunk metadata\n");
        free(new_chunk);
        exit(1);
    }
    new_pool_chunk->chunk = new_chunk;
    new_pool_chunk->next = verif_optimised_pool_chunks;
    verif_optimised_pool_chunks = new_pool_chunk;
    for (int i = 0; i < NODE_CHUNK_SIZE; i++) {
        new_chunk[i].next_free = verif_optimised_node_pool;
        verif_optimised_node_pool = &new_chunk[i];
    }
}

static inline void verif_optimised_return_node(VerifOptimisedNode* node) {
    node->next_free = verif_optimised_node_pool;
    verif_optimised_node_pool = node;
}

void verif_optimised_free_all() {
    VerifOptimisedChunk* current_chunk = verif_optimised_pool_chunks;
    while (current_chunk != NULL) {
        VerifOptimisedChunk* next_chunk = current_chunk->next;
        free(current_chunk->chunk);
        free(current_chunk);
        current_chunk = next_chunk;
    }
    verif_optimised_node_pool = NULL;
    verif_optimised_pool_chunks = NULL;
}

void verif_optimised_insert(VerifOptimisedNode** head, int data) {
    if (verif_optimised_node_pool == NULL) {
        verif_optimised_allocate_pool_chunk();
    }
    VerifOptimisedNode* new_node = verif_optimised_node_pool;
    verif_optimised_node_pool = verif_optimised_node_pool->next_free;
    new_node->data = data;
    new_node->next = *head;
    new_node->prev = NULL;
    if (*head != NULL) {
        (*head)->prev = new_node;
    }
    *head = new_node;
}

void verif_optimised_delete(VerifOptimisedNode** head, int data) {
    if (*head == NULL)
        return;

    if ((*head)->data == data) {
        VerifOptimisedNode* temp = *head;
        _mm_stream_si64((long long*)head, (long long)(*head)->next);
        *head = (*head)->next;
        if (*head != NULL)
            (*head)->prev = NULL;
        verif_optimised_return_node(temp);
        return;
    }
    
    VerifOptimisedNode* current = *head;
    // Traverse the list, using prefetching and unrolling where possible.
    while (current) {
        if (current->data == data) {
            // Remove the node from the list.
            if (current->prev)
                current->prev->next = current->next;
            if (current->next)
                current->next->prev = current->prev;
            verif_optimised_return_node(current);
            return;
        }
        // Prefetch the next nodes to improve cache behavior.
        if (current->next) {
            __builtin_prefetch(current->next, 0, 3);
            if (current->next->next) {
                __builtin_prefetch(current->next->next, 0, 3);
            }
        }
        current = current->next;
    }
}

void verif_optimised_show(VerifOptimisedNode* head) {
    VerifOptimisedNode* current = head;
    while (current != NULL) {
        printf("%d <-> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

VerifOptimisedNode* verif_optimised_search(VerifOptimisedNode* head, int data) {
    VerifOptimisedNode* current = head;
    while (current && current->next) {
        __builtin_prefetch(current->next, 0, 3);
        if (current->next->next) {
            __builtin_prefetch(current->next->next, 0, 3);
        }
        if (likely(current->data == data)) {
            return current;
        }
        if (likely(current->next->data == data)) {
            return current->next;
        }
        current = current->next->next;
    }
    if (current && current->data == data) {
        return current;
    }
    return NULL;
}
