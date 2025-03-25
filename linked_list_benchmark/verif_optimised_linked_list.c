#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "verif_optimised_linked_list.h"
#include <stdlib.h>  // for posix_memalign
#include <emmintrin.h>  // for non-temporal store (if needed)

#define NODE_CHUNK_SIZE 100000

// Global pool variables.
VerifOptimisedNode* node_pool = NULL;
VerifOptimisedChunk* pool_chunks = NULL;

// Branch prediction macros.
#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

// Empty marker function (for potential future use).
static inline void insert_exit_marker() { }

// Minimal hook for deletion instrumentation.
// This function is a no-op in C, but can be probed by eBPF.
static inline void delete_node_info(void *pred, void *target, void *succ) { }

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
    new_pool_chunk->next = pool_chunks;
    pool_chunks = new_pool_chunk;
    
    for (int i = 0; i < NODE_CHUNK_SIZE; i++) {
        new_chunk[i].next_free = node_pool;
        node_pool = &new_chunk[i];
    }
}

static inline void verif_optimised_return_node(VerifOptimisedNode* node) {
    node->next_free = node_pool;
    node_pool = node;
}

void verif_optimised_free_all() {
    VerifOptimisedChunk* current_chunk = pool_chunks;
    while (current_chunk != NULL) {
        VerifOptimisedChunk* next_chunk = current_chunk->next;
        free(current_chunk->chunk);
        free(current_chunk);
        current_chunk = next_chunk;
    }
    node_pool = NULL;
    pool_chunks = NULL;
}

void verif_optimised_insert(VerifOptimisedNode** head, int data) {
    if (node_pool == NULL) {
        verif_optimised_allocate_pool_chunk();
    }
    VerifOptimisedNode* new_node = node_pool;
    node_pool = node_pool->next_free;
    new_node->data = data;
    new_node->next = *head;
    *head = new_node;
    insert_exit_marker();
}

void verif_optimised_delete(VerifOptimisedNode** head, int data) {
    if (*head == NULL) return;
    
    if ((*head)->data == data) {
        void *pred = NULL;
        void *target = *head;
        void *succ = (*head)->next;
        delete_node_info(pred, target, succ);
        
        VerifOptimisedNode* temp = *head;
        *head = (*head)->next;
        verif_optimised_return_node(temp);
        return;
    }

    VerifOptimisedNode* curr = *head;
    while (curr->next != NULL) {
        if (curr->next->data == data) {
            void *pred = curr;
            void *target = curr->next;
            void *succ = curr->next->next;
            delete_node_info(pred, target, succ);
            curr->next = curr->next->next;
            verif_optimised_return_node((VerifOptimisedNode*)target);
            return;
        }
        curr = curr->next;
    }
}

void verif_optimised_show(VerifOptimisedNode* head) {
    VerifOptimisedNode* current = head;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

//
// verif_optimised_search: linear search for a node with the given data.
//
VerifOptimisedNode* verif_optimised_search(VerifOptimisedNode* head, int data) {
    VerifOptimisedNode* current = head;
    while (likely(current != NULL)) {
        if (current->data == data)
            return current;
        current = current->next;
    }
    return NULL;
}
