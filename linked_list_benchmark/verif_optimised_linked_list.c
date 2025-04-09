#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "verif_optimised_linked_list.h"
#include <emmintrin.h>

#define NODE_CHUNK_SIZE 100000

/* Global pool variables for verif_optimised version */
VerifOptimisedNode* verif_node_pool = NULL;
VerifOptimisedChunk* verif_pool_chunks = NULL;

/* Branch prediction macros */
#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

/* Empty marker function */
static inline void insert_exit_marker() { }

__attribute__((noinline, used))
void deletion_instrumentation(void *pred, void *target, void *succ) {
    asm volatile ("nop");
}


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
    new_pool_chunk->next = verif_pool_chunks;
    verif_pool_chunks = new_pool_chunk;
    for (int i = 0; i < NODE_CHUNK_SIZE; i++) {
        new_chunk[i].next_free = verif_node_pool;
        verif_node_pool = &new_chunk[i];
    }
}

static inline void verif_optimised_return_node(VerifOptimisedNode* node) {
    node->next_free = verif_node_pool;
    verif_node_pool = node;
}

void verif_optimised_free_all() {
    VerifOptimisedChunk* current_chunk = verif_pool_chunks;
    while (current_chunk != NULL) {
        VerifOptimisedChunk* next_chunk = current_chunk->next;
        free(current_chunk->chunk);
        free(current_chunk);
        current_chunk = next_chunk;
    }
    verif_node_pool = NULL;
    verif_pool_chunks = NULL;
}

void verif_optimised_insert(VerifOptimisedNode** head, int data) {
    if (verif_node_pool == NULL) {
        verif_optimised_allocate_pool_chunk();
    }
    VerifOptimisedNode* new_node = verif_node_pool;
    verif_node_pool = verif_node_pool->next_free;
    new_node->data = data;
    new_node->next = *head;
    *head = new_node;
    insert_exit_marker();
}

int verif_optimised_delete(VerifOptimisedNode** head, int data) {
    if (*head != NULL && (*head)->data == data) {
        VerifOptimisedNode* temp = *head;
        _mm_stream_si64((long long*)head, (long long)(*head)->next);
        verif_optimised_return_node(temp);
        return 1; // Deletion successful.
    }
    VerifOptimisedNode* prev = *head;
    VerifOptimisedNode* temp = (*head != NULL) ? (*head)->next : NULL;
    while (temp != NULL) {
        if (temp->data == data) {
            deletion_instrumentation(prev, temp, temp->next);
            prev->next = temp->next;
            verif_optimised_return_node(temp);
            return 1; // Deletion successful.
        }
        prev = temp;
        temp = temp->next;
    }
    return 0; // Node not found.
}

void verif_optimised_show(VerifOptimisedNode* head) {
    VerifOptimisedNode* current = head;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

VerifOptimisedNode* verif_optimised_search(VerifOptimisedNode* head, int data) {
    VerifOptimisedNode* current = head;
    while (likely(current != NULL)) {
        if (current->data == data)
            return current;
        current = current->next;
    }
    return NULL;
}
