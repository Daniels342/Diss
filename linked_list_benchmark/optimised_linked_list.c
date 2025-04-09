#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "optimised_linked_list.h"
#include <emmintrin.h>

#define NODE_CHUNK_SIZE 100000

/* Global pool variables for optimised version */
OptimisedNode* node_pool = NULL;
OptimisedChunk* pool_chunks = NULL;

/* Branch prediction macros */
#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

__attribute__((noinline, used, externally_visible))
void deletion_instrumentation(void *pred, void *target, void *succ) {
    volatile int dummy = 0;
    dummy++;
}

void optimised_allocate_pool_chunk() {
    OptimisedNode* new_chunk = NULL;
    if (posix_memalign((void**)&new_chunk, CACHE_LINE_SIZE, NODE_CHUNK_SIZE * sizeof(OptimisedNode)) != 0) {
        printf("Aligned memory allocation failed\n");
        exit(1);
    }
    OptimisedChunk* new_pool_chunk = (OptimisedChunk*)malloc(sizeof(OptimisedChunk));
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

void optimised_insert(OptimisedNode** head, int data) {
    if (node_pool == NULL) {
        optimised_allocate_pool_chunk();
    }
    OptimisedNode* new_node = node_pool;
    node_pool = node_pool->next_free;
    new_node->data = data;
    new_node->next = *head;
    *head = new_node;
}

static inline void optimised_return_node(OptimisedNode* node) {
    node->next_free = node_pool;
    node_pool = node;
}

void optimised_free_all() {
    OptimisedChunk* current_chunk = pool_chunks;
    while (current_chunk != NULL) {
        OptimisedChunk* next_chunk = current_chunk->next;
        free(current_chunk->chunk);
        free(current_chunk);
        current_chunk = next_chunk;
    }
    node_pool = NULL;
    pool_chunks = NULL;
}


int optimised_delete(OptimisedNode** head, int data) {
    if (*head != NULL && (*head)->data == data) {
        OptimisedNode* temp = *head;
        _mm_stream_si64((long long*)head, (long long)(*head)->next);
        optimised_return_node(temp);
        return 1; 
    }
    OptimisedNode* prev = *head;
    OptimisedNode* temp = (*head != NULL) ? (*head)->next : NULL;
    while (temp != NULL) {
        if (temp->data == data) {
            deletion_instrumentation(prev, temp, temp->next);
            prev->next = temp->next;
            optimised_return_node(temp);
            return 1; 
        }
        prev = temp;
        temp = temp->next;
    }
    return 0;
}

void optimised_show(OptimisedNode* head) {
    OptimisedNode* current = head;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

OptimisedNode* optimised_search(OptimisedNode* head, int data) {
    OptimisedNode* current = head;
    while (likely(current != NULL)) {
        if (current->data == data)
            return current;
        current = current->next;
    }
    return NULL;
}