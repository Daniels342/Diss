#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "optimised_linked_list.h"
#include <emmintrin.h>  // For non-temporal store intrinsic

#define NODE_CHUNK_SIZE 100000

// Global node pool and chunk list.
OptimisedNode* node_pool = NULL;
OptimisedChunk* pool_chunks = NULL;

// Define branch prediction hints.
#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

// Empty marker function (for potential future use)
static inline void insert_exit_marker() { }

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

void optimised_insert(OptimisedNode** head, int data) {
    if (node_pool == NULL) {
        optimised_allocate_pool_chunk();
    }
    OptimisedNode* new_node = node_pool;
    node_pool = node_pool->next_free;
    new_node->data = data;
    new_node->next = *head;
    *head = new_node;
    insert_exit_marker();
}

void optimised_delete(OptimisedNode** head, int data) {
    if (*head != NULL && (*head)->data == data) {
        OptimisedNode* temp = *head;
        // Use non-temporal store via _mm_stream_si64 (x86-64 specific)
        _mm_stream_si64((long long*)head, (long long)(*head)->next);
        optimised_return_node(temp);
        return;
    }

    OptimisedNode* prev = *head;
    OptimisedNode* temp = (*head != NULL) ? (*head)->next : NULL;

    while (temp != NULL) {
        if (temp->data == data) {
            prev->next = temp->next;
            optimised_return_node(temp);
            return;
        }
        prev = temp;
        temp = temp->next;
    }
}


// Display function remains unchanged.
void optimised_show(OptimisedNode* head) {
    OptimisedNode* current = head;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

// Aggressively unrolled search function with multi-level prefetching.
OptimisedNode* optimised_search(OptimisedNode* head, int data) {
    OptimisedNode* current = head;
    // Process two nodes per iteration.
    while (current && current->next) {
        // Prefetch the next two nodes to reduce latency.
        if (current->next) {
            __builtin_prefetch(current->next, 0, 3);
        }
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
