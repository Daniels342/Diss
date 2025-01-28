#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "linked_list.h"
#define CACHE_LINE_SIZE 64

#define NODE_CHUNK_SIZE 100000

Node* node_pool = NULL;
Chunk* pool_chunks = NULL;
void insert_exit_marker() {}
void allocate_pool_chunk() {
    Node* new_chunk = NULL;
    if (posix_memalign((void**)&new_chunk, CACHE_LINE_SIZE, NODE_CHUNK_SIZE * sizeof(Node)) != 0) {
        printf("Aligned memory allocation failed");
        exit(1);
    }
    Chunk* new_pool_chunk = (Chunk*)malloc(sizeof(Chunk));
    if (new_pool_chunk == NULL) {
        printf("Memory allocation failed for chunk metadata");
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

void init_node_pool() {
    allocate_pool_chunk();
}

inline void return_node(Node* node) {
    node->next_free = node_pool;
    node_pool = node;
}

void free_all() {
    Chunk* current_chunk = pool_chunks;
    while (current_chunk != NULL) {
        Chunk* next_chunk = current_chunk->next;
        free(current_chunk->chunk); 
        free(current_chunk);         
        current_chunk = next_chunk;
    }
}

inline void insert(Node** head, int data) {
    if (node_pool == NULL) {
        allocate_pool_chunk(); // Directly call allocate_pool_chunk if pool is empty
    }
    Node* new_node = node_pool;
    node_pool = node_pool->next_free;
    new_node->data = data;
    new_node->next = *head;
    *head = new_node;
    insert_exit_marker();
}

void delete(Node** head, int data) {
    // Handle the special case where the data is in the head node
    if (*head != NULL && (*head)->data == data) {
        Node* temp = *head;
        *head = (*head)->next;
        return_node(temp);
        return;
    }

    // Initialize pointers for traversal
    Node* prev = *head;
    Node* temp = (*head != NULL) ? (*head)->next : NULL;

    // Loop through the list to find the node with the target data
    while (temp != NULL) {
        if (temp->data == data) {
            prev->next = temp->next;
            return_node(temp);
            return;
        }
        prev = temp;
        temp = temp->next;
    }
}

void show(Node* head) {
    Node* current = head;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

Node* search(Node* head, int data) {
    Node* current = head;
    while (current != NULL) {
        if (current->data == data) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

