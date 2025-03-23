#ifndef LINKED_LIST_H
#define LINKED_LIST_H

typedef struct Node {
    int data;
    struct Node* next;
    struct Node* next_free;
} Node;

typedef struct Chunk {
    Node* chunk; 
    struct Chunk* next;   
} Chunk;

void insert(Node** head, int data);
void delete(Node** head, int data);
void show(Node* head);
Node* search(Node* head, int data);
void return_node(Node* node);
void free_all();
void allocate_pool_chunk();

#endif
