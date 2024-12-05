#ifndef LINKED_LIST_H
#define LINKED_LIST_H

typedef struct Node {
    int data;
    struct Node* next;
} Node;

Node* create_node(int data);
void insert(Node** head, int data);
void delete(Node** head, int data);
void display(Node* head);
void free_list(Node** head);
Node* search(Node* head, int data);

#endif
