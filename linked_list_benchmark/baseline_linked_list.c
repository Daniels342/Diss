#include <stdio.h>
#include <stdlib.h>
#include "baseline_linked_list.h"

void baseline_insert(BaselineNode** head, int data) {
    BaselineNode* new_node = (BaselineNode*)malloc(sizeof(BaselineNode));
    if (!new_node) {
        perror("malloc failed");
        exit(1);
    }
    new_node->data = data;
    // Insert at the head: new_node->prev is NULL.
    new_node->next = *head;
    new_node->prev = NULL;
    if (*head != NULL) {
        (*head)->prev = new_node;
    }
    *head = new_node;
}

void baseline_delete(BaselineNode** head, int data) {
    if (*head == NULL)
        return;
    BaselineNode* current = *head;
    while (current) {
        if (current->data == data) {
            // If current is not the head, update its previous node.
            if (current->prev)
                current->prev->next = current->next;
            else
                *head = current->next;  // current is head

            // If there is a next node, update its prev pointer.
            if (current->next)
                current->next->prev = current->prev;

            free(current);
            return;
        }
        current = current->next;
    }
}

void baseline_show(BaselineNode* head) {
    BaselineNode* current = head;
    while (current) {
        printf("%d <-> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

BaselineNode* baseline_search(BaselineNode* head, int data) {
    BaselineNode* current = head;
    while (current) {
        if (current->data == data)
            return current;
        current = current->next;
    }
    return NULL;
}

void baseline_free_all(BaselineNode** head) {
    BaselineNode* current = *head;
    while (current) {
        BaselineNode* next = current->next;
        free(current);
        current = next;
    }
    *head = NULL;
}
