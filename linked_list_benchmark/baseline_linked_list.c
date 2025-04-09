#include <stdio.h>
#include <stdlib.h>
#include "baseline_linked_list.h"

__attribute__((noinline, used, externally_visible))
void deletion_instrumentation(void *pred, void *target, void *succ) {
    volatile int dummy = 0;
    dummy++;
}

void baseline_insert(BaselineNode** head, int data) {
    BaselineNode* new_node = (BaselineNode*)malloc(sizeof(BaselineNode));
    if (!new_node) {
        perror("malloc failed");
        exit(1);
    }
    new_node->data = data;
    // Insert at the head: new_node->next points to the current head.
    new_node->next = *head;
    *head = new_node;
}

int baseline_delete(BaselineNode** head, int data) {
    if (*head == NULL)
        return 0; // List is empty.
    
    BaselineNode* current = *head;
    BaselineNode* prev = NULL;
    
    while (current) {
        if (current->data == data) {
            deletion_instrumentation(prev, current, current->next);
            if (prev == NULL)
                *head = current->next; // Node to delete is the head.
            else
                prev->next = current->next;
            
            free(current);
            return 1; // Deletion successful.
        }
        prev = current;
        current = current->next;
    }
    return 0; // Node not found.
}

void baseline_show(BaselineNode* head) {
    BaselineNode* current = head;
    while (current) {
        printf("%d -> ", current->data);
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
