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
    new_node->next = *head;
    *head = new_node;
}

void baseline_delete(BaselineNode** head, int data) {
    if (*head == NULL) return;
    BaselineNode* temp = *head;
    if (temp->data == data) {
        *head = temp->next;
        free(temp);
        return;
    }
    BaselineNode* prev = temp;
    temp = temp->next;
    while (temp) {
        if (temp->data == data) {
            prev->next = temp->next;
            free(temp);
            return;
        }
        prev = temp;
        temp = temp->next;
    }
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
