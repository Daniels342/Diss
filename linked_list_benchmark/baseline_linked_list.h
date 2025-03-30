#ifndef BASELINE_LINKED_LIST_H
#define BASELINE_LINKED_LIST_H

typedef struct BaselineNode {
    int data;
    struct BaselineNode* next;
    struct BaselineNode* prev;  
} BaselineNode;

void baseline_insert(BaselineNode** head, int data);
void baseline_delete(BaselineNode** head, int data);
void baseline_show(BaselineNode* head);
BaselineNode* baseline_search(BaselineNode* head, int data);
void baseline_free_all(BaselineNode** head);

#endif
