#include <stdio.h>
#include <stdlib.h> 
#include <time.h>  
#include "linked_list.h"
#include "workload.h"

int random_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

int main() {
    Node* head = NULL;
    srand(time(NULL));
    for (int i = 0; i < 1000000; i++) {
      int random_value = random_range(1, 10000);
      insert(&head, random_value);
    }
    run_workload(&head, 34, 33, 33, 10);
    return 0;
}
