#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include "list_interface.h"
#include "workload.h"

int random_range(int min, int max) {
    return rand() % (max - min + 1) + min;
}

int main() {
    int num_initial = 1000000;
    int duration = 300;
    int insert_percent = 34, search_percent = 33, delete_percent = 33;

    srand(time(NULL));
    Node* head = NULL;

    // Pre-populate the list with random values.
    for (int i = 0; i < num_initial; i++) {
        int random_value = random_range(1, 10000);
        list_insert(&head, random_value);
    }
    
    // Fork the process after pre-population.
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    
    if (pid == 0) {
        // Child process: execute the workload.
        run_workload(&head, insert_percent, search_percent, delete_percent, duration);
        
        // Clean up the list in the child.
#ifdef USE_OPTIMISED
        list_free_all();
#else
        list_free_all(&head);
#endif
        exit(EXIT_SUCCESS);
    } else {
        // Parent process: wait for the child to finish.
        int status;
        wait(&status);
        exit(EXIT_SUCCESS);
    }
}
