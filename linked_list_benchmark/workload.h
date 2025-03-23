#ifndef WORKLOAD_H
#define WORKLOAD_H

#include <time.h>
#include "list_interface.h"

int random_in_range(int min, int max);
void run_workload(Node** head, int insert_percentage, int search_percentage, int delete_percentage, int duration_seconds);

#endif
