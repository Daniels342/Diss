#ifndef LIST_INTERFACE_H
#define LIST_INTERFACE_H

#ifdef USE_VERIF_OPTIMISED
#include "verif_optimised_linked_list.h"
typedef VerifOptimisedNode Node;
#define list_insert   verif_optimised_insert
#define list_delete   verif_optimised_delete
#define list_show     verif_optimised_show
#define list_search   verif_optimised_search
#define list_free_all(...) verif_optimised_free_all()
#elif defined(USE_OPTIMISED)
#include "optimised_linked_list.h"
typedef OptimisedNode Node;
#define list_insert   optimised_insert
#define list_delete   optimised_delete
#define list_show     optimised_show
#define list_search   optimised_search
#define list_free_all() optimised_free_all()
#else
#include "baseline_linked_list.h"
typedef BaselineNode Node;
#define list_insert   baseline_insert
#define list_delete   baseline_delete
#define list_show     baseline_show
#define list_search   baseline_search
#define list_free_all(head) baseline_free_all(head)
#endif

#endif
