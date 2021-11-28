#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

void swap_init(void);
bool swap_in(void *kpage, size_t sector);
size_t swap_out(void *kpage);
void swap_remove(size_t swap_index);

#endif