#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <debug.h>
#include <list.h>
#include <hash.h>
#include "threads/palloc.h"
#include "vm/page.h"

struct frame
{
    void* paddr;
    struct vmentry* entry;
    struct list_elem ptable_elem;
};

struct list frame_list;
struct list_elem* clock_pointer;
struct lock frame_lock;

void frame_init(void);
struct frame* frame_allocate(struct vmentry*);
struct frame* frame_evict(void);
bool frame_destroy(struct frame*);
bool frame_deallocate(struct frame*);
void frame_push_back(struct frame*);
bool is_tail (struct list_elem *);
uint32_t* frame_to_pagedir(struct frame* );
struct frame* frame_evict(void);
uint32_t * get_pagedir(struct frame* frame);
#endif
