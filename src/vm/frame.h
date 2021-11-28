#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include "threads/synch.h"
#include "vm/page.h"

struct frame
    {
        void *kpage;
        struct page* page;
        struct list_elem elem;
    };

void frame_init (void);
struct frame* frame_allocate(struct page* page);
void frame_push_back(struct frame* frame);
void frame_remove(struct frame* frame, bool is_free_page);
void frame_page_reassign_and_remove_list(struct frame* f, struct page* p);
bool frame_evict(struct frame* frame);
struct frame* frame_to_evict(void);
struct frame* frame_evict_and_reassign(struct page* page);
uint32_t* get_pagedir_of_frame(struct frame* frame);
bool swap_frame(struct page* page, struct frame* frame);
struct frame* frame_clock_forward(void);

#endif
