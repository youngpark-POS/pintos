#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <string.h>


uint32_t* frame_to_pagedir(struct frame* f)
{
    return f->entry->thread->pagedir;
}

void frame_init()
{
    list_init(&frame_list);
    lock_init(&frame_lock);
    clock_pointer = list_front(&frame_list);
}

struct frame* frame_allocate(struct vmentry* vme)
{
    struct frame* new_frame;
    void* paddr;
    
    lock_acquire(&frame_lock);
    if((paddr = palloc_get_page(PAL_USER)) != NULL)
    {
        if((new_frame = malloc(sizeof(struct frame)) != NULL))
        {
            new_frame->paddr = paddr;
            new_frame->entry = vme;
        }
        else palloc_free_page(paddr);
    }
    else
    {
        new_frame = frame_evict();

        new_frame->entry = vme;
    }
    list_insert(&frame_list, &new_frame->ptable_elem);
    lock_release(&frame_lock);
    return new_frame;
}

bool frame_destroy(struct frame* f)
{
    lock_acquire(&frame_lock);
    if(clock_pointer == &f->ptable_elem)
        clock_pointer = list_next(clock_pointer);
    
    list_remove(&f->ptable_elem);
    palloc_free_page(f->paddr);
    free(f);
    lock_release(&frame_lock);
}

bool frame_deallocate(struct frame* f)
{
    lock_acquire(&frame_lock);
    if(clock_pointer == &f->ptable_elem)
        clock_pointer = list_next(clock_pointer);
    
    list_remove(&f->ptable_elem);
    free(f);
    lock_release(&frame_lock);
}

bool frame_is_dirty(struct frame* f)
{
    return pagedir_is_dirty(frame_to_pagedir(f), f->paddr) ||
           pagedir_is_dirty(frame_to_pagedir(f), f->entry->vaddr);
}

struct frame* frame_evict()
{
    struct frame* target;
    struct vmentry* entry;
    bool success = true;
    int swap_num;

    // find victim frame
    while(true)
    {
        target = list_entry(clock_pointer, struct frame, ptable_elem);
        if(pagedir_is_accessed(frame_to_pagedir(target), target->entry->vaddr))
        {
            pagedir_set_accessed(frame_to_pagedir(target), target->entry->vaddr, false);
            if(clock_pointer == list_tail(&frame_list))
                clock_pointer = list_front(&frame_list);
            else 
                clock_pointer = list_next(clock_pointer);
        }
        else break;
    }
    entry = target->entry;
    entry->pretype = entry->type;
    switch(entry->type)
    {
    case PAGE_ZERO:
        success = swap_out(target->paddr);
        if(!success) return NULL;
    case PAGE_FILE:
        if(entry->writable) 
        {
            success = swap_num = swap_out(target->paddr);
        }
        if(!success) return NULL;
        entry->type = PAGE_SWAP;
        entry->swap_slot = swap_num;
    case PAGE_SWAP:
        if(frame_is_dirty(target))
            file_write_at(entry->file, target->paddr, entry->read_bytes, entry->offset);
    }
    entry->frame = NULL;
    list_remove(&target->ptable_elem);
    pagedir_clear_page(target->entry->thread->pagedir, entry->vaddr);
    return target;
}