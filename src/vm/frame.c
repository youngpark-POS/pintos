#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <list.h>
#include <string.h>

bool is_tail (struct list_elem *elem)
{
  return elem != NULL && elem->prev != NULL && elem->next == NULL;
}
bool is_back (struct list_elem* elem)
{
    return list_back(&frame_list)==elem;
}


void frame_push_back(struct frame* f)
{
    //lock_acquire(&frame_lock);
    list_push_back(&frame_list, &f->ptable_elem);
    //lock_release(&frame_lock);
}

void frame_init(void)
{
    list_init(&frame_list);
    lock_init(&frame_lock);
    clock_pointer = list_tail(&frame_list);
}

struct frame* frame_allocate(struct vmentry* vme)
{
    struct frame* new_frame=NULL;
    void* paddr;

    lock_acquire(&frame_lock);
    paddr = palloc_get_page(PAL_USER);
    if(paddr != NULL)
    {
        new_frame = malloc(sizeof(struct frame));
        if(new_frame != NULL)
        {
            new_frame->paddr = paddr;
            new_frame->entry = vme;
        }
        else
        {
            palloc_free_page(paddr);
        }
    }
    else
    {
        
        new_frame = frame_evict();
        //ASSERT(!"come");
        new_frame->entry = vme;
    }
    //list_push_back(&frame_list, &new_frame->ptable_elem);
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
uint32_t * get_pagedir(struct frame* frame)
{
    return frame->entry->thread->pagedir;
}
bool frame_is_dirty(struct frame* f)
{
    return pagedir_is_dirty(get_pagedir(f), f->paddr) ||
           pagedir_is_dirty(get_pagedir(f), f->entry->vaddr);
}

struct frame* frame_evict(void)
{
    ASSERT(lock_held_by_current_thread(&frame_lock));
    struct frame* target;
    struct vmentry* entry;
    struct list_elem* next_elem;
    bool success = true;
    int swap_num;
    //ASSERT(!"file");
    // find victim frame
    
    if(is_tail(clock_pointer) || is_back(clock_pointer)) next_elem = list_front(&frame_list);
    else next_elem = list_next(clock_pointer);
    clock_pointer=next_elem;
    target=list_entry(next_elem, struct frame, ptable_elem);
    while(pagedir_is_accessed(get_pagedir(target), target->entry->vaddr))
    {
        pagedir_set_accessed(get_pagedir(target), target->entry->vaddr, false);
        if(is_tail(clock_pointer) || is_back(clock_pointer)) //== list_tail(&frame_list) || ==list_tail(&frame_list))
            next_elem = list_front(&frame_list);
        else 
            next_elem = list_next(clock_pointer);
        clock_pointer=next_elem;
        target=list_entry(next_elem, struct frame, ptable_elem);
    }

    //ASSERT(lock_held_by_current_thread(&frame_lock));
    //ASSERT(!"file");
    entry = target->entry;
    entry->pretype = entry->type;
    switch(entry->type)
    {
    case PAGE_ZERO:
        swap_num = swap_out(target->paddr);
        if(swap_num == BITMAP_ERROR) return NULL;
        entry->type=PAGE_SWAP;
        entry->swap_slot=swap_num;
        break;
    case PAGE_MAPP:
        if(frame_is_dirty(target))
            mmap_file_write_at(entry->file, target->paddr, entry->read_bytes, entry->offset);
        break;
    case PAGE_FILE:
        if(entry->writable && frame_is_dirty(target)) 
        {
            swap_num = swap_out(target->paddr);
            if(swap_num == BITMAP_ERROR) return NULL;
            entry->type = PAGE_SWAP;
            entry->swap_slot = swap_num;
        }
        break;
    }
    entry->frame = NULL;
    list_remove(&target->ptable_elem);
    pagedir_clear_page(target->entry->thread->pagedir, entry->vaddr);
    return target;
}