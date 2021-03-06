#include "page.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "devices/block.h"
#include "bitmap.h"
#include <string.h>

#define NUM_SECTORS_PER_ENTRY 8 // 4096B per a block, 512B per a sector


void swap_init()
{
    
    swap_block = block_get_role(3);
    ASSERT(swap_block!=NULL);
    swap_bitmap = bitmap_create(block_size(swap_block) / NUM_SECTORS_PER_ENTRY);
    ASSERT(swap_bitmap!=NULL);
    bitmap_set_all(swap_bitmap, true);
    lock_init(&swap_lock);
}

size_t swap_out(void* addr)
{
    size_t swap_idx;
    size_t i;
    lock_acquire(&swap_lock);
    swap_idx = bitmap_scan(swap_bitmap, 0, 1, true);
    if(swap_idx == BITMAP_ERROR) 
    {
        lock_release(&swap_lock);
        return BITMAP_ERROR;
    }
    else bitmap_set(swap_bitmap, swap_idx, false);
    
    for(i = 0; i < NUM_SECTORS_PER_ENTRY; i++)
        block_write(swap_block, swap_idx * NUM_SECTORS_PER_ENTRY + i, addr + BLOCK_SECTOR_SIZE * i);
    
    lock_release(&swap_lock);
    return swap_idx;
}

size_t swap_in(void* addr, size_t swap_idx)
{
    int i;
    lock_acquire(&swap_lock);

    if(bitmap_test(swap_bitmap, swap_idx) || swap_idx >= bitmap_size(swap_bitmap))
    {
        lock_release(&swap_lock);
        return -1;
    }
    for(i = 0;i < NUM_SECTORS_PER_ENTRY;i++)
        block_read(swap_block, swap_idx * NUM_SECTORS_PER_ENTRY + i, addr + BLOCK_SECTOR_SIZE * i);
    bitmap_set(swap_bitmap, swap_idx, true);

    lock_release(&swap_lock);
    return swap_idx;
} 

void swap_remove(size_t swap_idx)
{
    lock_acquire(&swap_lock);
    bitmap_set(swap_bitmap, swap_idx, true);
    lock_release(&swap_lock);
}