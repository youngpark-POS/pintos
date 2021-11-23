#include "page.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "devices/block.h"
#include "bitmap.h"
#include <string.h>

#define SECTORS_PER_ENTRY 8 // 4096B per a block, 512B per a sector


void swap_init()
{
    lock_init(&swap_lock);
    swap_block = block_get_role(BLOCK_SWAP);
    swap_bitmap = bitmap_create(block_size(swap_block) / SECTORS_PER_ENTRY);
    bitmap_set_all(swap_bitmap, true);
}

size_t swap_out(void* addr)
{
    size_t swap_idx = bitmap_scan(swap_bitmap, 0, 1, true);
    int i;
    lock_acquire(&swap_lock);

    if(swap_idx == BITMAP_ERROR) 
    {
        lock_release(&swap_lock);
        return BITMAP_ERROR;
    }
    else bitmap_set(swap_bitmap, swap_idx, false);
    
    for(i = 0;i < SECTORS_PER_ENTRY;i++)
        block_write(swap_block, swap_idx * SECTORS_PER_ENTRY + i, addr + BLOCK_SECTOR_SIZE * i);
    
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
    for(i = 0;i < SECTORS_PER_ENTRY;i++)
        block_read(swap_block, swap_idx * SECTORS_PER_ENTRY + i, addr + BLOCK_SECTOR_SIZE * i);
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