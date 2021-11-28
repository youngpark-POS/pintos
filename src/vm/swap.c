#include "vm/swap.h"
#include <bitmap.h>
#include <debug.h>
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static struct block *swap_block_device;

static struct bitmap *swap_bitmap;

static struct lock swap_lock;

#define NUM_SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void
swap_init(void)
{
    swap_block_device = block_get_role(BLOCK_SWAP);
    ASSERT(swap_block_device != NULL);
    swap_bitmap = bitmap_create(block_size(swap_block_device) / NUM_SECTORS_PER_PAGE);
    ASSERT(swap_bitmap != NULL);
    bitmap_set_all (swap_bitmap, true);
    lock_init(&swap_lock);
}

bool
swap_in(void *kpage, size_t swap_index)
{
    lock_acquire(&swap_lock);

    ASSERT(kpage != NULL);

    if(swap_index >= bitmap_size(swap_bitmap) || bitmap_test(swap_bitmap, swap_index))
    {
        lock_release(&swap_lock);
        return false;
    }

    for(size_t i = 0; i < NUM_SECTORS_PER_PAGE; i++)
        block_read(swap_block_device, swap_index * NUM_SECTORS_PER_PAGE + i, kpage + BLOCK_SECTOR_SIZE * i);
    
    bitmap_flip(swap_bitmap, swap_index);
    lock_release(&swap_lock);

    return true;
}

/* Swap out of kpage. 
    If fail, return -1
    Otherwise, return sector index */
size_t
swap_out(void *kpage)
{
    lock_acquire(&swap_lock);

    ASSERT(kpage != NULL);

    size_t swap_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, true);
    if (swap_index == BITMAP_ERROR)
        return swap_index;
    
    for(size_t i = 0; i < NUM_SECTORS_PER_PAGE; i++)
        block_write(swap_block_device, swap_index * NUM_SECTORS_PER_PAGE + i, kpage + BLOCK_SECTOR_SIZE * i);

    lock_release(&swap_lock);
    return swap_index;
}

void
swap_remove(size_t swap_index)
{
    lock_acquire(&swap_lock);
    ASSERT(swap_index != BITMAP_ERROR);
    bitmap_set(swap_bitmap, swap_index, true);
    lock_release(&swap_lock);
}