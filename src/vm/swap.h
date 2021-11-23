#include <stdint.h>
#include <debug.h>
#include <list.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"

struct block* swap_block;
struct bitmap* swap_bitmap;
struct lock swap_lock;

void swap_init();
size_t swap_out(void*);
size_t swap_in(void*, size_t);