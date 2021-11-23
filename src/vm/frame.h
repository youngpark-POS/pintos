#include <stdint.h>
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

void frame_init();
struct frame* frame_allocate(struct vmentry*);
struct frame* frame_evict();
bool frame_destroy(struct frame*);
bool frame_deallocate(struct frame*);

