#include <stdint.h>
#include <debug.h>
#include <list.h>
#include <hash.h>
#include "threads/palloc.h"

#define PAGE_ZORO 0
#define PAGE_FILE 1
#define PAGE_MAPP 2
#define PAGE_SWAP 3

struct vmentry
{
    unit8_t type;
    unit8_t pretype;
    void *vaddr;
    bool writable;

    bool is_loaded;
    struct file* file;
    struct list_elem mmap_elem;

    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;

    size_t swap_slot;

    struct frame* frame;

    struct hash_elem elem;

}
void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);
static unsigned vm_hash_func(const struct hahs_elem *e, void *aux UNUSED);
static bool vm_less_func(const struct hash_elem *x, const struct hash_elem *y, void* aux UNUSED);
static void vm_destroy_func(struct hash_elme *e, void* aux UNUSED);
struct vmentry* fine_vme(void *vaddr);
bool insert_vme(struct hash* vm, struct vmentry * vme);
bool delete_vme(struct hash* vm, struct vmentry * vme);

bool vme_create(void *vaddr, bool writable, struct file* file, size_t offset,
    size_t read_bytes, size_t zero_bytes, bool ismap, bool isstack);
bool vm_load(void *vaddr);