#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <debug.h>
#include <list.h>
#include <stdio.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"

#define PAGE_ZERO 0
#define PAGE_FILE 1
#define PAGE_MAPP 2
#define PAGE_SWAP 3

struct vmentry
{
    int type;
    int pretype;
    struct thread* thread;
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
};

void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);

struct vmentry* fine_vme(void *vaddr);
bool insert_vme(struct hash* vm, struct vmentry * vme);
bool delete_vme(struct hash* vm, struct vmentry * vme);

bool vme_create(void *vaddr, bool writable, struct file* file, size_t offset,
                size_t read_bytes, size_t zero_bytes, bool ismap, bool isstack);
bool vm_load(void *vaddr);
struct vmentry* addr_to_entry(void* addr);

#endif