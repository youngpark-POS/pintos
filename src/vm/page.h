#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

enum page_type
  {
    PAGE_ZERO,          
    PAGE_FILE,
    PAGE_MMAP,
    PAGE_SWAP
  };

struct page 
    {
        struct thread* thread;
        struct hash_elem elem; 

        struct frame* frame;
        void* upage;
        
        size_t swap_index;
        
        struct file* file;
        bool writable;
        uint32_t read_bytes;
        uint32_t zero_bytes;
        off_t ofs;

        enum page_type type;
        enum page_type prev_type;
    };

bool page_create_with_file(void* upage, struct file* file, off_t ofs, uint32_t read_bytes,  uint32_t zero_bytes, bool writable, bool is_mmap);
bool page_create_with_zero(void *upage);
bool page_load(void *upage);
void page_exit(void);
void page_destory(struct hash_elem *e, void *aux);
struct page* page_find_by_upage(void* upage);
bool page_load_with_file(struct frame* f,struct page* p);
void page_destory_by_upage (void* upage, bool);
    
hash_hash_func page_hash_func;
hash_less_func page_less_func;

#endif