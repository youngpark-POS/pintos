#include "vm/page.h"
#include <hash.h>
#include <stdio.h>
#include <bitmap.h>
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"

bool
page_create_with_file(
    void* upage, struct file* file, off_t ofs, uint32_t read_bytes, 
    uint32_t zero_bytes, bool writable, bool is_mmap)
{
    if(page_find_by_upage(upage) != NULL)
        return false;

    struct page* new_page = malloc(sizeof(struct page));
    if(new_page != NULL)
    {
        new_page->upage = upage;
        new_page->file = file;
        new_page->ofs = ofs;
        new_page->read_bytes = read_bytes;
        new_page->zero_bytes = zero_bytes;
        new_page->writable = writable;
        new_page->swap_index = BITMAP_ERROR;
        new_page->thread = thread_current();
        new_page->frame = NULL;
        new_page->type = is_mmap ? PAGE_MMAP : PAGE_FILE;

        hash_insert(thread_current()->pages, &new_page->elem);
        return true;
    }
    else
    {
        return false;
    }
}

bool
page_create_with_zero(void *upage)
{
    if(page_find_by_upage(upage) != NULL)
        return false;

    struct page* new_page = malloc(sizeof(struct page));    
    if(new_page != NULL)
    {
        new_page->upage = upage;
        new_page->file = NULL;
        new_page->ofs = 0;
        new_page->read_bytes = 0;
        new_page->zero_bytes = PGSIZE;
        new_page->writable = true;
        new_page->swap_index = BITMAP_ERROR;
        new_page->thread = thread_current();
        new_page->frame = NULL;
        new_page->type = PAGE_ZERO;

        hash_insert(thread_current()->pages, &new_page->elem);
        return true;
    }
    else
    {
        return false;
    }
}

bool
page_load(void *upage)
{
    struct page* page_to_load = page_find_by_upage(upage);
    if (page_to_load == NULL || page_to_load->frame != NULL)
        return false;
    
    struct frame* new_frame = frame_allocate(page_to_load);
    if(new_frame == NULL)
        return false;
    
    bool success;
    switch (page_to_load->type)
    {
    case PAGE_SWAP:
        page_to_load->type = page_to_load->prev_type;
        success = swap_in(new_frame->kpage, page_to_load->swap_index);
        break;
    
    case PAGE_FILE:
    case PAGE_MMAP:
        success = page_load_with_file(new_frame, page_to_load);
        break;
    
    case PAGE_ZERO:
        success = memset(new_frame->kpage, 0, PGSIZE) != NULL;
        break;

    default:
        NOT_REACHED();
        break;
    }
    
    if(!success || !pagedir_set_page(thread_current ()->pagedir, upage, new_frame->kpage, page_to_load->writable))
    {
        frame_remove(new_frame, true);
        return false;
    }

    page_to_load->frame = new_frame;
    frame_push_back(page_to_load->frame); //After init, push
    return true;
}

bool
page_load_with_file(struct frame* f,struct page* p)
{
    if (file_read_at(p->file, f->kpage, p->read_bytes, p->ofs) != (int) p->read_bytes)
    {
        frame_remove(f, true);
        return false;
    }
    memset(f->kpage + p->read_bytes, 0, p->zero_bytes);
    return true;
}

void
page_exit(void)
{
    struct hash* h = thread_current()->pages;
    if(h != NULL)
        hash_destroy(h, page_destory);
}

void
page_destory (struct hash_elem *e, void *aux UNUSED)
{
    struct page* p = hash_entry(e, struct page, elem);
    if(p->frame)
        frame_remove(p->frame, false);
    if(p->swap_index != BITMAP_ERROR) 
        swap_remove(p->swap_index);
    free(p);
}

struct page*
page_find_by_upage(void* upage)
{
    struct page page_to_find;
    struct hash_elem *e;

    page_to_find.upage = upage;
    e = hash_find (thread_current()->pages, &page_to_find.elem);
    if(e != NULL)
        return hash_entry(e, struct page, elem);
    else
        return NULL;
}

void
page_destory_by_upage (void* upage, bool is_free_page)
{
    struct page* p = page_find_by_upage(upage);
    if(p->frame)
        frame_remove(p->frame, is_free_page);
    if(p->swap_index != BITMAP_ERROR) 
        swap_remove(p->swap_index);
    free(p);
}

unsigned
page_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  const struct page *p = hash_entry (e, struct page, elem);
  return hash_bytes (&p->upage, sizeof p->upage);
}

bool
page_less_func(const struct hash_elem *e1, const struct hash_elem *e2,void *aux UNUSED)
{
  const struct page *p1 = hash_entry (e1, struct page, elem);
  const struct page *p2 = hash_entry (e2, struct page, elem);

  return p1->upage < p2->upage;
}