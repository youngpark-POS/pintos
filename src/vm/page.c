#include "page.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include <string.h>

static unsigned
vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    ASSERT(e!=NULL);
    return hash_int(hash_entry(e, struct vmentry, elem)->vaddr);
}

static bool vm_less_func(const struct hash_elem *x, const struct hash_elem *y, void* aux UNUSED)
{
    ASSERT(x!=NULL && y!=NULL);
    if(hash_entry(x,struct vmentry, elem)->vaddr < hash_entry(y,struct vmentry, elem)->vaddr) return true;
    else return false;
}

static void vm_destroy_func(struct hash_elem *e, void* aux UNUSED)
{
    ASSERT(e!=NULL);
    struct vmentry *vme;
    vme=hash_entry(e, struct vmentry, elem);
    if(vme->frame != NULL) frame_deallocate(vme->frame);
    if(vme->swap_slot!=BITMAP_ERROR) swap_remove(vme->swap_slot);
    free(vme);
}

void vm_init(struct hash *vm)
{
    ASSERT(vm!=NULL);
    hash_init(vm,vm_hash_func,vm_less_func,NULL);
}

void vm_destroy(struct hash *vm)
{
    ASSERT(vm!=NULL);
    hash_destroy(vm,vm_destroy_func);
}

struct vmentry* find_vme(void *vaddr)
{
    struct hash *vm=thread_current()->pages;
    struct vmentry vme;
    struct hash_elem *elem;
    vme.vaddr=pg_round_down(vaddr);
    ASSERT(pg_ofs (vme.vaddr)==0);
    elem=hash_find(vm,&vme.elem);
    return elem ? hash_entry(elem, struct vmentry, elem) : NULL;
}

bool insert_vme(struct hash* vm, struct vmentry * vme)
{
    ASSERT(vm!=NULL && vme!=NULL);
    ASSERT(pg_ofs(vme->vaddr)==0);
    if(hash_insert(vm,&vme->elem)==NULL) return true;
    else return false;
}

bool delete_vme(struct hash* vm, struct vmentry * vme)
{
    ASSERT(vm!=NULL && vme!=NULL);
    ASSERT(pg_ofs(vme->vaddr)==0);
    if(!hash_delete(vm,&vme->elem)) return false;
    if(vme->frame != NULL) frame_deallocate(vme->frame);
    if(vme->swap_slot!=BITMAP_ERROR) swap_remove(vme->swap_slot);
    free(vme);
    return true;
}

bool delete_vme_add(void* upage)
{
    struct vmentry* p = find_vme(upage);
    if(p->frame != NULL) frame_destroy(p->frame);

    if(p->swap_slot != BITMAP_ERROR) swap_remove(p->swap_slot);
    free(p);
    return true;
}

bool vme_create(void *vaddr, bool writable, struct file* file, size_t offset,
    size_t read_bytes, size_t zero_bytes, bool ismap, bool isstack)
{
    struct vmentry* newone;
    if(find_vme(vaddr)==NULL)
    {
        newone=malloc(sizeof(struct vmentry));
        if(newone==NULL)
        {
            return false;
        }
        else
        {
            if(isstack==true)
            {
                newone->vaddr=vaddr;
                newone->file=NULL;
                newone->writable=true;
                newone->read_bytes=0;
                newone->zero_bytes=0;
                newone->offset=0;
                newone->swap_slot=BITMAP_ERROR;
                newone->type=PAGE_ZERO;
                newone->frame=NULL;
                newone->thread=thread_current();
            }
            else
            {
                newone->vaddr=vaddr;
                newone->file=file;
                newone->writable=writable;
                newone->read_bytes=read_bytes;
                newone->zero_bytes=zero_bytes;
                newone->offset=offset;
                newone->swap_slot=BITMAP_ERROR;
                if(ismap==true) newone->type=PAGE_MAPP;
                else newone->type=PAGE_FILE;
                newone->frame=NULL;
                newone->thread=thread_current();
            }
           insert_vme(thread_current()->pages, newone);
           return true;
        }
    }
    else return false;
}

bool vm_load(void *vaddr)
{
    struct vmentry* page;
    struct frame* new_frame;
    page=find_vme(vaddr);
    if(page->frame!=NULL || page==NULL)
    {
        return false;
    }
    new_frame=frame_allocate(page);
    if(new_frame==NULL)
    {
        return false;
    }
    if(page->type==PAGE_ZERO)
    {
        if(memset(new_frame->paddr,0,PGSIZE)!=NULL) page->is_loaded=true;
        if(page->is_loaded && pagedir_set_page(thread_current()->pagedir, vaddr, new_frame->paddr, page->writable))
        {
            page->frame=new_frame;
        }
        else
        {
            frame_destroy(new_frame);
            page->is_loaded=false;
            return false;
        }
    }
    else if(page->type==PAGE_FILE || page->type==PAGE_MAPP)
    {
        int readlen = file_read_at(page->file, new_frame->paddr, (off_t)page->read_bytes, page->offset);
        if(readlen != (off_t) page->read_bytes)
        {
            frame_destroy(new_frame);
            return false;
        }
        else
        {
            memset(new_frame->paddr + page->read_bytes, 0, page->zero_bytes);
            page->is_loaded=true;
        }
        if(page->is_loaded && pagedir_set_page(thread_current()->pagedir, vaddr, new_frame->paddr, page->writable))
        {
            page->frame=new_frame;   
        }
        else if(page->is_loaded)
        {
            frame_destroy(new_frame);
            page->is_loaded=false;
            return false;
        }
    }
    else if(page->type==PAGE_SWAP)
    {
        if(swap_in(new_frame->paddr, page->swap_slot)==-1) page->is_loaded=false;
        else page->is_loaded=true;
        page->type=page->pretype;
        if(page->is_loaded && pagedir_set_page(thread_current()->pagedir, vaddr, new_frame->paddr, page->writable))
        {
            page->frame=new_frame;
        }
        else
        {
            frame_destroy(new_frame);
            page->is_loaded=false;
            return false;
        }
    }
    frame_push_back(page->frame);
    return true;
}