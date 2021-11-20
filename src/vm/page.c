#include "page.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <string.h>

static usnsigned vm_hash_func(const struct hash_elem *, void* UNUSED);
static bool vm_less_func(const struct hash_elem *, const struct hash_elem *, void* UNUSED);
static void vm_destroy_func(struct hash_elme *, void* UNUSED);

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

static unsigned vm_hash_func(const struct hahs_elem *e, void *aux UNUSED)
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

static void vm_destroy_func(struct hash_elme *e, void* aux UNUSED)
{
    ASSERT(e!=NULL);
    struct vmentry *vme;
    vme=hash_entry(e, struct vmentry, elem);
    if(vme->frame != NULL) frame_remove(vme->frame,false);
    if(vme->swap_slot!=BITMAP_ERROR) swap_remove(vme->swap_slot);
    free(vme);
}

struct vmentry* fine_vme(void *vaddr)
{
    struct hash *vm=&thread_current()->vm;
    struct vmentry vme;
    struct hash_elem *elem;
    vme.vaddr=pg_round_down(vaddr);
    ASSERT(pg_ofs(vme.vaddr)==0);
    elem=hash_find(vm,&vme.elem);
    return elem ? hash_entry(elem, struct vmentry, elem) : NULL;
}

bool insert_vme(struct hash* vm, struct vmentry * vme)
{
    ASSERT(vm!=NULL && vme!=NULL);
    ASSERT(pg_offs(vme->vaddr)==0);
    if(hash_insert(vm,&vme->elem)==NULL) return true;
    else return false;
}

bool delete_vme(struct hash* vm, struct vmentry * vme)
{
    ASSERT(vm!=NULL && vme!=NULL);
    ASSERT(pg_offs(vme->vaddr)==0);
    if(!hash_delete(vm,&vme->elem)) return false;
    if(vme->frame != NULL) frame_remove(vme->frame,false);
    if(vme->swap_slot!=BITMAP_ERROR) swap_remove(vme->swap_slot);
    free(vme);
    return true;
}

bool vme_create(void *vaddr, bool writable, struct file* file, size_t offset,
    size_t read_bytes, size_t zero_bytes, bool ismap, bool isstack)
{
    struct vme* newone;
    if(fine_vme(vaddr)==NULL)
    {
        newone=malloc(sizeof(struct vmentry));
        if(newone==NULL) return false;
        else
        {
            memset(newone,0,sizeof(struct vmentry));
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
                if(ismap==true) newone->type=PAGE_MMAP;
                else newone->type=PAGE_FILE;
                newone->frame=NULL;
            }
            insert_vme(&thread_current()->vm, newone);
        }
    }
    else return false;
}

bool vm_load(void *vaddr)
{
    struct vmentry* page;
    struct frame* new_frame;
    page=find_vme(vaddr);
    if(page==NULL || page->is_loaded==true) return false;
    new_frame=frame_allocate(page);
    if(newframe==NULL) return false;
    if(page->type==PAGE_ZERO)
    {
        if(memset(new_frame->kpage,0,PGSIZE)!=NULL) page->is_loaded=true;
        if(page->is_loaded && pagedir_set_page(thread_current()->pagedir, vaddr, new_frame->kpage, page->writable))
        {
            page->frame=new_frame;
        }
        else
        {
            frame_remove(new_frame, true);
            page->is_loaded=false;
            return false;
       }
    }
    else if(page->type==PAGE_FILE || page->type==PAGE_MMAP)
    {
        if(file_read_at(page->file,new_frame->kpage,page->read_bytes,page->offset) != (int) page->read_bytes)
        {
            frame_remove(new_frame, true);
            return false;
        }
        else
        {
            memset(new_frame->kpage + page->read_bytes, 0, page->zero_bytes);
            page->isloaded=true;
        }
        if(page->is_loaded && pagedir_set_page(thread_current()->pagedir, vaddr, new_frame->kpage, page->writable))
        {
               page->frame=new_frame;
        }
        else if(page->isloaded)
        {
            frame_remove(new_frame, true);
            page->is_loaded=false;
            return false;
        }
    }
    else if(page->type==PAGE_SWAP)
    {
        page->is_loaded=swap_in(new_frame->kpage, page->swap_slot);
        page->type=page->pretype;
        if(page->is_loaded && pagedir_set_page(thread_current()->pagedir, vaddr, new_frame->kpage, page->writable))
        {
            page->frame=new_frame;
        }
        else
        {
            frame_remove(new_frame, true);
            page->is_loaded=false;
            return false;
        }
    }
    fram_push_back(page->frame);
    return true;
}