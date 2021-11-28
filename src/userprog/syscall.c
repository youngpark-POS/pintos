#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <bitmap.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "vm/frame.h"



static void syscall_handler(struct intr_frame *);

static void check_vaddr(const void *);

void syscall_halt(void);
pid_t syscall_exec(const char *);
int syscall_wait(pid_t);
bool syscall_create(const char *, unsigned);
bool syscall_remove(const char *);
int syscall_open(const char *);
int syscall_filesize(int);
int syscall_read(int, void *, unsigned);
int syscall_write(int, const void *, unsigned);
void syscall_seek(int, unsigned);
unsigned syscall_tell(int);
mapid_t syscall_mmap (int, void *);
void syscall_munmap (mapid_t);


static void clear_previous_pages(void* addr, off_t ofs);
static mapid_t register_new_mmap(struct file* file, void* base, int page_count);
static struct mapping* get_mapping_by_mapid(mapid_t id);

/* Registers the system call interrupt handler. */
void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

/* Pops the system call number and handles system call
   according to it. */
static void
syscall_handler(struct intr_frame *f)
{
    void *esp = f->esp;
    int syscall_num;

    check_vaddr(esp);
    check_vaddr(esp + sizeof(uintptr_t) - 1);
    syscall_num = *(int *)esp;

    switch (syscall_num)
    {
    case SYS_HALT:
    {
        syscall_halt();
        NOT_REACHED();
    }
    case SYS_EXIT:
    {
        int status;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        status = *(int *)(esp + sizeof(uintptr_t));

        syscall_exit(status);
        NOT_REACHED();
    }
    case SYS_EXEC:
    {
        char *cmd_line;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        cmd_line = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_exec(cmd_line);
        break;
    }
    case SYS_WAIT:
    {
        pid_t pid;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        pid = *(pid_t *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_wait(pid);
        break;
    }
    case SYS_CREATE:
    {
        char *file;
        unsigned initial_size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));
        initial_size = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_create(file, initial_size);
        break;
    }
    case SYS_REMOVE:
    {
        char *file;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_remove(file);
        break;
    }
    case SYS_OPEN:
    {
        char *file;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_open(file);
        break;
    }
    case SYS_FILESIZE:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_filesize(fd);
        break;
    }
    case SYS_READ:
    {
        int fd;
        void *buffer;
        unsigned size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 4 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_read(fd, buffer, size);
        break;
    }
    case SYS_WRITE:
    {
        int fd;
        void *buffer;
        unsigned size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 4 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_write(fd, buffer, size);
        break;
    }
    case SYS_SEEK:
    {
        int fd;
        unsigned position;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        position = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        syscall_seek(fd, position);
        break;
    }
    case SYS_TELL:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_tell(fd);
        break;
    }
    case SYS_CLOSE:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        syscall_close(fd);
        break;
    }
    case SYS_MMAP:
    {
        int fd;
        void* addr;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        addr = *(void **)(esp + 2 * sizeof(uintptr_t));

        f->eax = syscall_mmap (fd, addr);
        break;
    }
    case SYS_MUNMAP:
    {
        mapid_t mapping;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        mapping = *(mapid_t *)(esp + sizeof(uintptr_t));

        syscall_munmap (mapping);
        break;
    }
    default:
        syscall_exit(-1);
    }
}

/* Checks user-provided virtual address. If it is
   invalid, terminates the current process. */
static void
check_vaddr(const void *vaddr)
{
    if (!vaddr || !is_user_vaddr(vaddr) || !find_vme(pg_round_down(vaddr)))
        syscall_exit(-1);
}

struct lock *syscall_get_filesys_lock(void)
{
    return &filesys_lock;
}

/* Handles halt() system call. */
void syscall_halt(void)
{
    shutdown_power_off();
}

/* Handles exit() system call. */
void syscall_exit(int status)
{
    struct process *pcb = thread_get_pcb();

    pcb->exit_status = status;
    printf("%s: exit(%d)\n", thread_name(), status);
    if(lock_held_by_current_thread(&filesys_lock)) lock_release(&filesys_lock);
    thread_exit();
}

/* Handles exec() system call. */
pid_t syscall_exec(const char *cmd_line)
{
    pid_t pid;
    struct process *child;
    int i;

    check_vaddr(cmd_line);
    for (i = 0; *(cmd_line + i); i++)
        check_vaddr(cmd_line + i + 1);

    pid = process_execute(cmd_line);
    child = process_get_child(pid);

    if (!child || !child->is_loaded)
        return PID_ERROR;

    return pid;
}

/* Handles wait() system call. */
int syscall_wait(pid_t pid)
{
    return process_wait(pid);
}

/* Handles create() system call. */
bool syscall_create(const char *file, unsigned initial_size)
{
    bool success;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    lock_acquire(&filesys_lock);
    success = filesys_create(file, (off_t)initial_size);
    lock_release(&filesys_lock);

    return success;
}

/* Handles remove() system call. */
bool syscall_remove(const char *file)
{
    bool success;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    lock_acquire(&filesys_lock);
    success = filesys_remove(file);
    lock_release(&filesys_lock);

    return success;
}

/* Handles open() system call. */
int syscall_open(const char *file)
{
    struct file_descriptor_entry *fde;
    struct file *new_file;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    fde = palloc_get_page(0);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);

    new_file = filesys_open(file);
    if (!new_file)
    {
        palloc_free_page(fde);
        lock_release(&filesys_lock);

        return -1;
    }

    fde->fd = thread_get_next_fd();
    fde->file = new_file;
    list_push_back(thread_get_fdt(), &fde->fdtelem);

    lock_release(&filesys_lock);

    return fde->fd;
}

/* Handles filesize() system call. */
int syscall_filesize(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);
    int filesize;

    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    filesize = file_length(fde->file);
    lock_release(&filesys_lock);

    return filesize;
}

/* Handles read() system call. */
int syscall_read(int fd, void *buffer, unsigned size)
{
    struct file_descriptor_entry *fde;
    int bytes_read, i;
    for (i = 0; i < size; i++)
        check_vaddr(buffer + i);

    if (fd == 0)
    {
        unsigned i;

        for (i = 0; i < size; i++)
            *(uint8_t *)(buffer + i) = input_getc();

        return size;
    }

    fde = process_get_fde(fd);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    bytes_read = (int)file_read(fde->file, buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_read;
}

/* Handles write() system call. */
int syscall_write(int fd, const void *buffer, unsigned size)
{
    struct file_descriptor_entry *fde;
    int bytes_written, i;

    for (i = 0; i < size; i++)
        check_vaddr(buffer + i);

    if (fd == 1)
    {
        putbuf((const char *)buffer, (size_t)size);

        return size;
    }

    fde = process_get_fde(fd);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    bytes_written = (int)file_write(fde->file, buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_written;
}

/* Handles seek() system call. */
void syscall_seek(int fd, unsigned position)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);

    if (!fde) return;

    lock_acquire(&filesys_lock);
    file_seek(fde->file, (off_t)position);
    lock_release(&filesys_lock);
}

/* Handles tell() system call. */
unsigned syscall_tell(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);
    unsigned pos;

    if (!fde) return -1;

    lock_acquire(&filesys_lock);
    pos = (unsigned)file_tell(fde->file);
    lock_release(&filesys_lock);

    return pos;
}

/* Handles close() system call. */
void syscall_close(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);

    if (!fde) return;

    lock_acquire(&filesys_lock);
    file_close(fde->file);
    list_remove(&fde->fdtelem);
    palloc_free_page(fde);
    lock_release(&filesys_lock);
}

mapid_t 
syscall_mmap(int fd, void* addr)
{
  int len, ofs = 0;
  int page_cnt = 0, read_bytes = 0, zero_bytes = 0;
  struct file* file;
  struct mapping* mapping;
  int i;
  //ASSERT(!"mmap enter"); // <- unreached
  if(addr==NULL || /* addr < 0x8048000 || addr > 0xc0000000*/ !is_user_vaddr(addr) || pg_ofs(addr)) 
  {
    return -1;
  }
  //ASSERT(!"mmap enter2");
  lock_acquire(&filesys_lock);
 // ASSERT(!"mmap enter3");
  struct file_descriptor_entry *fde=process_get_fde(fd);
   //ASSERT(!"mmap enter4");
  file = file_reopen(fde->file);
  //ASSERT(!"mmap enter5");
  if(file == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }
  else
  {
    len = file_length(file);
    lock_release(&filesys_lock);
  }
  //ASSERT(!"mmap enter");
  while(len > 0)
  {
    //if(find_vme(addr))
      //return -1;
    read_bytes = len >= PGSIZE ? PGSIZE : len;
    zero_bytes = read_bytes == PGSIZE ? 0 : PGSIZE - read_bytes;
    if(!vme_create(addr + ofs, true, file, ofs, read_bytes, zero_bytes, 
                   true, false))
    {
      for(i=0; i<ofs; i=i+PGSIZE)
      {
        delete_vme_add(pg_round_down(addr + i));
      }
      file_close(file);
      return -1;
    }
    else
    {
      ofs += read_bytes;
      len -= read_bytes;
      page_cnt++;
    }
  }
  mapping = malloc(sizeof(struct mapping));
  mapping->addr = addr;
  mapping->file = file;
  mapping->page_num = page_cnt;
  mapping->mapid = thread_current()->number_mapped;
  (thread_current()->number_mapped)++; 
  //ASSERT(mapping->mapid);
  list_push_back(&thread_current()->mapping_list, &mapping->elem);
  // //<= mapid = 0
  return mapping->mapid;
}

void
syscall_munmap(mapid_t mapid)
{
  int i;
  struct vmentry* entry;
  struct mapping* mapping = NULL;
  struct list* list=&thread_current()->mapping_list;
  struct list_elem* e;
  struct mapping* candidate;
  for(e=list_begin(list); e!=list_end(list); e=list_next(e))
  {
    candidate=list_entry(e, struct mapping, elem);
    if(candidate->mapid == mapid)
    {
      mapping=candidate;
      break;
    }
  }
  if(mapping==NULL) return;
  //ASSERT(!"found mapping"); // <- unreached
  lock_acquire(&filesys_lock);
  for(i = 0; i<mapping->page_num; i++)
  {
    entry=find_vme(mapping->addr + i*PGSIZE);
    if(entry  == NULL) continue;
    if(entry->frame != NULL)
    {
      //ASSERT(!"syscall_unmap");
      if(pagedir_is_dirty(entry->thread->pagedir, entry->vaddr)) 
        file_write_at(mapping->file, entry->vaddr, PGSIZE, PGSIZE * i);
      frame_destroy(entry->frame);
    }
    pagedir_clear_page(entry->thread->pagedir, entry->vaddr);
    hash_delete(entry->thread->pages, &entry->elem);
  }
  list_remove(&mapping->elem);
  file_close(mapping->file);
  free(mapping);
  lock_release(&filesys_lock);
  //ASSERT(!"unmapped"); // <- unreached
}

void unmap(struct mapping *mapping)
{
    int i;
    struct vmentry* entry;
    lock_acquire(&filesys_lock);
    for(i = 0; i<mapping->page_num; i++)
    {
        entry=find_vme(mapping->addr + i*PGSIZE);
        if(entry  == NULL) continue;
        if(entry->frame != NULL)
        {
            //ASSERT(!"syscall_unmap");
            if(pagedir_is_dirty(entry->thread->pagedir, entry->vaddr)) 
                file_write_at(mapping->file, entry->vaddr, PGSIZE, PGSIZE * i);
            frame_destroy(entry->frame);
        }
        pagedir_clear_page(entry->thread->pagedir, entry->vaddr);
        hash_delete(entry->thread->pages, &entry->elem);
    }
    list_remove(&mapping->elem);
    file_close(mapping->file);
    free(mapping);
    lock_release(&filesys_lock);
}

void
mmap_file_write_at(struct file* file, void* addr, uint32_t read_bytes, off_t ofs)
{
    ASSERT(file != NULL);
    lock_acquire(&filesys_lock);
    file_write_at(file, addr, read_bytes, ofs);
    lock_release(&filesys_lock);
}


