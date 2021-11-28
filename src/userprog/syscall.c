#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

// branch legacy

static void syscall_handler (struct intr_frame *);

void
validate_addr(void* addr)
{
  int i;
  for(i = 0;i < 4;i++)
  {
    if(!addr || !is_user_vaddr(addr + i)) syscall_exit(-1);
    if(!find_vme(pg_round_down(addr + i))) syscall_exit(-1);
  }
}

void
validate_string(const char* str)
{
  char* ch = str;
  for(;*ch;ch++)
    validate_addr(ch);
  validate_addr(ch);
}

void
validate_file(void* file, size_t size)
{
  void* ptr = file;
  int i = 0;
  for(;i < size;i++)
    validate_addr(ptr + i);
  validate_addr(ptr + i);
}

struct mapping*
find_mapping(int mapid)
{
  struct mapping* map;
  struct list_elem* e;
  struct list* list = &thread_current()->mapping_list;
  for(e = list_begin(list);e != list_end(list);e = list_next(e))
  {
    if(list_entry(e, struct mapping, elem)->mapid == mapid)
      return list_entry(e, struct mapping, elem);
  }
  return NULL;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int* esp = f->esp;
  validate_addr(esp);
  int syscall_num = *esp;
  switch(syscall_num)
  {
    case SYS_HALT:
      syscall_halt();
      break;
    case SYS_EXIT:
      validate_addr(esp+1);
      syscall_exit(*(esp+1));
      break;
    case SYS_EXEC:
      validate_addr(esp+1);
      validate_addr(*(esp+1));
      f->eax = syscall_exec(*(esp+1));
      break;
    case SYS_WAIT:
      validate_addr(esp+1);
      f->eax = syscall_wait(*(esp+1));      
      break;
    case SYS_CREATE:
      validate_addr(esp+1);
      validate_addr(*(esp+1));
      validate_addr(esp+2);
      f->eax = syscall_create(*(esp+1), *(esp+2));
      break;
    case SYS_REMOVE:
      validate_addr(esp+1);
      validate_addr(*(esp+1));
      f->eax = syscall_remove(*(esp+1));
      break;
    case SYS_OPEN:
      validate_addr(esp+1);
      validate_addr(*(esp+1));
      f->eax = syscall_open(*(esp+1));
      break;
    case SYS_FILESIZE:
      validate_addr(esp+1);
      f->eax = syscall_filesize(*(esp+1));      
      break;
    case SYS_READ:
      validate_addr(esp+1);
      validate_addr(esp+2);
      validate_addr(*(esp+2));
      validate_addr(esp+3);
      f->eax = syscall_read(*(esp+1), *(esp+2), *(esp+3));      
      break;
    case SYS_WRITE:
      validate_addr(esp+1);
      validate_addr(esp+2);
      validate_addr(*(esp+2));
      validate_addr(esp+3);
      f->eax = syscall_write(*(esp+1), *(esp+2), *(esp+3));      
      break;
    case SYS_SEEK:
      validate_addr(esp+1);
      validate_addr(esp+2);
      syscall_seek(*(esp+1), *(esp+2));
      break;
    case SYS_TELL:
      validate_addr(esp+1);
      f->eax = syscall_tell(*(esp+1));      
      break;
    case SYS_CLOSE:
      // ASSERT(!"syscall_close"); <- mmap unreached
      validate_addr(esp+1);
      syscall_close(*(esp+1));      
      break;
    case SYS_MMAP:
      validate_addr(esp+1);
      validate_addr(esp+2);
      f->eax = syscall_mmap(*(esp+1), *(esp+2));
    case SYS_MUNMAP:
      validate_addr(esp+1);
      syscall_munmap(*(esp+1));
    default:
      thread_exit();
  }
}

void
syscall_halt()
{
  shutdown_power_off();
}

void 
syscall_exit(int status)
{
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_code = status;
  thread_exit();
}

int
syscall_exec(const char* cmdline)
{
  struct list_elem* e;
  struct thread* child;
  validate_string(cmdline);
  return process_execute(cmdline);
}

int
syscall_wait(int pid)
{
  return process_wait(pid);
}

bool
syscall_create(const char* file, unsigned initial_size)
{
  validate_string(file);
  return filesys_create(file, (off_t)initial_size);
}

bool
syscall_remove(const char* file)
{
  validate_string(file);
  return filesys_remove(file);
}

int 
syscall_open(const char* file)
{
  validate_string(file);
  lock_acquire(&file_lock);
  struct file *fp = filesys_open(file);
  int i;

  if(!fp) 
  {
    lock_release(&file_lock);
    return -1;
  }
  for(i = 2;i < FD_MAX;i++)
  {
    if(thread_current()->fd_table[i] == NULL)
    {
      thread_current()->fd_table[i] = fp;
      if(!strcmp(thread_name(), file)) 
        file_deny_write(fp);
      lock_release(&file_lock);
      return i;
    }
  }
  filesys_remove(file);
  lock_release(&file_lock);
  return -1;
}

int 
syscall_filesize(int fd)
{
  struct file *fp = thread_current()->fd_table[fd];
  if(!fp) return -1;

  return (int)file_length(fp);
}

int
syscall_read(int fd, void* buffer, unsigned size)
{
  int bytes = 0;
  uint8_t* buffer_ptr = (uint8_t*)buffer;
  uint8_t byte;

  validate_file(buffer, size);
  lock_acquire(&file_lock);
  if(fd == 0) // stdin
  {
    for(;bytes < size;bytes++)
    {
      if((byte = input_getc()) != -1)
      {
        *buffer_ptr = byte;
        buffer_ptr++;
      }
      else break;
    }
  }
  else if(2 <= fd && fd < FD_MAX) // file input
  {
    if(thread_current()->fd_table[fd] != NULL) 
      bytes = (int)file_read(thread_current()->fd_table[fd], buffer, (off_t)size);
    else bytes = -1;
  }
  else bytes = -1;

  lock_release(&file_lock);
  return bytes;
}

int
syscall_write(int fd, void* buffer, unsigned size)
{
  int bytes = 0;
  uint8_t* buffer_ptr = (uint8_t*)buffer;
  uint8_t byte;

  validate_file(buffer, size);
  lock_acquire(&file_lock);
  if(fd == 1) // stdout
  {
    putbuf(buffer, size);
    bytes = size;
  }
  else if(2 <= fd && fd < FD_MAX) // file output
  {
    if(thread_current()->fd_table[fd] != NULL) 
      bytes = (int)file_write(thread_current()->fd_table[fd], buffer, (off_t)size);
    else bytes = -1;
  }
  else bytes = -1;
  
  lock_release(&file_lock);
  return bytes;
}

void
syscall_seek(int fd, unsigned position)
{
  struct file* fp = process_get_file(fd);
  if(!fp) return;
  file_seek(fp, (off_t)position);
}

unsigned
syscall_tell(int fd)
{
  struct file* fp = process_get_file(fd);
  if(!fp) return -1;
  return (int)file_tell(fp);
}

void
syscall_close(int fd)
{
  if(fd < 2 || fd >= FD_MAX) return;
  process_close_file(fd);
}

void mmap_file_write_at(struct file* file, void* addr, uint32_t read_bytes, off_t ofs)
{
  ASSERT(file != NULL);
  lock_acquire(&file_lock);
  file_write_at(file, addr, read_bytes, ofs);
  lock_release(&file_lock);
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
  if(!addr || addr < 0x8048000 || addr > 0xc0000000 || pg_ofs(addr)) 
  {
    return -1;
  }
  lock_acquire(&file_lock);
  file = file_reopen(process_get_file(fd));
  if(file == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }
  else
  {
    len = file_length(file);
    lock_release(&file_lock);
  }
  while(len > 0)
  {
    if(find_vme(addr))
      return -1;
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
  mapping->mapid = thread_current()->max_mapid;
  (thread_current()->max_mapid)++;
  list_push_back(&thread_current()->mapping_list, &mapping->elem);
  // ASSERT(mapping->mapid); //<= mapid = 0
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
  lock_acquire(&file_lock);
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
    pagedir_clear_page(entry->thread->pagedir);
    hash_delete(&entry->thread->vm, &entry->elem);
  }
  list_remove(&mapping->elem);
  file_close(mapping->file);
  free(mapping);
  lock_release(&file_lock);
  //ASSERT(!"unmapped"); // <- unreached
}
struct lock* get_file_lock(void)
{
  return &file_lock;
}