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

static void syscall_handler (struct intr_frame *);


void
validate_addr(void* addr)
{
  int i;
  for(i = 0;i < 4;i++)
  {
    if(!is_user_vaddr(addr + i)) syscall_exit(-1);
    if(!pagedir_get_page(thread_current()->pagedir, addr + i)) syscall_exit(-1);
  }
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
      validate_addr(esp+1);
      syscall_close(*(esp+1));      
      break;
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
  tid_t tid = process_execute(cmdline);
  struct thread* thread_child = get_child_process(tid);
  sema_down(&thread_current()->child_load);
  return thread_child->loaded ? thread_child->tid : -1;
}

int
syscall_wait(int pid)
{
  return process_wait(pid);
}

bool
syscall_create(const char* file, unsigned initial_size)
{
  return filesys_create(file, (off_t)initial_size);
}

bool
syscall_remove(const char* file)
{
  return filesys_remove(file);
}

int 
syscall_open(const char* file)
{
  struct file *fp = filesys_open(file);
  int i;

  if(!fp) return -1;
  for(i = 2;i < FD_MAX;i++)
  {
    if(thread_current()->fd_table[i] == NULL)
    {
      thread_current()->fd_table[i] = fp;
      return i;
    }
  }
  filesys_remove(file);
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
  struct file *fp;
  int bytes = 0, retval;
  uint8_t* buffer_ptr = (uint8_t*)buffer;
  uint8_t byte;

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
  struct file *fp;
  int bytes = 0, retval;
  uint8_t* buffer_ptr = (uint8_t*)buffer;
  uint8_t byte;

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
