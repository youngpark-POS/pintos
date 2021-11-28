#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "filesys/filesys.h"
#include "userprog/process.h"

struct lock filesys_lock;

struct file_mapping{
  mapid_t mapid;
  struct file* file;
  struct list_elem elem;
  void* base;
  int page_count;
};

void syscall_init(void);

struct lock *syscall_get_filesys_lock(void);

void syscall_exit(int);
void syscall_close(int);
void mmap_file_write_at(struct file* file, void* addr, uint32_t read_bytes, off_t ofs);
void unmap(struct file_mapping* m);

#endif /* userprog/syscall.h */
