#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"
#include <debug.h>

struct lock filesys_lock;
typedef int mapid_t;

struct mapping
{
    mapid_t mapid;
    void* addr;
    struct file* file;
    struct list_elem elem;
    int page_num;
};

void validate_addr(void*);
void destroy_mapping();
void syscall_init (void);
void syscall_halt(void);
void syscall_exit(int);
int syscall_exec(const char*);
int syscall_wait(int);
bool syscall_create(const char*, unsigned);
bool syscall_remove(const char*);
int syscall_open(const char*);
int syscall_filesize(int);
int syscall_read(int, void*, unsigned);
int syscall_write(int, const void*, unsigned);
void syscall_seek(int, unsigned);
unsigned syscall_tell(int);
void syscall_close(int);
void mmap_file_write_at(struct file* file, void* addr, uint32_t read_bytes, off_t ofs);
struct lock* get_file_lock(void);
struct lock *syscall_get_filesys_lock(void);
#endif /* userprog/syscall.h */
