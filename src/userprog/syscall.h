#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/synch.h"

struct lock file_lock;

void validate_addr(void*);
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
int syscall_write(int, void*, unsigned);
void syscall_seek(int, unsigned);
unsigned syscall_tell(int);
void syscall_close(int);

#endif /* userprog/syscall.h */
