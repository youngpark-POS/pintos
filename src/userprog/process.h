#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "lib/user/syscall.h"
#include "threads/synch.h"
#include "threads/thread.h"


struct process
{
    const char *file_name; 
    struct thread *parent;  
    struct list_elem childelem; 
    struct semaphore load_sema; 
    pid_t pid;                 
    bool is_loaded;             
    bool is_exited;             
    int exit_status;   
    struct semaphore exit_sema;          
};

tid_t process_execute(const char *);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

struct process *process_get_child(pid_t);
void process_remove_child(struct process *);
struct file* process_get_file(int);
int process_add_file(struct file*);

#endif 
