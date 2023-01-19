#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* File descriptor table for each process. Keep track of a list
 * of OPEN files for each process.*/
typedef int fd_t; // File descriptor
struct file_descriptor {
  fd_t fd;
  struct file* file;
  struct list_elem elem;
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct file* file;          /* file pointer for executable load*/
  struct thread* main_thread; /* Pointer to main thread */
  struct list* file_descriptor_list; /* File descriptor for each process*/
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

/* The system needs to keep track of a minimal list of process info*/
struct process_info
{
  tid_t pid;
  tid_t parentPid;
  int exit_status;
  bool waited;
  bool load_success;          /* Can't put in pcb for not existing files*/
  struct semaphore exit;
  struct semaphore load_semaphore; /*Sync for exec syscall*/
  struct list_elem elem;
};

extern struct list process_info_list;

extern struct semaphore filesys;
#endif /* userprog/process.h */
