#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

bool is_user_address_valid(void* uaddr);
bool is_user_address_valid(void* uaddr)
{
  /* Invalid cases include: 
   *   1. If the user program stack pointer is invalid when they make a syscall
   *   2. Arguments that are pointer may point to invalid address
   * All in all: Check every pointer including the original ESP!!!*/
  
  /* Get the thread*/
  struct thread* t = thread_current();
  /* Get the pagedir from pcb*/
  uint32_t* pd = t->pcb->pagedir;
  /* Check whether the virtual address is in user space*/
  if (!is_user_vaddr(uaddr))
    return false;  
  /* Get the kernel virtual address, return false if NULL(not mapped)*/
  if (!pagedir_get_page(pd, uaddr))
    return false;

  return true;
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  /* The esp in intr frame struct is save by the CPU while executing int 0x30 
   * instruction. So this esp points to the userprog stack. syscallx assembly 
   * has pushed the arguments and SYSCALL number on the user stack for us to
   * use here. Check for validity before use.*/
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  /* First make sure args[0] and args[0] + 4 is valid addresses*/
  bool syscall_num_valid = is_user_address_valid((void*)args) 
                         & is_user_address_valid((void*)args+4);

  /* Exit if not valid*/
  if (!syscall_num_valid)
    process_exit();

  /* Use switch case structure to save re-evaluation time*/
  switch(args[0])
  {
  case SYS_EXIT:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      process_exit();

    /* Signal exit semaphore in case parent waiting.*/
    struct thread * cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
         e = list_next(e))
    {
      struct process_info* p = list_entry(e, struct process_info, elem);
      if (p->pid == cur->tid)
      {
        /*Up the exit sema*/
        p->exit_status = args[1];
        sema_up(&(p->exit));
      }
    }
    /* Return exit status via eax*/
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
    break;

  case SYS_PRACTICE:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      process_exit();
    /*Inc the argument*/
    int32_t ret = args[1];
    ret++;
    /*Return the value*/
    f->eax = ret;
    break;

  case SYS_HALT:
    shutdown_power_off();
    NOT_REACHED();
    break;

  case SYS_EXEC:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      process_exit();
    /*Invoke the program and save return pid value*/
    f->eax = process_execute((char*)args[1]);
    struct thread* t = thread_current();
    sema_down(&(t->load_semaphore));

    /*If the program can't load or run for any reason, return -1*/
    if(!t->pcb->load_success)
      f->eax = -1;
    break;

  case SYS_WAIT:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      process_exit();
    int rtn = process_wait(args[0]);
    
    for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
         e = list_next(e))
    {
      struct process_info* p = list_entry(e, struct process_info, elem);
      if (p->parentPid == thread_current()->tid)
        /* Done with the node and free resources. If waited a second time 
         * will still return -1 simply b/c can't find the node*/
        free(p);
    }

    f->eax = rtn;

    break;

  default:
    /*Not supported yet, sorry. Can't offer you anything*/
    break;
  }
}
