#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <string.h>

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
}

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

void up_sema_and_exit(void);
void up_sema_and_exit(void)
{
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
      p->exit_status = -1;
      sema_up(&(p->exit));
    }
  }
  /* Return exit status via eax*/
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
  process_exit();
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
    up_sema_and_exit();

  struct thread* t = thread_current();
  struct list_elem *e;

  /* Use switch case structure to save re-evaluation time*/
  switch(args[0])
  {
  case SYS_EXIT:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      up_sema_and_exit();

    /* Signal exit semaphore in case parent waiting.*/
    struct thread * cur = thread_current();
    for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
         e = list_next(e))
    {
      struct process_info* p = list_entry(e, struct process_info, elem);
      if (p->pid == cur->tid)
      {
        p->exit_status = args[1];
        sema_up(&(p->exit));
        break;
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
      up_sema_and_exit();
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
    if (!is_user_address_valid((void*)args+8) || !is_user_address_valid((void*)args[1])
        || !is_user_address_valid((void*)(args[1]+4)))
      up_sema_and_exit();
    /*Invoke the program and save return pid value*/
    f->eax = process_execute((char*)args[1]);
    
    /* Find the correct load sema and see if child has been loaded*/
    for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
         e = list_next(e))
    {
      struct process_info* p = list_entry(e, struct process_info, elem);
      if (p->pid == (uint8_t)f->eax)
      {
        sema_down(&(p->load_semaphore));
        /*If the program can't load or run for any reason, return -1*/
        if(!p->load_success)
          f->eax = -1;
        break;
      }
    }

    break;

  case SYS_WAIT:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      up_sema_and_exit();
    int rtn = process_wait(args[1]);
    
    for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
         e = list_next(e))
    {
      struct process_info* p = list_entry(e, struct process_info, elem);
      if (p->parentPid == thread_current()->tid)
      {
        /* Done with the node and free resources. If waited a second time 
         * will still return -1 simply b/c can't find the node*/
        (void)list_remove(&(p->elem));
        free(p);
        break;
      }
    }

    f->eax = rtn;

    break;

  /*File Operation syscalls starts from here */
  case SYS_CREATE:
    /* syscall2(NUMBER, ARG0, ARG1)*/
    if (!is_user_address_valid((void*)args+8) || !is_user_address_valid((void*)args+12)
        || !is_user_address_valid((void*)args[1]) || !is_user_address_valid((void*)(args[1]+4)))
      up_sema_and_exit();
    
    sema_down(&filesys);
    f->eax = filesys_create((char*)args[1], (unsigned)args[2]);
    sema_up(&filesys);
    break;

  case SYS_REMOVE:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8) || !is_user_address_valid((void*)args[1])
        || !is_user_address_valid((void*)(args[1]+4)))
      up_sema_and_exit();

    sema_down(&filesys);
    f->eax = filesys_remove((char*)args[1]);
    sema_up(&filesys);
    break;

  case SYS_OPEN:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8) || !is_user_address_valid((void*)args[1])
        || !is_user_address_valid((void*)(args[1]+4)))
      up_sema_and_exit();
    
    static fd_t i = 2; // File Descriptor starts from 2 since 0 and 1 are occupied

    /* Open the file from the filesys*/
    sema_down(&filesys);
    struct file* fp = filesys_open((char*)args[1]);
    sema_up(&filesys);

    /* Create a file descriptor node and add it to the list */
    struct file_descriptor* fd = (struct file_descriptor*)malloc(sizeof(struct file_descriptor));

    if (fp)
    {
      fd->file = fp;
      fd->fd = i;
      f->eax = i;
      i++;
      list_push_front(t->pcb->file_descriptor_list, &(fd->elem));
    }
    else
    {
      f->eax = -1;
    }
    
    break;

  case SYS_CLOSE:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      up_sema_and_exit();

    /* Find the file descriptor node*/
    for (e = list_begin(t->pcb->file_descriptor_list); e != list_end(t->pcb->file_descriptor_list);
         e = list_next(e))
    {
      struct file_descriptor* p = list_entry(e, struct file_descriptor, elem);
      if (p->fd == (fd_t)args[1])
      {
        file_close(p->file);
        (void)list_remove(&(p->elem));
        free(p);
        break;
      }
    }

    break;

  case SYS_FILESIZE:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      up_sema_and_exit();

    /* Default return*/
    f->eax = -1;

    /* Find the file descriptor node*/
    for (e = list_begin(t->pcb->file_descriptor_list); e != list_end(t->pcb->file_descriptor_list);
         e = list_next(e))
    {
      struct file_descriptor* p = list_entry(e, struct file_descriptor, elem);
      if (p->fd == (fd_t)args[1])
      {
        /* Return the filesize*/
        sema_down(&filesys);
        f->eax = file_length(p->file);
        sema_up(&filesys);
        break;
      }
    }

    break;

  case SYS_READ:
    /* syscall3(NUMBER, ARG0, ARG1, ARG2)*/
    if (!is_user_address_valid((void*)args+8) || !is_user_address_valid((void*)args+12) 
        || (!is_user_address_valid((void*)args+16)) || !is_user_address_valid((void*)args[2])
        || !is_user_address_valid((void*)(args[2]+4)))
      up_sema_and_exit();

    /* Check if it is STDIN*/
    if (args[1] == STDIN_FILENO)
    {
      char* ptr = (char*)args[2];
      for (uint8_t i = 0; i < args[3]; i++)
      {
        *ptr = input_getc();
        ptr++;
      }
      f->eax = args[3];
    }
    else
    {
      /* Default return error*/
      f->eax = -1;
      /* Find the file descriptor node*/
      for (e = list_begin(t->pcb->file_descriptor_list); e != list_end(t->pcb->file_descriptor_list);
           e = list_next(e))
      {
        struct file_descriptor* p = list_entry(e, struct file_descriptor, elem);
        if (p->fd == (fd_t)args[1])
        {
          sema_down(&filesys);
          f->eax = file_read(p->file, (char*)args[2], args[3]);
          sema_up(&filesys);
          break;
        }
      }
    }
    
    break;

  case SYS_WRITE:
    /* syscall3(NUMBER, ARG0, ARG1, ARG2)*/
    if (!is_user_address_valid((void*)args+8) || !is_user_address_valid((void*)args+12) 
        || (!is_user_address_valid((void*)args+16)) || !is_user_address_valid((void*)args[2])
        || !is_user_address_valid((void*)(args[2]+4)))
      up_sema_and_exit();

    /* Check if it is STDOUT*/
    if (args[1] == STDOUT_FILENO)
    {
      putbuf((char*)args[2], args[3]);
      f->eax = args[3];
    }
    else
    {
      /* Default return error*/
      f->eax = -1;
      /* Find the file descriptor node*/
      for (e = list_begin(t->pcb->file_descriptor_list); e != list_end(t->pcb->file_descriptor_list);
           e = list_next(e))
      {
        struct file_descriptor* p = list_entry(e, struct file_descriptor, elem);
        if (p->fd == (fd_t)args[1])
        {
          sema_down(&filesys);
          f->eax = file_write(p->file, (char*)args[2], args[3]);
          sema_up(&filesys);
          break;
        }
      }
    }
    break;

  case SYS_SEEK:
    /* syscall2(NUMBER, ARG0, ARG1)*/
    if (!is_user_address_valid((void*)args+8) || !is_user_address_valid((void*)args+12))
      up_sema_and_exit();

    /* Find the file descriptor node*/
    for (e = list_begin(t->pcb->file_descriptor_list); e != list_end(t->pcb->file_descriptor_list);
         e = list_next(e))
    {
      struct file_descriptor* p = list_entry(e, struct file_descriptor, elem);
      if (p->fd == (fd_t)args[1])
      {
        sema_down(&filesys);
        file_seek(p->file, args[2]);
        sema_up(&filesys);
        break;
      }
    }

    break;

  case SYS_TELL:
    /* syscall1(NUMBER, ARG0)*/
    if (!is_user_address_valid((void*)args+8))
      up_sema_and_exit();

    /* Find the file descriptor node*/
    for (e = list_begin(t->pcb->file_descriptor_list); e != list_end(t->pcb->file_descriptor_list);
         e = list_next(e))
    {
      struct file_descriptor* p = list_entry(e, struct file_descriptor, elem);
      if (p->fd == (fd_t)args[1])
      {
        sema_down(&filesys);
        file_tell(p->file);
        sema_up(&filesys);
        break;
      }
    }

    break;

  default:
    /*Not supported yet, sorry. Can't offer you anything*/
    break;
  }
}
