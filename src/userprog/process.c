#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

struct list process_info_list;

static struct semaphore temporary;
struct semaphore filesys;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* prog_name, void (**eip)(void), void** esp, char* file_name);
bool setup_thread(void (**eip)(void), void** esp);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  sema_init(&filesys, 1);
  /* Initialize the system level lists*/
  list_init(&process_info_list);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy, *save_ptr, *fn_name, *fn_copy2;
  tid_t tid;
  enum intr_level old_level;

  sema_init(&temporary, 0);
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy  = palloc_get_page(PAL_ZERO);
  fn_copy2 = palloc_get_page(PAL_ZERO);

  if ((fn_copy == NULL)||(fn_copy2 == NULL))
  {
    if (fn_copy)
      palloc_free_page(fn_copy);

    if (fn_copy2)
      palloc_free_page(fn_copy2);

    return TID_ERROR;
  }

  strlcpy(fn_copy,  file_name, PGSIZE);
  strlcpy(fn_copy2, file_name, PGSIZE);

  /*Separate out function name*/
  fn_name = strtok_r(fn_copy, " ", &save_ptr);

  /* Disable interrupt b/c after thread creation it could run before
   * process_info is created. And process_info needs to be here since
   * we need the parent info*/
  old_level = intr_disable();

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(fn_name, PRI_DEFAULT, start_process, fn_copy2);

  /* fn_copy is only used for thread_create, so release it after use*/
  palloc_free_page(fn_copy);

  if (tid == TID_ERROR)
    palloc_free_page(fn_copy2);
  else
  {
    /* Thread created, add a node to the process_info_list*/
    struct process_info* p = (struct process_info*)malloc(sizeof(struct process_info));
    p->parentPid = thread_current()->tid;
    p->pid = tid;
    p->exit_status = -1;
    p->waited = false;
    sema_init(&(p->load_semaphore), 0); 
    sema_init(&(p->exit), 0);
    list_push_front(&process_info_list, &(p->elem));
  }
  /* Now you can interrupt me*/
  intr_set_level(old_level);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* file_name_) {
  char* file_name = (char*)file_name_;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;
  char* prog_name, *fn_copy, *save_ptr;
  struct list_elem *e;
 
  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /*Separate program name*/
  fn_copy = (char*)malloc(sizeof(char) * (strlen(file_name) + 1));
  if (fn_copy == NULL)
    success = false;
  strlcpy(fn_copy, file_name, PGSIZE);

  prog_name = strtok_r(fn_copy, " ", &save_ptr);

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    t->pcb->fd_track = 2;
    t->pcb->file_descriptor_list = (struct list*)malloc(sizeof(struct list));
    list_init(t->pcb->file_descriptor_list);
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    //uint8_t fpu_save[108];
    //asm volatile("finit; fsave (%0)": :"g"(&fpu_save));
    memcpy(&if_.fpu, fpu, 108);
    success = load(prog_name, &if_.eip, &if_.esp, file_name);
  }

  /*Log the success status in pcb(for exec to use)*/
  for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
       e = list_next(e))
  {
    struct process_info* p = list_entry(e, struct process_info, elem);
    /* Signal parent that child exited(if parent is waiting)*/
    if (t->tid == p->pid)
    {
      p->load_success = success;
      sema_up(&(p->load_semaphore));
      break;
    }
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    free(t->pcb->file_descriptor_list);
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  free(fn_copy);

  if (!success) {
    //sema_up(&temporary);

    for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
         e = list_next(e))
    {
      struct process_info* p = list_entry(e, struct process_info, elem);
      /* Signal parent that child exited(if parent is waiting)*/

      if (t->tid == p->pid)
      {
        /* Delete the node so that any wait will default to return -1 */
        (void)list_remove(&(p->elem));
        free(p);
        //p->exit_status = -1;
        //sema_up(&(p->exit));
        //sema_up(&(p->load_semaphore));
        break;
      }
    }
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid UNUSED) {
  // sema_down(&temporary);
  /* Find the corrent process_info node according to child_pid*/
  struct list_elem *e;
  struct thread* cur = thread_current(); 

  for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
       e = list_next(e))
  {
    struct process_info* p = list_entry(e, struct process_info, elem);
    if (child_pid == p->pid)
    {
      /* Check if the calling process is the parent of the child or it
       * has been waited*/
      if ((p->parentPid != cur->tid) || (p->waited))
      {
        return -1;
      }

      /* Wait for the child process to finish*/
      p->waited = true;
      sema_down(&(p->exit));
      return p->exit_status;
      break;
    }
  }
  return -1;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;
  struct list_elem* e;

  /*  Close the opened file and release deny write*/
  file_close(cur->pcb->file);

  /* Signal exit semaphore in case parent waiting*/
  

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Release any unclosed file descriptor, or will not pass multi-oom*/
  e = list_begin(cur->pcb->file_descriptor_list); 
  while(e != list_end(cur->pcb->file_descriptor_list))
  {
    struct file_descriptor* p = list_entry(e, struct file_descriptor, elem);
    e = list_next(e);
    file_close(p->file);
    (void)list_remove(&(p->elem));
    free(p);
  }
  free(cur->pcb->file_descriptor_list);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);

  //for (e = list_begin(&process_info_list); e != list_end(&process_info_list);
  //     e = list_next(e))
  //{
  //  struct process_info* p = list_entry(e, struct process_info, elem);
  //  if (p->pid == cur->tid)
  //  {
  //    sema_up(&(p->exit));
  //    break;
  //  }
  //}

  //sema_up(&temporary);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static void setup_call_stack(char* file_name, void **esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* prog_name, void (**eip)(void), void** esp, char* file_name) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  sema_down(&filesys);
  file = filesys_open(prog_name);
  sema_up(&filesys);
  t->pcb->file = file;
  if (file)
    file_deny_write(file);

  if (file == NULL) {
    printf("load: %s: open failed\n", prog_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", prog_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* solve page fault exception by pushing the required arguments to the user function.
   * initial fault happens at 0x08048996 mov 0xc(%ebp), %eax as presented in pregame.*/
  setup_call_stack(file_name, esp);

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/*Follow Program startup details and setup the stack for user program,
 * avoiding initial page fault from pregame project*/
static void setup_call_stack(char* file_name, void **esp) 
{
  char* argv[30] = {NULL};
  uint8_t i = 0U;
  char * token, *save_ptr;

  /* Push the userprog arguments into the calling stack first and gather their
   * location in argv[] array for later use*/
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; 
       token = strtok_r(NULL, " ", &save_ptr))
  {
    uint8_t size = strlen(token) * sizeof(char) + 1U; // NULL at the end
    *esp = *esp - size;
    strlcpy((char*)(*esp), token, size);
    argv[i] = (char*)(*esp);
    i++;
  }

  /* Calculate Stack alignment:
   * later we still need to push i + 1 char pointers, 1 pointer to char pointer 
   * and one int. So the total bytes needed is (i+1) * 4 + 4 + 4*/
  uint8_t align_byte = ((uint32_t)(*esp) - 4 * (i + 3U)) % 0x10;
  for(uint8_t j = 0; j < align_byte; j++)
  {
    *esp = *esp - 1;
    *(char*)*esp = 0; // cast to char* b/c want to set one byte at a time
  }

  /* Push argv[]*/
  for(int8_t j = i; j >= 0; j--)
  {
    *esp = *esp - 4;
    *(char**)*esp = argv[j]; // cast to pointer to any pointer(always 4 byte)
  }

  /* Push argv*/
  *esp = *esp - 4;
  *(char***)*esp = (char**)(*esp + 4);

  /*Push argc and return address*/
  *esp = *esp - 4;
  *(int*)*esp = i;
  *esp = *esp - 4;
  *(uint32_t*)*esp = 0;

}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
