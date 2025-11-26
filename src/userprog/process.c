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
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
extern struct lock filesys_lock;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *cmd_line_copy; // start_process에 전달할 원본 명령어 복사본
  char *parsing_copy;  // strtok_r로 파싱할 복사본
  char *prog_name;     // 파싱된 프로그램 이름
  char *save_ptr;      // strtok_r 상태 저장용 포인터
  tid_t tid;

  /* Make a copy of FILE_NAME for parsing and another for start_process.
     Otherwise there's a race between the caller and load(). */
  // 원본 보존용 복사본 생성
  cmd_line_copy = palloc_get_page (0);
  if (cmd_line_copy == NULL)
    return TID_ERROR;
  strlcpy (cmd_line_copy, file_name, PGSIZE);

  // 파싱용 복사본 생성
  parsing_copy = palloc_get_page (0);
  if (parsing_copy == NULL) 
    {
      palloc_free_page (cmd_line_copy); // 앞에서 할당한 것도 해제
      return TID_ERROR;
    }
  strlcpy (parsing_copy, file_name, PGSIZE);

  /* Extract the program name using strtok_r. */
  // 프로그램 이름 파싱
  prog_name = strtok_r (parsing_copy, " ", &save_ptr);
  if (prog_name == NULL) // 빈 문자열이나 공백만 들어온 경우 처리
    {
      palloc_free_page (cmd_line_copy);
      palloc_free_page (parsing_copy);
      return TID_ERROR;
    }

  /* Create a new thread to execute the program.
     Pass the extracted program name as the thread name,
     and the original command line copy as the argument to start_process. */
  // 수정된 인자로 스레드 생성
  tid = thread_create (prog_name, PRI_DEFAULT, start_process, cmd_line_copy);

  /* Free the parsing copy, it's no longer needed. */
  // 파싱용 복사본 해제
  palloc_free_page (parsing_copy);

  // 스레드 생성 실패 시 원본 복사본도 해제
  if (tid == TID_ERROR)
    {
      /* If thread_create failed, free the command line copy too. */
      palloc_free_page (cmd_line_copy); 
    }
    
  return tid;
}

struct child_process *
process_get_child_by_tid (tid_t child_tid)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->child_list); e != list_end (&cur->child_list);
       e = list_next (e))
    {
      struct child_process *cp = list_entry (e, struct child_process, elem);
      if (cp->tid == child_tid)
        {
          return cp;
        }
    }
  
  return NULL;
}

/* A thread function that loads a user process and starts it running. */
static void
start_process (void *command_line_) // Renamed parameter for clarity
{
  char *command_line = command_line_; // Original command line copy from process_execute aux
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current ();
  struct child_process *cp = cur->child_info;

#ifdef VM
  // VM: SPT 초기화
  vm_init (&cur->vm);
  // mmap 리스트 초기화
  list_init (&cur->mmap_list);
  cur->next_mapid = 1;
#endif

  if (cur->fd_table == NULL)
    {
      cur->fd_table = palloc_get_page (PAL_ZERO);
      if (cur->fd_table == NULL)
        {
          if (cp != NULL)
            {
              cp->load_success = false;
              sema_up (&cp->load_sema);
            }
          palloc_free_page (command_line);
          thread_exit ();
        }
      cur->fd_max = 2;
    }

  /* === Argument Parsing Logic Added === */
  char *token, *save_ptr;
  int argc = 0;
  char **argv = NULL; // Dynamic allocation for argv

  // Count arguments first using a temporary copy
  char *count_copy = palloc_get_page(0); 
  if (count_copy == NULL) {
      palloc_free_page(command_line); // Free the original copy passed from process_execute
      thread_exit(); 
  }
  strlcpy(count_copy, command_line, PGSIZE);
  for (token = strtok_r (count_copy, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr)) {
      argc++;
  }
  palloc_free_page(count_copy); // Free the counting copy

  // Allocate argv array dynamically
  argv = (char **)malloc(sizeof(char *) * argc); 
  if (argv == NULL) {
      palloc_free_page(command_line);
      thread_exit();
  }

  // Populate argv using another temporary copy for parsing
  int current_arg = 0;
  char *parse_copy = palloc_get_page(0); 
  if (parse_copy == NULL) {
      free(argv); // Free argv if allocation fails
      palloc_free_page(command_line);
      thread_exit();
  }
  strlcpy(parse_copy, command_line, PGSIZE);
  for (token = strtok_r (parse_copy, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr)) {
      argv[current_arg++] = token;
  }
  char *prog_name = argv[0]; // Program name is the first token
  /* === Argument Parsing Logic Ends === */


  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  // Load using the parsed program name (argv[0])
  success = load (prog_name, &if_.eip, &if_.esp);

  if (cp != NULL)
    {
      cp->load_success = success;
      sema_up (&cp->load_sema);
    }

  /* === Stack Construction Logic Added === */
  // If load succeeds, construct the user stack
  if (success) 
    {
      construct_user_stack(argc, argv, &if_.esp);
    }
  /* === Stack Construction Logic Ends === */

  /* Free resources used for parsing before jumping to user space */
  free(argv);             // Free the dynamically allocated argv array
  palloc_free_page(parse_copy); // Free the copy used for parsing argv
  palloc_free_page (command_line); // Free the original command line copy passed from process_execute


  /* If load failed, quit. */
  // Moved the check after freeing resources, before jumping
  if (!success) {
      cur->fd_max = 0;
      if (cur->fd_table != NULL)
        {
          palloc_free_page (cur->fd_table);
          cur->fd_table = NULL;
        }
      thread_exit (); 
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Constructs the user stack according to the x86 calling convention. */
void
construct_user_stack(int argc, char **argv, void **esp) 
{
    // Temporary storage for stack addresses of the copied argument strings
    char *arg_addresses[argc]; 
    int i;
    size_t total_arg_len = 0; // Keep track for potential debugging or future use

    // 1. Push argument strings onto the stack (from high address to low address)
    //    and store their addresses.
    for (i = 0; i < argc; i++) {
        size_t arg_len = strlen(argv[i]) + 1; // Length including null terminator
        *esp -= arg_len;
        memcpy(*esp, argv[i], arg_len);   // Copy string to stack
        arg_addresses[i] = *esp;          // Save the stack address of this string
        total_arg_len += arg_len;
    }

    // 2. Word Align: Align the stack pointer to a multiple of 4 bytes.
    int padding = (uintptr_t)*esp % 4;
    if (padding != 0) {
        *esp -= padding;                // Decrement stack pointer by padding amount
        memset(*esp, 0, padding);       // Fill padding space with zeros
    }

    // 3. Push argument addresses (in reverse order onto the stack)
    // Push null sentinel (argv[argc]) first
    *esp -= sizeof(char *);             // Make space for the null pointer
    **(char ***)esp = NULL;              // Write the null pointer

    // Push addresses of the actual argument strings (argv[argc-1] down to argv[0])
    for (i = argc - 1; i >= 0; i--) {
        *esp -= sizeof(char *);             // Make space for the pointer
        **(char ***)esp = arg_addresses[i]; // Write the string address
    }

    // 4. Push argv (the address of argv[0] on the stack) and argc
    char **argv_on_stack = (char **)*esp; // This is where argv[0]'s pointer resides
    *esp -= sizeof(char **);            // Make space for the argv pointer itself
    **(char ****)esp = argv_on_stack;     // Write the address of argv[0] on stack

    *esp -= sizeof(int);                // Make space for argc
    **(int **)esp = argc;               // Write the argument count

    // 5. Push fake return address (required by calling convention)
    *esp -= sizeof(void *);             // Make space for the return address
    **(void ***)esp = NULL;              // Write NULL as the fake return address
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct child_process *cp = process_get_child_by_tid (child_tid);

  if (cp == NULL)
    return -1;

  if (cp->wait_called)
    return -1;

  cp->wait_called = true;

  if (!cp->exited)
    sema_down (&cp->wait_sema);

  int exit_status = cp->exit_status;
  list_remove (&cp->elem);
  cp->parent_alive = false;
  free (cp);
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct list_elem *e;

  if (cur->cur_file != NULL)
    {
      lock_acquire (&filesys_lock);
      file_allow_write (cur->cur_file);
      file_close (cur->cur_file);
      lock_release (&filesys_lock);
      cur->cur_file = NULL;
    }

  if (cur->fd_table != NULL)
    {
      for (int i = 2; i < cur->fd_max; i++) 
        {
          close (i);
        }
      palloc_free_page (cur->fd_table);
      cur->fd_table = NULL;
    }
  cur->fd_max = 0;

#ifdef VM
  // 1. mmap 파일 정리 (Dirty Page 파일 기록 수행)
  munmap_all ();
  
  // 2. SPT 파괴 (해시 테이블 순회하며 각 vm_entry 삭제)
  vm_destroy (&cur->vm);
#endif

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  while (!list_empty (&cur->child_list))
    {
      e = list_pop_front (&cur->child_list);
      struct child_process *cp = list_entry (e, struct child_process, elem);
      cp->parent_alive = false;
      if (cp->exited)
        free (cp);
      else
        cp->wait_called = true;
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  bool filesys_lock_held = false;
  bool exec_file_locked = false;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file under filesystem lock. */
  lock_acquire (&filesys_lock);
  filesys_lock_held = true;
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  file_deny_write (file);
  exec_file_locked = true;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
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
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  t->cur_file = file;
  file = NULL;

 done:
  /* We arrive here whether the load is successful or not. */
  if (file != NULL)
    {
      if (exec_file_locked)
        file_allow_write (file);
      file_close (file);
    }
  if (filesys_lock_held)
    lock_release (&filesys_lock);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
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
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

#ifdef VM
  // Lazy Loading: 실제 데이터를 로드하지 않고 메타데이터만 SPT에 등록
  off_t current_ofs = ofs;
  
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      // Calculate how to fill this page.
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      // vm_entry 생성 및 초기화
      struct vm_entry *vme = malloc (sizeof (struct vm_entry));
      if (vme == NULL)
        return false;

      vme->type = VM_BIN;
      vme->vaddr = upage;
      vme->writable = writable;
      vme->is_loaded = false;     // 아직 로드되지 않음
      vme->file = file;           // file 객체는 process_exit 전까지 닫으면 안 됨
      vme->offset = current_ofs;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      vme->swap_slot = SWAP_ERROR;

      // SPT에 등록
      if (!insert_vme (&thread_current ()->vm, vme))
        {
          free (vme);
          return false;
        }

      // Advance
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      current_ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;

#else
  // Original implementation without VM
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
#endif
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
#ifdef VM
  void *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  
  // vm_entry 생성 및 초기화 (스택은 VM_ANON 타입)
  struct vm_entry *vme = malloc (sizeof (struct vm_entry));
  if (vme == NULL)
    return false;

  vme->type = VM_ANON;
  vme->vaddr = upage;
  vme->writable = true;
  vme->is_loaded = true;    // 스택은 바로 로드됨
  vme->file = NULL;
  vme->offset = 0;
  vme->read_bytes = 0;
  vme->zero_bytes = PGSIZE;
  vme->swap_slot = SWAP_ERROR;

  // 물리 프레임 할당
  void *kpage = frame_allocate (PAL_ZERO, vme);
  if (kpage == NULL)
    {
      free (vme);
      return false;
    }

  // 페이지 테이블에 매핑
  if (!install_page (upage, kpage, true))
    {
      frame_free (kpage);
      free (vme);
      return false;
    }

  // SPT에 등록
  if (!insert_vme (&thread_current ()->vm, vme))
    {
      frame_free (kpage);
      free (vme);
      return false;
    }

  // 스택은 바로 사용되므로 pinned를 false로 설정
  frame_pin_allocate (kpage, false);

  *esp = PHYS_BASE;
  return true;

#else
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
#endif
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
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
