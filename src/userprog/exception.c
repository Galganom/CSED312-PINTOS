#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#endif

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */

#ifdef VM
// 스택 확장을 수행하는 헬퍼 함수
static bool
stack_growth (void *fault_addr)
{
  void *upage = pg_round_down (fault_addr);
  
  // 스택 제한 검사 (8MB)
  if (upage < (void *)(PHYS_BASE - (1 << 23))) // 8MB = 2^23
    return false;

  // vm_entry 생성 (type = VM_ANON)
  struct vm_entry *vme = malloc (sizeof (struct vm_entry));
  if (vme == NULL)
    return false;

  vme->type = VM_ANON;
  vme->vaddr = upage;
  vme->writable = true;
  vme->is_loaded = true;
  vme->file = NULL;
  vme->offset = 0;
  vme->read_bytes = 0;
  vme->zero_bytes = PGSIZE;
  vme->swap_slot = SWAP_ERROR;

  // 물리 프레임 할당 (0으로 초기화)
  void *kaddr = frame_allocate (PAL_ZERO, vme);
  if (kaddr == NULL)
    {
      free (vme);
      return false;
    }

  // 페이지 테이블에 매핑
  if (!pagedir_set_page (thread_current ()->pagedir, upage, kaddr, true))
    {
      frame_free (kaddr);
      free (vme);
      return false;
    }

  // SPT에 등록
  if (!insert_vme (&thread_current ()->vm, vme))
    {
      pagedir_clear_page (thread_current ()->pagedir, upage);
      frame_free (kaddr);
      free (vme);
      return false;
    }

  // 스택은 바로 사용되므로 pin 해제
  frame_pin_allocate (kaddr, false);

  return true;
}

// 페이지 폴트를 처리하는 핵심 함수
bool
handle_mm_fault (struct vm_entry *vme)
{
  // 물리 프레임 할당 요청
  // frame_allocate 내부에서 pinned=true 상태로 프레임이 반환됨
  void *kaddr = frame_allocate (PAL_USER, vme);
  if (kaddr == NULL)
    return false;

  // 데이터 로딩 (Type별 분기)
  bool success = false;
  switch (vme->type)
    {
    case VM_BIN:
    case VM_FILE:
      // 파일에서 읽어오기
      success = load_file (kaddr, vme);
      break;
    case VM_ANON:
      // 스왑 디스크에서 읽어오기
      data_in (vme->swap_slot, kaddr);
      success = true;
      break;
    default:
      success = false;
    }

  if (!success)
    {
      frame_free (kaddr);
      return false;
    }

  // 페이지 테이블 매핑 및 상태 업데이트
  if (!pagedir_set_page (thread_current ()->pagedir, vme->vaddr, kaddr, vme->writable))
    {
      frame_free (kaddr);
      return false;
    }
  vme->is_loaded = true;

  // 로딩이 완료되었으므로 Pin을 해제하여 Eviction이 가능하게 함
  frame_pin_allocate (kaddr, false);

  return true;
}
#endif

static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

#ifdef VM
  // VM: Page Fault Handler Logic
  
  bool vm_success = false;

  // 1. 유효성 검사
  if (is_user_vaddr (fault_addr))
    {
      // 2. SPT 조회
      struct vm_entry *vme = find_vme (fault_addr);

      // 3. Stack Growth 처리 (vme가 없는 경우)
      if (vme == NULL)
        {
          // 커널 모드에서의 page fault는 f->esp가 아닌 스레드의 esp 사용
          void *esp = user ? f->esp : thread_current ()->stack;
          
          /* Stack Pointer(esp) 기준 32바이트(PUSH 명령어) 이내이고,
             유효한 스택 영역인 경우 */
          if (fault_addr >= esp - 32 && fault_addr < PHYS_BASE)
            {
              if (stack_growth (fault_addr))
                return; // 성공적으로 스택 확장
            }
          // SPT에도 없고 스택 확장도 아니면 잘못된 접근
        }
      // 4. 읽기 전용 페이지에 쓰기 시도 검사
      else if (write && !vme->writable)
        {
          // 읽기 전용 페이지에 쓰기 시도 - 실패 처리
        }
      // 5. Page Fault 처리 (Lazy Loading 수행)
      else if (handle_mm_fault (vme))
        {
          vm_success = true;
        }
    }

  if (vm_success)
    return; // 성공
#endif

  // 페이지 폴트가 사용자 모드에서 발생했을때 처리
  if (user)
    {
      // userprog의 잘못된 메모리에 접근시 처리
      // syscall.c에 구현한 exit(-1)과 동일한 동작

      // 1. 종료 상태를 -1로 기록합니다.
      struct thread *cur = thread_current ();
      cur->process_exit_status = -1;
      
      // 2. 요구사항에 따라 종료 메시지를 출력합니다.
      printf ("%s: exit(%d)\n", cur->name, -1);
      
      // 3. 스레드(프로세스)를 종료합니다.
      thread_exit ();
    }
  else
    {
      /* To implement virtual memory, delete the rest of the function
         body, and replace it with code that brings in the page to
         which fault_addr refers. */
      printf ("Page fault at %p: %s error %s page in %s context.\n",
               fault_addr,
               not_present ? "not present" : "rights violation",
               write ? "writing" : "reading",
               user ? "user" : "kernel");
      kill (f);
    }
}
