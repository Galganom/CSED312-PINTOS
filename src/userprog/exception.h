#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

void exception_init (void);
void exception_print_stats (void);

#ifdef VM
#include "vm/page.h"
// Page Fault 처리 함수 (Lazy Loading 수행) - syscall에서도 사용
bool handle_mm_fault (struct vm_entry *vme);
#endif

#endif /* userprog/exception.h */
