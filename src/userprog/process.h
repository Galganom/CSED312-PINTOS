#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdbool.h>
#include "threads/thread.h"
#include "threads/synch.h"

/* Per-child bookkeeping shared between parent and child. */
struct child_process
  {
    tid_t tid;                      /* Child thread id. */
    int exit_status;                /* Reported exit status. */
    bool exited;                    /* True once child has exited. */
    bool wait_called;               /* True if parent already waited. */
    bool parent_alive;              /* Parent still around to reap. */
    bool load_success;              /* Result of load() for exec sync. */
    struct semaphore wait_sema;     /* Signals when child exits. */
    struct semaphore load_sema;     /* Signals when load completes. */
    struct list_elem elem;          /* Link in parent's child_list. */
  };

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct child_process *process_get_child_by_tid (tid_t child_tid);

#endif /* userprog/process.h */
