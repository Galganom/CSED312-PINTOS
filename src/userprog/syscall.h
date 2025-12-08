#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include "threads/synch.h"

typedef int pid_t;
typedef int mapid_t;

void syscall_init (void);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t user_exec (const char *file);
int user_wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

#ifdef VM
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapid);
void munmap_all (void);
#endif

extern struct lock filesys_lock;

void is_valid_addr(void *addr);
void read_esp(void *esp, int *data, int count);
struct file *process_get_file(int fd);

#endif
