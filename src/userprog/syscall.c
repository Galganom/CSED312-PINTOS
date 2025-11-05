#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include <string.h>

typedef int pid_t;
unsigned tell(int fd);
bool remove(const char* file);
bool create(const char* file, unsigned initial_size);
// void exit (int status);

static void syscall_handler (struct intr_frame *);
struct lock filesys_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) {
	is_valid_addr((void *)(f->esp));
	for (int i = 0; i < 3; i++) 
    	is_valid_addr(f->esp + 4*i);

	int argv[3];
	switch(*(uint32_t *)(f->esp)) {
		case SYS_HALT:
			shutdown_power_off();
			break;
		case SYS_EXIT:
			get_argument(f->esp+4, argv, 1);
			exit((int)argv[0]);
			break;
		case SYS_EXEC:
			get_argument(f->esp+4, argv, 1);
			f->eax = user_exec((const char*)argv[0]);
			break;
		case SYS_WAIT:
			get_argument(f->esp+4, argv, 1);
			f->eax = user_wait((pid_t)argv[0]);
			break;
		case SYS_CREATE:
			get_argument(f->esp+4, argv, 2);
			f->eax = create((const char*)argv[0], (unsigned)argv[1]);
			break;
		case SYS_REMOVE:
			get_argument(f->esp+4, argv, 1);
			f->eax = remove((const char*)argv[0]);
			break;
		case SYS_OPEN:
			get_argument(f->esp+4, argv, 1);
			f->eax = open((const char*)argv[0]);
			break;
		case SYS_FILESIZE:
			get_argument(f->esp+4, argv, 1);
			f->eax = filesize((int)argv[0]);
			break;
		case SYS_READ:
			get_argument(f->esp+4, argv, 3);
			f->eax = read((int)argv[0], (void *)argv[1], (unsigned)argv[2]);
			break;
		case SYS_WRITE:
			get_argument(f->esp+4, argv, 3);
			f->eax = write((int)argv[0], (const void *)argv[1], (unsigned)argv[2]);
			break;
		case SYS_SEEK:
			get_argument(f->esp+4, argv, 2);
			seek((int)argv[0], (unsigned)argv[1]);
			break;
		case SYS_TELL:
			get_argument(f->esp+4, argv, 1);
			f->eax = tell((int)argv[0]);
			break;
		case SYS_CLOSE:
			get_argument(f->esp+4, argv, 1);
			close((int)argv[0]);
			break;
		default:
			exit(-1);
	}
}

void is_valid_addr(void *addr) {
	// 주소가 NULL 이거나 유저영역의 주소가 아니거나 페이지가 존재하지 않음
	if (!addr || !is_user_vaddr(addr) || !pagedir_get_page(thread_current()->pagedir, addr))
		exit(-1);
}

void get_argument(void *esp, int *arg, int count) {
	int i;
	void* arg_pos;
	for (i=0; i<count; i++) {
		arg_pos=esp + 4*i;
		is_valid_addr(arg_pos);
		arg[i] = *(int*)(arg_pos);
	}
}

bool create(const char* file, unsigned initial_size)
{ 
  // initial_size 크기의 파일을 생성, 열지는 않음
  is_valid_addr((void*)file);
  if(!file)
  {
    exit(-1);
  }
  return filesys_create(file, initial_size);
}

bool remove(const char* file)
{
  // 단순 삭제
  return filesys_remove(file);
}

struct file *process_get_file(int fd)
{
  struct file *f;

  if( (fd > 1) && (fd < thread_current()->fd_max) )
  {
    f = thread_current()->fd_table[fd];
    return f;
  }
  return NULL; 
}

int filesize (int fd)
{
  // 파일 크기 반환 (file descriptor값 입력 받음)
  struct file* f;
  f = process_get_file(fd);
  if(f)
  {
    return file_length(f);
  }
  return -1;
}

void seek (int fd, unsigned position)
{
  /* 
  Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. 
  (Thus, a position of 0 is the file’s start.)
  A seek past the current end of a file is not an error. 
  A later read obtains 0 bytes, indicating end of file.
  A later write extends the file, filling any unwritten gap with zeros.
  (However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.)
  These semantics are implemented in the file system and do not require any special effort in system call implementation.
  */
  struct file* f = process_get_file(fd);
  ASSERT(f != NULL);
  file_seek(f, position);
}

unsigned tell (int fd)
{
  /* Returns the position of the next byte to be read or written in open file fd, expressed
  in bytes from the beginning of the file. */
  struct file *f = process_get_file(fd);
  if (f)
  {
    return file_tell(f);
  }
  else
  {
    return -1;
  }
}

int open (const char *file)
{
  /* Opens the file called file.
  Returns a nonnegative integer handle called a “file descriptor” (fd), or -1 if the file could not be opened.

  Each process has an independent set of file descriptors.
  File descriptors are not inherited by child processes.
  
  When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor.
  Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position.
  */
 int fd;
 struct file* f;
 struct thread* cur;

 is_valid_addr((void*)file);

 f = filesys_open(file);
 if(f==NULL)
 {
  return -1;
 }

 /* deny write */
 if(!strcmp(thread_current()->name, file))
 {
  file_deny_write(f);
 }
 
 /* add file to process */ 
 cur = thread_current();
 fd = cur->fd_max;

 cur->fd_table[fd] = f;
 cur->fd_max++;

 return fd;
}

void close (int fd)
{
  /* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open
  file descriptors, as if by calling this function for each one. */
  struct file *f = process_get_file(fd);
  if(f)
  {
    if((fd>1) && (fd<thread_current()->fd_max))
    {
      file_close(f);
      thread_current()->fd_table[fd] = NULL;
    }
  }
}

int read (int fd, void *buffer, unsigned size)
{
 /* Reads size bytes from the file open as fd into buffer. 
  Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file).
  Fd 0 reads from the keyboard using input_getc(). */
  int bytes_read=0;
  struct file *f;
  unsigned i;
  for (i = 0; i < size; i++)
    is_valid_addr(buffer+i);

  if(fd==0)
  {
    for (i = 0; i < size;i++)
    {
      ((char*)buffer)[i]=input_getc();
      if(((char*)buffer)[i] == '\0')
      {
        break;
      }
      bytes_read = i;
    }
  }
  else if(fd > 0)
  {
    f = process_get_file(fd);
    if(!f)
    {
      return -1;
    }
    lock_acquire(&filesys_lock);
    bytes_read = file_read(f, buffer, size);
    lock_release(&filesys_lock);
  }
  return bytes_read;
}

int write (int fd, const void *buffer, unsigned size)
{
  /* Writes size bytes from buffer to the open file fd.
  Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
  
  The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written,
  or 0 if no bytes could be written at all.
  
  Fd 1 writes to the console -> should write all of buffer in one call to putbuf()
  */
  
 int bytes_write = 0;
 struct file* f;
 unsigned i;
  for (i = 0; i < size; i++)
    is_valid_addr(buffer+i);

 if(fd == 1)
 {
  lock_acquire(&filesys_lock);
  putbuf(buffer, size);
  lock_release(&filesys_lock);
  return size;
 }
 else if(fd > 1)
 {
  f = process_get_file(fd);
    if(!f)
    {
      return -1;
    }
    lock_acquire(&filesys_lock);
    bytes_write = file_write(f, buffer, size);
    lock_release(&filesys_lock);
 }
 return bytes_write;

}

//-----------------------형찬---------------------------------
tid_t
user_exec (const char *cmd_line)
{
  tid_t tid;
  struct thread *child_thread;

  //  자식 프로세스(스레드) 생성 요청 (process.c의 함수 호출)
  tid = process_execute (cmd_line);

  // 스레드 생성 실패 시 (TID_ERROR) 즉시 -1 반환
  if (tid == TID_ERROR)
    {
      return -1;
    }
  
  child_thread = process_get_child_by_tid (tid); // 이 함수는 process.h에 선언되어있음
  
  //  자식을 찾을 수 없는 경우
  if (child_thread == NULL)
    {
      return -1; 
    }

  // 자식이 load()를 완료할 때까지 대기 (sema_load_complete가 'up'될 때까지)
  sema_down (&child_thread->sema_load_complete);

  // 자식의 load 성공 여부 확인
  if (child_thread->load_success == true)
    {
      // 성공 시, 자식의 TID 반환
      return tid;
    }
  else
    {
      // 실패 시, -1 반환
      // (이때 실패한 자식 스레드는 start_process에서 스스로 thread_exit()함)
      return -1;
    }
}

int
user_wait (pid_t pid)
{
  // 실제 대기및 정리는 process_wait() 함수에 위임한다.
  return process_wait (pid);
}

void exit (int status)
{
  struct thread *cur = thread_current ();

  // 1. 현재 스레드의 종료 상태를 기록합니다. (부모가 wait에서 읽어갈 값)
  cur->process_exit_status = status;

  // 2. 요구사항에 따라 종료 메시지를 출력합니다.
  printf ("%s: exit(%d)\n", cur->name, status);

  // 3. 실제 스레드 종료 및 부모를 깨우는 절차를 시작합니다.
  thread_exit ();
}
