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

static void syscall_handler (struct intr_frame *);
struct lock filesys_lock;

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void syscall_handler (struct intr_frame *f UNUSED) {
	is_valid_addr((void *)(f->esp));
	for (int i = 0; i < 3; i++) 
    	is_valid_addr(f->esp + 4*i);

	int data[3];
	switch(*(uint32_t *)(f->esp)) {
		case SYS_HALT:
			shutdown_power_off();
			break;
		case SYS_EXIT:
			read_esp(f->esp+4, data, 1);
			exit((int)data[0]);
			break;
		case SYS_EXEC:
			read_esp(f->esp+4, data, 1);
			f->eax = user_exec((const char*)data[0]);
			break;
		case SYS_WAIT:
			read_esp(f->esp+4, data, 1);
			f->eax = user_wait((pid_t)data[0]);
			break;
		case SYS_CREATE:
			read_esp(f->esp+4, data, 2);
			f->eax = create((const char*)data[0], (unsigned)data[1]);
			break;
		case SYS_REMOVE:
			read_esp(f->esp+4, data, 1);
			f->eax = remove((const char*)data[0]);
			break;
		case SYS_OPEN:
			read_esp(f->esp+4, data, 1);
			f->eax = open((const char*)data[0]);
			break;
		case SYS_FILESIZE:
			read_esp(f->esp+4, data, 1);
			f->eax = filesize((int)data[0]);
			break;
		case SYS_READ:
			read_esp(f->esp+4, data, 3);
			f->eax = read((int)data[0], (void *)data[1], (unsigned)data[2]);
			break;
		case SYS_WRITE:
			read_esp(f->esp+4, data, 3);
			f->eax = write((int)data[0], (const void *)data[1], (unsigned)data[2]);
			break;
		case SYS_SEEK:
			read_esp(f->esp+4, data, 2);
			seek((int)data[0], (unsigned)data[1]);
			break;
		case SYS_TELL:
			read_esp(f->esp+4, data, 1);
			f->eax = tell((int)data[0]);
			break;
		case SYS_CLOSE:
			read_esp(f->esp+4, data, 1);
			close((int)data[0]);
			break;
		default:
			exit(-1);
	}
}

void read_esp(void *esp, int *data, int count) {
	
  void* pos;
  int i;
	for (i=0; i<count; i++) {
		pos = esp + 4*i;
		is_valid_addr(pos);
		data[i] = *(int*)(pos);
	}
}

void is_valid_addr(void *addr) {
	// 주소가 NULL 이거나 유저영역의 주소가 아니거나 페이지가 존재하지 않음
	if (!addr || !is_user_vaddr(addr) || !pagedir_get_page(thread_current()->pagedir, addr))
		exit(-1);
}

static void validate_string (const char *str) {
  // 포인터 주소 자체를 검사 (NULL 또는 커널 주소 등)
  // is_valid_addr는 실패 시 exit(-1)을 호출
  is_valid_addr((void *)str);

  // 문자열의 끝(\0)을 만날 때까지 모든 바이트를 검사
  // 페이지 경계를 넘어가는지(exec-bound-3) 확인
  int i = 0;
  while (true) {
    // (str + i) 주소가 유효한지 검사
    is_valid_addr((void *)(str + i));
    
    // 해당 주소에서 값을 읽어와 \0인지 확인
    if (*(str + i) == '\0') {
      break; // 문자열의 끝을 찾은 경우
    }
    i++;
  }
}

bool create(const char* file, unsigned initial_size) {
  // initial_size 크기의 파일을 생성, 열지는 않음
  is_valid_addr((void*)file);
  if(!file) exit(-1);
  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return success;
}

bool remove(const char* file) {
  is_valid_addr ((void *) file);
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);
  return success;
}

struct file *process_get_file(int fd) {
  struct file *f;

  if( (fd > 1) && (fd < thread_current()->fd_max)) {
    f = thread_current()->fd_table[fd];
    return f;
  }
  return NULL; 
}

int filesize (int fd) {
  // 파일 크기 반환 (file descriptor값 입력 받음)
  struct file* f;
  f = process_get_file(fd);
  if(f) {
    lock_acquire (&filesys_lock);
    int length = file_length (f);
    lock_release (&filesys_lock);
    return length;
  }
  return -1;
}

void seek (int fd, unsigned position) {
  // fd에 해당하는 파일의 현재 읽기/쓰기 위치를 옮기는 함수

  struct file* f = process_get_file(fd);
  ASSERT(f != NULL);
  lock_acquire (&filesys_lock);
  file_seek(f, position);
  lock_release (&filesys_lock);
}

unsigned tell (int fd) {
  // fd에 해당하는 파일의 현재 읽기/쓰기 위치를 알려주는 함수
  struct file *f = process_get_file(fd);
  if (f) {
    lock_acquire (&filesys_lock);
    unsigned position = file_tell (f);
    lock_release (&filesys_lock);
    return position;
  }
  else {
    return -1;
  }
}

int open (const char *file) {
  // file을 열고 해당 file의 fd를 반환함. file을 열 수 없을 땐 -1을 반환함
  // 각 프로세스는 fd table이 있음

  int fd;
  struct file* f;
  struct thread* cur;

  is_valid_addr((void*)file);

  lock_acquire (&filesys_lock);
  f = filesys_open(file);
  if(f==NULL) {
    lock_release (&filesys_lock);
    return -1;
  }

  // 열린 파일에 쓰기 방지
  if(!strcmp(thread_current()->name, file)) {
    file_deny_write(f);
  }
  lock_release (&filesys_lock);

  // 함수의 입력 *file을 현재 프로세스의 fd에 추가
  cur = thread_current();
  fd = cur->fd_max;

  cur->fd_table[fd] = f;
  cur->fd_max++;

  return fd;
}

void close (int fd) {
  // fd에 해당하는 파일을 닫고 fd를 NULL로 초기화함
  struct file *f = process_get_file(fd);
  if(f) {
    if((fd>1) && (fd < thread_current()->fd_max)) {
      lock_acquire (&filesys_lock);
      file_close(f);
      lock_release (&filesys_lock);
      thread_current()->fd_table[fd] = NULL;
    }
  }
}

int read (int fd, void *buffer, unsigned size) {
  // fd에 해당하는 파일을 최대 size byte 만큼 읽고 buffer에 채워넣음, 실제로 읽은 byte 수를 return함
  // return -1: 읽기 에러, 0: EOF, 1 이상: 해당 byte만큼 file을 읽음

  int bytes_read=0;
  struct file *f;
  unsigned i;

  for (i = 0; i < size; i++) {
    is_valid_addr(buffer+i);
  }

  if(fd==0) {
    for (i = 0; i < size;i++) {
      ((char*)buffer)[i]=input_getc();
      if(((char*)buffer)[i] == '\0')
        break;
      bytes_read = i;
    }
  }
  else if(fd > 0) {
    f = process_get_file(fd);
    if(!f)
      return -1;
    lock_acquire(&filesys_lock);
    bytes_read = file_read(f, buffer, size);
    lock_release(&filesys_lock);
  }
  return bytes_read;
}

int write (int fd, const void *buffer, unsigned size) {
  // fd에 해당하는 파일을 최대 size 만큼 쓰고, 실제로 쓰기를 한 byte 만큼 반환함
  
  int bytes_write = 0;
  struct file* f;
  unsigned i;

  for (i = 0; i < size; i++) {
    is_valid_addr(buffer+i);
  }

  if(fd == 1) {
    lock_acquire(&filesys_lock);
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }
  else if(fd > 1) {
    f = process_get_file(fd);
    if(!f)
      return -1;
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
  
  validate_string(cmd_line);
  
  tid_t tid;
  struct child_process *cp;

  //  자식 프로세스(스레드) 생성 요청 (process.c의 함수 호출)
  tid = process_execute (cmd_line);

  // 스레드 생성 실패 시 (TID_ERROR) 즉시 -1 반환
  if (tid == TID_ERROR)
    {
      return -1;
    }

  cp = process_get_child_by_tid (tid); // 이 함수는 process.h에 선언되어있음

  //  자식을 찾을 수 없는 경우
  if (cp == NULL)
    {
      return -1; 
    }

  // 자식이 load()를 완료할 때까지 대기 (load_sema가 'up'될 때까지)
  sema_down (&cp->load_sema);

  // 자식의 load 성공 여부 확인
  if (cp->load_success == true)
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
