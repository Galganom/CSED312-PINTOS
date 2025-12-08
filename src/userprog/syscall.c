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

#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "userprog/exception.h"
#include "threads/malloc.h"

// Buffer Pinning 헬퍼 함수 (Section 10)
static void pin_buffer (void *buffer, unsigned size, bool writable);
static void unpin_buffer (void *buffer, unsigned size);
static bool pin_page (void *upage, bool writable);
#endif

typedef int pid_t;
typedef int mapid_t;

unsigned tell(int fd);
bool remove(const char* file);
bool create(const char* file, unsigned initial_size);

#ifdef VM
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapid);
#endif

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
#ifdef VM
		case SYS_MMAP:
			read_esp(f->esp+4, data, 2);
			f->eax = mmap((int)data[0], (void *)data[1]);
			break;
		case SYS_MUNMAP:
			read_esp(f->esp+4, data, 1);
			munmap((mapid_t)data[0]);
			break;
#endif
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
	// 주소가 NULL 이거나 유저영역의 주소가 아닌 경우
	if (!addr || !is_user_vaddr(addr))
		exit(-1);
#ifdef VM
	// VM 환경에서는 SPT를 확인 (lazy loading 지원)
	struct vm_entry *vme = find_vme (addr);
	if (vme == NULL && pagedir_get_page(thread_current()->pagedir, addr) == NULL)
		exit(-1);
#else
	if (!pagedir_get_page(thread_current()->pagedir, addr))
		exit(-1);
#endif
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

#ifdef VM
  // [Section 10] Buffer Pinning - 읽기 전에 버퍼 고정
  pin_buffer (buffer, size, true);  // writable=true: 읽기 시 버퍼에 쓰기 필요
#endif

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
    if(!f) {
#ifdef VM
      unpin_buffer (buffer, size);
#endif
      return -1;
    }
    lock_acquire(&filesys_lock);
    bytes_read = file_read(f, buffer, size);
    lock_release(&filesys_lock);
  }

#ifdef VM
  // [Section 10] Buffer Unpinning - 읽기 완료 후 해제
  unpin_buffer (buffer, size);
#endif

  return bytes_read;
}

int write (int fd, const void *buffer, unsigned size) {
  // fd에 해당하는 파일을 최대 size 만큼 쓰고, 실제로 쓰기를 한 byte 만큼 반환함
  
  int bytes_write = 0;
  struct file* f;
  unsigned i;

  for (i = 0; i < size; i++) {
    is_valid_addr((void *)(buffer+i));
  }

#ifdef VM
  // [Section 10] Buffer Pinning - 쓰기 전에 버퍼 고정
  pin_buffer ((void *)buffer, size, false);  // writable=false: 쓰기 시 버퍼에서 읽기만 필요
#endif

  if(fd == 1) {
    lock_acquire(&filesys_lock);
    putbuf(buffer, size);
    lock_release(&filesys_lock);
#ifdef VM
    unpin_buffer ((void *)buffer, size);
#endif
    return size;
  }
  else if(fd > 1) {
    f = process_get_file(fd);
    if(!f) {
#ifdef VM
      unpin_buffer ((void *)buffer, size);
#endif
      return -1;
    }
    lock_acquire(&filesys_lock);
    bytes_write = file_write(f, buffer, size);
    lock_release(&filesys_lock);
  }

#ifdef VM
  // [Section 10] Buffer Unpinning - 쓰기 완료 후 해제
  unpin_buffer ((void *)buffer, size);
#endif

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

#ifdef VM
// mmap: 파일을 메모리에 매핑
mapid_t 
mmap (int fd, void *addr)
{
  struct thread *cur = thread_current ();
  struct file *file;
  struct file *file__reopen;
  off_t file_len;
  off_t ofs = 0;
  
  // 1. 유효성 검사
  // addr이 NULL이거나 페이지 정렬되지 않은 경우
  if (addr == NULL || pg_ofs (addr) != 0)
    return -1;
  
  // fd가 STDIN(0) 또는 STDOUT(1)인 경우
  if (fd == 0 || fd == 1)
    return -1;
    
  // addr이 0인 경우 (주소 0에 매핑 금지)
  if (addr == 0)
    return -1;

  // 파일 가져오기
  file = process_get_file (fd);
  if (file == NULL)
    return -1;
  
  // 파일 길이가 0인 경우
  lock_acquire (&filesys_lock);
  file_len = file_length (file);
  lock_release (&filesys_lock);
  
  if (file_len == 0)
    return -1;
  
  // 2. 매핑할 주소 범위에 기존 매핑이 있는지 확인
  off_t remaining = file_len;
  void *check_addr = addr;
  while (remaining > 0)
    {
      if (find_vme (check_addr) != NULL)
        return -1;  // 이미 매핑된 페이지가 있음
      check_addr += PGSIZE;
      remaining -= PGSIZE;
    }
  
  // 3. 파일 복제 (file_reopen) - close(fd) 후에도 매핑 유지
  lock_acquire (&filesys_lock);
  file__reopen = file_reopen (file); // 실제 파일은 동일한데 struct file을 새로 만듬
  lock_release (&filesys_lock);
  
  if (file__reopen == NULL)
    return -1;
  
  // 4. mmap_file 구조체 생성
  struct mmap_file *mf = malloc (sizeof (struct mmap_file));
  if (mf == NULL)
    {
      lock_acquire (&filesys_lock);
      file_close (file__reopen);
      lock_release (&filesys_lock);
      return -1;
    }
  
  mf->mapid = cur->next_mapid++;
  mf->file = file__reopen;
  list_init (&mf->vme_list);
  
  // 5. 파일을 페이지 단위로 나누어 vm_entry 생성
  remaining = file_len;
  void *upage = addr;
  
  while (remaining > 0)
    {
      size_t page_read_bytes = remaining < PGSIZE ? remaining : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      // vm_entry 생성
      struct vm_entry *vme = malloc (sizeof (struct vm_entry)); // physical memory allocation 아님
      if (vme == NULL)
        {
          // 롤백: 이미 생성된 vm_entry 들을 정리
          munmap (mf->mapid);
          return -1;
        }
      
      vme->type = VM_FILE; // 파일 매핑 타입
      vme->vaddr = upage;
      vme->writable = true; // mmap은 기본적으로 쓰기 가능
      vme->is_loaded = false; // lazy loading
      vme->file = file__reopen;
      vme->offset = ofs;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      vme->swap_slot = SWAP_ERROR;
      
      // SPT에 등록
      if (!insert_vme (&cur->vm, vme))
        {
          free (vme);
          munmap (mf->mapid);
          return -1;
        }
      
      // mmap_vme 생성하여 mmap_file의 리스트에 추가
      struct mmap_vme *mvme = malloc (sizeof (struct mmap_vme));
      if (mvme == NULL)
        {
          munmap (mf->mapid);
          return -1;
        }
      mvme->vme = vme;
      list_push_back (&mf->vme_list, &mvme->elem);
      
      // 다음 페이지
      remaining -= page_read_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  
  // 6. mmap_list에 추가
  list_push_back (&cur->mmap_list, &mf->elem);
  
  return mf->mapid;
}

// munmap: 메모리 매핑 해제
void 
munmap (mapid_t mapid)
{
  struct thread *cur = thread_current ();
  struct mmap_file *mf = NULL;
  
  // mapid에 해당하는 mmap_file 찾기
  struct list_elem *e;
  for (e = list_begin (&cur->mmap_list); e != list_end (&cur->mmap_list); 
       e = list_next (e))
    {
      struct mmap_file *temp = list_entry (e, struct mmap_file, elem);
      if (temp->mapid == mapid)
        {
          mf = temp;
          break;
        }
    }
  
  if (mf == NULL)
    return;  // 해당 mapid를 찾지 못함
  
  // mmap_file에 속한 모든 vm_entry 처리
  while (!list_empty (&mf->vme_list))
    {
      // 각 page에 대해
      struct list_elem *vme_elem = list_pop_front (&mf->vme_list);
      struct mmap_vme *mvme = list_entry (vme_elem, struct mmap_vme, elem);
      struct vm_entry *vme = mvme->vme;
      
      // 로드된 상태라면 Write-back 및 프레임 해제
      if (vme->is_loaded)
        {
          void *kaddr = pagedir_get_page (cur->pagedir, vme->vaddr);
          if (kaddr != NULL)
            {
              // Dirty 페이지는 파일에 기록
              if (pagedir_is_dirty (cur->pagedir, vme->vaddr))
                {
                  lock_acquire (&filesys_lock);
                  file_write_at (vme->file, kaddr, vme->read_bytes, vme->offset);
                  lock_release (&filesys_lock);
                }
              // 프레임 해제
              frame_free (kaddr);
              pagedir_clear_page (cur->pagedir, vme->vaddr);
            }
        }
      
      // SPT에서 제거
      hash_delete (&cur->vm, &vme->elem);
      free (vme);
      free (mvme);
    }
  
  // mmap_list에서 제거
  list_remove (&mf->elem);
  
  // 파일 닫기
  lock_acquire (&filesys_lock);
  file_close (mf->file);
  lock_release (&filesys_lock);
  
  free (mf);
}

// 프로세스 종료 시 모든 mmap 해제
void
munmap_all (void)
{
  struct thread *cur = thread_current ();
  
  while (!list_empty (&cur->mmap_list))
    {
      struct list_elem *e = list_front (&cur->mmap_list);
      struct mmap_file *mf = list_entry (e, struct mmap_file, elem);
      munmap (mf->mapid);
    }
}

// Buffer Pinning

/*
pin_page: 단일 페이지를 메모리에 고정
upage: 페이지 정렬된 가상 주소
writable: 쓰기 권한 필요 여부
return: 성공 시 true
*/
static bool
pin_page (void *upage, bool writable)
{
  struct thread *cur = thread_current ();
  struct vm_entry *vme = find_vme (upage);
  
  // 1. vm_entry가 있는 경우
  if (vme != NULL)
    {
      // 쓰기 권한 검사
      if (writable && !vme->writable)
        return false;
      
      // 페이지가 로드되지 않았다면 로드 수행
      if (!vme->is_loaded)
        {
          if (!handle_mm_fault (vme))
            return false;
        }
      
      // 해당 프레임을 찾아서 pin 설정
      void *kaddr = pagedir_get_page (cur->pagedir, vme->vaddr);
      if (kaddr != NULL)
        frame_pin_allocate (kaddr, true);
      
      return true;
    }
  
  // 2. vm_entry가 없는 경우 - 스택 영역인지 확인
  // 스택은 PHYS_BASE 아래, 스택 제한(8MB) 이내여야 함
  void *stack_limit = (void *)(PHYS_BASE - (1 << 23)); // 8MB
  
  if (upage >= stack_limit && upage < PHYS_BASE)
    {
      // 스택 확장이 필요한 경우 - vm_entry 생성 및 프레임 할당
      struct vm_entry *new_vme = malloc (sizeof (struct vm_entry));
      if (new_vme == NULL)
        return false;
      
      new_vme->type = VM_ANON;
      new_vme->vaddr = upage;
      new_vme->writable = true;
      new_vme->is_loaded = true;
      new_vme->file = NULL;
      new_vme->offset = 0;
      new_vme->read_bytes = 0;
      new_vme->zero_bytes = PGSIZE;
      new_vme->swap_slot = SWAP_ERROR;
      
      // 물리 프레임 할당
      void *kaddr = frame_allocate (PAL_ZERO, new_vme);
      if (kaddr == NULL)
        {
          free (new_vme);
          return false;
        }
      
      // 페이지 테이블에 매핑
      if (!pagedir_set_page (cur->pagedir, upage, kaddr, true))
        {
          frame_free (kaddr);
          free (new_vme);
          return false;
        }
      
      // SPT에 등록
      if (!insert_vme (&cur->vm, new_vme))
        {
          pagedir_clear_page (cur->pagedir, upage);
          frame_free (kaddr);
          free (new_vme);
          return false;
        }
      
      // frame_allocate에서 이미 pinned=true로 설정됨
      return true;
    }
  
  // 3. 이미 물리 메모리에 매핑된 페이지 (pagedir에는 있지만 SPT에는 없는 경우)
  void *kaddr = pagedir_get_page (cur->pagedir, upage);
  if (kaddr != NULL)
    {
      frame_pin_allocate (kaddr, true);
      return true;
    }
  
  return false;
}

/* 
 * pin_buffer: 버퍼가 속한 모든 페이지를 메모리에 고정
buffer: 버퍼 시작 주소
size: 버퍼 크기
writable: 버퍼에 쓰기가 필요한 경우 true (read 시스템콜)
*/
static void 
pin_buffer (void *buffer, unsigned size, bool writable)
{
  void *upage;
  
  if (size == 0)
    return;
  
  // 버퍼가 걸쳐있는 모든 페이지를 순회
  for (upage = pg_round_down (buffer); 
       upage < buffer + size; 
       upage += PGSIZE)
    {
      if (!pin_page (upage, writable))
        exit (-1);
    }
}

/*
 * unpin_buffer: 버퍼가 속한 모든 페이지의 고정 해제
 */
static void 
unpin_buffer (void *buffer, unsigned size)
{
  struct thread *cur = thread_current ();
  void *upage;
  
  if (size == 0)
    return;
  
  // 버퍼가 걸쳐있는 모든 페이지를 순회
  for (upage = pg_round_down (buffer); 
       upage < buffer + size; 
       upage += PGSIZE)
    {
      void *kaddr = pagedir_get_page (cur->pagedir, upage);
      if (kaddr != NULL)
        frame_pin_allocate (kaddr, false);
    }
}
#endif
