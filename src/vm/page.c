#include "vm/page.h"
#include <string.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"

// 해시 함수: vaddr를 해싱
static unsigned 
vm_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
    // hash_elem 으로 vm_entry 알아냄
    struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
    // vm_entry -> vddr 의 해시값 반환
    return hash_bytes (&vme->vaddr, sizeof (vme->vaddr));
}

// 비교 함수: vaddr 기준 정렬
static bool 
vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) 
{
    struct vm_entry *vme_a = hash_entry (a, struct vm_entry, elem);
    struct vm_entry *vme_b = hash_entry (b, struct vm_entry, elem);
    return vme_a->vaddr < vme_b->vaddr;
}

// hash_destroy가 각 요소마다 호출하는 함수
static void 
vm_destroy_func (struct hash_elem *e, void *aux UNUSED) 
{
    struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
    struct thread *cur = thread_current ();

    // Case 1: 물리 메모리에 로드된 상태
    if (vme->is_loaded) 
    {
        // 프레임 테이블에서 제거하고 물리 메모리 반환
        void *kaddr = pagedir_get_page (cur->pagedir, vme->vaddr);
        if (kaddr != NULL) 
        {
            frame_free (kaddr);
            pagedir_clear_page (cur->pagedir, vme->vaddr);
        }
    }
    // Case 2: 스왑 영역에 있는 상태 (VM_ANON)
    else if (vme->type == VM_ANON && vme->swap_slot != SWAP_ERROR)
    {
        // 스왕 비트맵에서 해당 슬롯을 해제
        release_slot (vme->swap_slot);
    }

    // 공통: vm_entry 구조체 메모리 해제
    free (vme);
}

// SPT 초기화
void 
vm_init (struct hash *vm) 
{
    hash_init (vm, vm_hash_func, vm_less_func, NULL);
}

// SPT 파괴 (Process Exit 시)
void 
vm_destroy (struct hash *vm) 
{
    hash_destroy (vm, vm_destroy_func); // lib/kernel/hash.c 빌트인 함수
}

// SPT에서 vaddr에 해당하는 vm_entry를 검색
struct vm_entry *
find_vme (void *vaddr) 
{
    struct thread *cur = thread_current ();
    struct vm_entry p;
    struct hash_elem *e;

    // 페이지 단위 내림 vvvv
    p.vaddr = pg_round_down (vaddr);

    e = hash_find (&cur->vm, &p.elem);
    return e != NULL ? hash_entry (e, struct vm_entry, elem) : NULL;
}

// SPT에 vm_entry 삽입
bool 
insert_vme (struct hash *vm, struct vm_entry *vme) 
{
    struct hash_elem *result = hash_insert (vm, &vme->elem);
    // hash_insert는 중복 시 기존 요소 반환, 성공 시 NULL 반환
    return result == NULL;
}

// SPT에서 vm_entry 삭제
bool 
delete_vme (struct hash *vm, struct vm_entry *vme) 
{
    struct hash_elem *result = hash_delete (vm, &vme->elem);
    if (result != NULL) 
    {
        free (vme);
        return true;
    }
    return false;
}

// Page fault 처리 시 파일에서 데이터를 로드하는 함수
bool 
load_file (void *kaddr, struct vm_entry *vme) 
{
    // 파일이 없으면 실패
    if (vme->file == NULL)
        return false;

    // 파일에서 read_bytes만큼 읽기
    // vme->file을 kaddr에 복사하기
    off_t bytes_read = file_read_at (vme->file, kaddr, vme->read_bytes, vme->offset);
    
    if (bytes_read != (off_t) vme->read_bytes)
        return false;

    // 나머지를 0으로 채우기
    memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);
    
    return true;
}
