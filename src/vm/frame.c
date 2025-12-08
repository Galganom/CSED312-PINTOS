#include "vm/frame.h"
#include <debug.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "filesys/file.h"

// 전역 Frame Table 및 Lock
static struct list frame_table;
static struct lock frame_lock;

// Clock Algorithm을 위한 현재 포인터
static struct list_elem *clock_hand;

// Frame Table 초기화
void 
frame_init (void) 
{
    list_init (&frame_table);
    lock_init (&frame_lock);
    clock_hand = NULL;
}

// 다음 frame element로 이동 (circular list 처리)
static struct list_elem *
get_next_frame (struct list_elem *e) 
{
    struct list_elem *next = list_next (e);
    if (next == list_end (&frame_table)) 
    {
        next = list_begin (&frame_table);
    }
    return next;
}

// 물리 프레임 할당 (메모리 부족 시 Eviction 수행)
void *
frame_allocate (enum palloc_flags flags, struct vm_entry *vme) 
{
    lock_acquire (&frame_lock);

    // 1. 사용자 풀에서 페이지 할당 시도
    void *kaddr = palloc_get_page (PAL_USER | flags);

    // 2. 가용 메모리가 없다면 Eviction 수행
    if (kaddr == NULL) 
    {
        // evict_frame 내부에서 data_out을 수행하고 공간을 만들어옴
        kaddr = evict_frame (flags);
        
        if (kaddr == NULL) 
        {
            lock_release (&frame_lock);
            return NULL; // PANIC 유발 가능성 있음
        }
    }

    // 3. Frame 구조체 생성 및 초기화
    struct frame *f = malloc (sizeof (struct frame));
    if (f == NULL) 
    {
        palloc_free_page (kaddr);
        lock_release (&frame_lock);
        return NULL;
    }
    
    f->kaddr = kaddr;
    f->vme = vme;
    f->t = thread_current ();
    f->pinned = true; // 할당 시점에는 일단 고정함 (로딩 중 Eviction 방지)

    // 4. 관리 리스트에 추가
    list_push_back (&frame_table, &f->elem);

    lock_release (&frame_lock);
    return kaddr;
}

// 사용이 끝난 프레임을 해제하고 리스트에서 제거
void 
frame_free (void *kaddr) 
{
    lock_acquire (&frame_lock);

    // 리스트를 순회하여 kaddr에 해당하는 frame을 찾음
    struct list_elem *e;
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e)) 
    {
        struct frame *f = list_entry (e, struct frame, elem);
        if (f->kaddr == kaddr) 
        {
            // clock_hand가 현재 프레임을 가리키고 있다면 다음으로 이동
            if (clock_hand == e) 
            {
                clock_hand = get_next_frame (e);
                if (clock_hand == e) 
                {
                    // 리스트에 이 프레임 하나만 있는 경우
                    clock_hand = NULL;
                }
            }
            
            list_remove (&f->elem);
            free (f);
            palloc_free_page (kaddr);
            break;
        }
    }

    lock_release (&frame_lock);
}

// kaddr로 frame 구조체를 검색
struct frame *
find_frame (void *kaddr) 
{
    lock_acquire (&frame_lock);

    struct list_elem *e;
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e)) 
    {
        struct frame *f = list_entry (e, struct frame, elem);
        if (f->kaddr == kaddr) 
        {
            lock_release (&frame_lock);
            return f;
        }
    }

    lock_release (&frame_lock);
    return NULL;
}

// 프레임의 pinned 상태 설정
void 
frame_pin_allocate (void *kaddr, bool pinned) 
{
    lock_acquire (&frame_lock);

    struct list_elem *e;
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e)) 
    {
        struct frame *f = list_entry (e, struct frame, elem);
        if (f->kaddr == kaddr) 
        {
            f->pinned = pinned;
            break;
        }
    }

    lock_release (&frame_lock);
}

// Clock Algorithm을 사용한 Eviction
void *
evict_frame (enum palloc_flags flags) 
{
    // 주의: frame_lock이 걸린 상태에서 호출됨
    
    if (list_empty (&frame_table))
        return NULL;

    // Clock hand 초기화
    if (clock_hand == NULL || clock_hand == list_end (&frame_table))
        clock_hand = list_begin (&frame_table);

    struct list_elem *start = clock_hand;
    size_t pass_count = 0;  // 순회 횟수 추적
    size_t frame_count = list_size (&frame_table);
    
    while (true) 
    {
struct frame *f = list_entry (clock_hand, struct frame, elem);
        
        // Pinned 프레임은 건너뛰
        if (!f->pinned)
        {
            // Accessed 비트 확인 (최근 참조 여부)
            if (pagedir_is_accessed (f->t->pagedir, f->vme->vaddr)) 
            {
                // 기회 제공: accessed bit를 0으로 설정
                pagedir_set_accessed (f->t->pagedir, f->vme->vaddr, false);
            } 
            else 
            {
                // Victim 선정 완료 -> Swap Out 수행
                
                // 1. Dirty Check & Swap/File Write
                bool is_dirty = pagedir_is_dirty (f->t->pagedir, f->vme->vaddr);
                
                if (f->vme->type == VM_FILE) 
                {
                    // VM_FILE 타입이고 Dirty -> 파일에 저장
                    if (is_dirty) 
                    {
                        file_write_at (f->vme->file, f->kaddr, 
                                       f->vme->read_bytes, f->vme->offset);
                    }
                    // 깨끗한 파일 페이지 -> 그냥 버림 (나중에 파일에서 다시 읽으면 됨)
                }
                else if (f->vme->type == VM_ANON) 
                {
                    // VM_ANON 타입 -> 항상 스왑 영역에 저장
                    f->vme->swap_slot = data_out (f->kaddr);
                }
                else if (f->vme->type == VM_BIN) 
                {
                    // VM_BIN 타입이고 Dirty -> 스왑에 저장하고 타입 변경
                    if (is_dirty) 
                    {
                        f->vme->swap_slot = data_out (f->kaddr);
                        f->vme->type = VM_ANON;
                    }
                    // 깨끗한 VM_BIN -> 그냥 버림 (나중에 ELF에서 다시 읽으면 됨)
                }
                
                // 2. SPT 상태 업데이트
                f->vme->is_loaded = false;

                // 3. 테이블 연결 끊기
                pagedir_clear_page (f->t->pagedir, f->vme->vaddr);

                // 4. Clock hand를 다음으로 이동
                clock_hand = get_next_frame (clock_hand);
                if (clock_hand == &f->elem) 
                {
                    clock_hand = NULL;
                }

                // 5. 리스트 제거 및 프레임 구조체 해제
                list_remove (&f->elem);
                void *freed_kaddr = f->kaddr;
                free (f);

                // 6. 물리 메모리 해제 후 다시 할당받아 리턴
                palloc_free_page (freed_kaddr);
                return palloc_get_page (PAL_USER | flags);
            }
        }
        
        // 다음 프레임으로 이동
        clock_hand = get_next_frame (clock_hand);
        
        // 한 바퀴 돌아서 시작점으로 돌아왔다면 패스 카운트 증가
        if (clock_hand == start) 
        {
            pass_count++;
            // 2번 순회해도 victim을 못 찾으면 (모든 페이지가 pinned)
            if (pass_count >= 2) 
            {
                return NULL;
            }
        }
        
        // 안전장치: 예상치 못한 무한 루프 방지
        if (pass_count == 0 && frame_count > 0)
        {
            frame_count--;
            if (frame_count == 0)
            {
                pass_count = 1;  // 최소 한 바퀴는 돌았음
            }
        }
    }
}
