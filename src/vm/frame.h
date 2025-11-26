#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/palloc.h"
#include "threads/synch.h"

// Forward declaration
struct vm_entry;

/*
Frame Table은 전역 리스트 + Global Lock 보호
Pinned 플래그로 개별 Eviction 방지 
*/
struct frame {
    void *kaddr;            // 커널 가상 주소 (물리 프레임과 1:1)
    struct vm_entry *vme;   // 이 프레임의 논리적 주인 (역참조)
struct thread *t;       // 이 프레임의 소유자 스레드
    
    // Eviction 방지용
    bool pinned;            // true면 절대 쫓아내지 않음
    
struct list_elem elem;  // frame_table 연결용
};

// Frame 관리 함수 선언
void frame_init (void);
void *frame_allocate (enum palloc_flags flags, struct vm_entry *vme);
void frame_free (void *kaddr);
void frame_pin_allocate (void *kaddr, bool pinned);

// kaddr로 frame 구조체를 검색하는 함수
struct frame *find_frame (void *kaddr);

// 메모리 부족 시 호출될 함수
void *evict_frame (enum palloc_flags flags);

#endif // vm/frame.h
