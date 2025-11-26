#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <list.h>
#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

#define VM_BIN  0    // 바이너리(실행 파일)에서 로드된 페이지
#define VM_FILE 1    // mmap으로 매핑된 파일 페이지
#define VM_ANON 2    // 스왕 대상 (Stack, Heap)

// 스왕 슬롯이 없음을 나타내는 상수
#define SWAP_ERROR SIZE_MAX

// 페이지의 현재 상태를 나타내는 구조체
struct vm_entry {
    uint8_t type;           // VM_BIN, VM_FILE, VM_ANON
    void *vaddr;            // 유저 가상 주소 (Key) - page aligned
    bool writable;          // 쓰기 가능 여부
    
    bool is_loaded;         // 현재 물리 메모리에 올라와 있는지 여부
    
    // Memory Mapped File & Lazy Loading 정보
    struct file *file;      // 매핑된 파일 포인터 (NULL이면 ANON)
    off_t offset;           // 파일 내 오프셋
    size_t read_bytes;      // 파일에서 읽어야 할 바이트 수
    size_t zero_bytes;      // 0으로 채워야 할 바이트 수 (padding)

    // Swap 정보
    size_t swap_slot;       // 스왕 디스크 내 인덱스

    // Hash Table 관리를 위한 요소
    struct hash_elem elem;
};

// Memory Mapped File 관리를 위한 구조체
struct mmap_file {
    int mapid;                  // 매핑 ID
    struct file *file;          // mmap된 파일 (reopen된 파일 포인터)
    struct list_elem elem;      // mmap_list 연결용
    struct list vme_list;       // 이 mmap에 속한 vm_entry 리스트
};

// mmap_file의 vme_list에 연결되는 요소
struct mmap_vme {
    struct vm_entry *vme;       // vm_entry 포인터
    struct list_elem elem;      // vme_list 연결용
};

// SPT 관리 함수 선언
void vm_init (struct hash *vm);
void vm_destroy (struct hash *vm);
struct vm_entry *find_vme (void *vaddr);
bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);

// Page fault 처리 시 파일에서 데이터를 로드하는 함수
bool load_file (void *kaddr, struct vm_entry *vme);

#endif // vm/page.h
