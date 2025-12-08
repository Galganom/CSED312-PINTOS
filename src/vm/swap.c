#include "vm/swap.h"
#include <bitmap.h>
#include <debug.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

// 1 page = 4KB = 8 sectors (512B * 8)
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

// 스왕 비트맵: 1 bit = 1 page (4KB)
static struct bitmap *swap_bitmap;

// 스왕 파티션 블록 디바이스
static struct block *swap_block;

// 스왕 테이블 보호용 락
static struct lock swap_lock;

// 스왕 테이블 초기화
void 
swap_init (void)
{
    swap_block = block_get_role (BLOCK_SWAP);
    
if (swap_block == NULL) 
    {
        // 스왕 파티션이 없으면 비트맵을 0 크기로 초기화
        swap_bitmap = bitmap_create (0);
    } 
    else 
    {
        // 블록 크기 / 페이지당 섹터 수 = 스왑 슬롯 개수
        size_t swap_slots = block_size (swap_block) / SECTORS_PER_PAGE;
        swap_bitmap = bitmap_create (swap_slots);
    }
    
    if (swap_bitmap == NULL)
        PANIC ("swap_init: bitmap creation failed");
    
    // 모든 슬롯을 사용 가능 상태로 초기화 (0 = free, 1 = used)
    bitmap_set_all (swap_bitmap, false);
    
lock_init (&swap_lock);
}

// 스왕 영역에서 데이터를 읽어 kaddr에 저장
void 
data_in (size_t used_index, void *kaddr)
{
    lock_acquire (&swap_lock);

    ASSERT (swap_block != NULL);
    ASSERT (used_index < bitmap_size (swap_bitmap));
    ASSERT (bitmap_test (swap_bitmap, used_index) == true);

    // 8개의 섹터를 읽어서 kaddr에 저장
    size_t i;
    for (i = 0; i < SECTORS_PER_PAGE; i++) 
    {
        block_read (swap_block, used_index * SECTORS_PER_PAGE + i, kaddr + i * BLOCK_SECTOR_SIZE);
    }

    // 비트맵에서 해당 슬롯을 free로 표시
    bitmap_flip (swap_bitmap, used_index);

    lock_release (&swap_lock);
}

// kaddr의 데이터를 스왑 영역에 저장하고 인덱스 반환
size_t 
data_out (void *kaddr) 
{
    lock_acquire (&swap_lock);

    ASSERT (swap_block != NULL);

    // 비트맵에서 빈 슬롯 찾기
    size_t free_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    
    if (free_index == BITMAP_ERROR)
        PANIC ("data_out: no free swap slots");

    // 8개의 섹터에 데이터 쓰기
    size_t i;
    for (i = 0; i < SECTORS_PER_PAGE; i++) 
    {
        block_write (swap_block,
                     free_index * SECTORS_PER_PAGE + i,
                     kaddr + i * BLOCK_SECTOR_SIZE);
    }

    lock_release (&swap_lock);
    return free_index;
}

// 스왑 슬롯 해제 (프로세스 종료 시 사용)
void 
release_slot (size_t used_index) 
{
    lock_acquire (&swap_lock);

    ASSERT (swap_block != NULL);
    ASSERT (used_index < bitmap_size (swap_bitmap));
    ASSERT (bitmap_test (swap_bitmap, used_index) == true);

    // 비트맵에서 해당 슬롯을 free로 표시
    bitmap_reset (swap_bitmap, used_index);

    lock_release (&swap_lock);
}
