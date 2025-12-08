#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

// 스왑 테이블 초기화
void swap_init (void);

// 스왑 영역에서 데이터를 읽어 kaddr에 저장
void data_in (size_t used_index, void *kaddr);

// kaddr의 데이터를 스왑 영역에 저장하고 인덱스 반환
size_t data_out (void *kaddr);

// 스왑 슬롯 해제 (프로세스 종료 시 사용)
void release_slot (size_t used_index);

#endif
