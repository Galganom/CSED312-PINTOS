#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

/* 스왑 테이블 초기화 */
void swap_init (void);

/* 스왑 영역에서 데이터를 읽어 kaddr에 저장 */
void swap_in (size_t used_index, void *kaddr);

/* kaddr의 데이터를 스왑 영역에 저장하고 인덱스 반환 */
size_t swap_out (void *kaddr);

#endif /* vm/swap.h */
