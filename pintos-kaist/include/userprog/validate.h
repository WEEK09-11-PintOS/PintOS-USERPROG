#ifndef USERPROG_VALIDATE_H
#define USERPROG_VALIDATE_H

#include <stddef.h>
#include <stdbool.h>

/* uaddr ~ uaddr+size-1 가
 *   ① NULL 아님
 *   ② < PHYS_BASE
 *   ③ 매핑(pml4_get_page) 존재
 * 중 하나라도 틀리면 syscall_exit(-1) 로 즉시 종료한다. */
void    validate_ptr (const void *uaddr, size_t size);

/* 유저 → 커널 안전 복사.
 * size 바이트 전부 복사 실패 시 syscall_exit(-1). */
size_t  copy_in  (void *kernel_dst, const void *user_src, size_t size);

/* 커널 → 유저 안전 복사.
 * size 바이트 전부 복사 실패 시 syscall_exit(-1). */
size_t  copy_out (void *user_dst,   const void *kernel_src, size_t size);

#endif /* userprog/validate.h */
