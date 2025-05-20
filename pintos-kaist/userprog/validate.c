#include "userprog/validate.h"
#include "userprog/syscall.h"     /* syscall_exit() */
#include "threads/thread.h"       /* thread_current(), pml4 */
#include "threads/vaddr.h"        /* PHYS_BASE, pg_ofs */
#include "threads/mmu.h"          /* PGSIZE */
#include "threads/pte.h"          /* pml4_get_page() */
#include <string.h>               /* memcpy */

/* 내부 헬퍼: 단일 가상 주소가 유저 영역에 있고 매핑돼 있는지 확인 */
static bool
check_page (const void *uaddr) {
    return uaddr != NULL &&
           uaddr < PHYS_BASE &&
           pml4_get_page (thread_current ()->pml4, uaddr) != NULL;
}

/* uaddr ~ uaddr+size-1 범위를 페이지 단위로 스캔 */
void
validate_ptr (const void *uaddr, size_t size) {
    if (size == 0) return;                        /* 길이 0 → no-op */

    const uint8_t *usr = uaddr;
    size_t left = size;

    while (left > 0) {
        if (!check_page (usr))
            sys_exit (-1);                    /* 잘못된 포인터 ⇒ 프로세스 종료 */

        size_t page_left = PGSIZE - pg_ofs (usr); /* 현재 페이지에 남은 바이트 */
        size_t chunk     = left < page_left ? left : page_left;

        usr  += chunk;
        left -= chunk;
    }
}

/* 유저 → 커널 복사 */
size_t
copy_in (void *kernel_dst, const void *user_src, size_t size) {
    validate_ptr (user_src, size);
    memcpy (kernel_dst, user_src, size);
    return size;
}

/* 커널 → 유저 복사 */
size_t
copy_out (void *user_dst, const void *kernel_src, size_t size) {
    validate_ptr (user_dst, size);
    memcpy (user_dst, kernel_src, size);
    return size;
}
