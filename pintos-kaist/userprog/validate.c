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
           is_user_vaddr(uaddr) &&
           pml4_get_page (thread_current ()->pml4, uaddr) != NULL;
}

/* uaddr ~ uaddr+size-1 범위를 페이지 단위로 검증 (고정된 물리적 범위) */
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

/* \0 문자가 나올 때까지 한 글자씩 따라가며 검증 (가변적인 논리적 길이)*/
void validate_str(const char *str) {
	for (const char *p = str;; ++p) {
		validate_ptr(p, 1);  // 한 바이트라도 접근 가능해야 함
		if (*p == '\0') break;
	}
}

/* 사용자 주소 UADDR의 바이트를 읽음 */
int64_t get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
        "movabsq $done_get, %0\n"
        "movzbq %1, %0\n"
        "done_get:\n"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* 사용자 주소 UDST에 BYTE를 씀 */
bool put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
	printf("[put_user] trying to write to %p\n", udst);
    __asm __volatile (
        "movabsq $done_put, %0\n"
        "movb %b2, %1\n"
        "done_put:\n"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
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
