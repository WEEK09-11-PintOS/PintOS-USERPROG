#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/validate.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/kernel/console.h"
#include "filesys/directory.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_halt();
bool sys_create(const char *file, unsigned initial_size);
bool strlcpy_user(char *dst, const char *src_user, size_t size);
static int sys_exec(const char *cmd_line);

/* 시스템 콜.
 *
 * 이전에는 시스템 콜 서비스가 인터럽트 핸들러(예: 리눅스의 int 0x80)에 의해 처리되었습니다.
 * 하지만 x86-64에서는 제조사가 시스템 콜을 요청하는 효율적인 경로인 `syscall` 명령어를 제공합니다.
 *
 * syscall 명령어는 모델별 레지스터(MSR)의 값을 읽어서 동작합니다.
 * 자세한 내용은 매뉴얼을 참고하세요.
 */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	/*시스템 콜 진입점 주소를 MSR_LSTAR에 기록. syscall_entry 는 시스템 콜 진입점, 유저 모드에서
	시스템 콜을 실행했을 때 커널 모드로 전환 */
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* 인터럽트 서비스 루틴은 시스템 엔트리가 유저모드 스택에서 커널모드 스택으로
	전환할때 까지 어떠한 인터럽트도 제공해서는 안된다. 그러므로, 우리는 만드시 FLAG_FL을 마스크 해야 한다.
	시스템 콜 핸들러 진입 시 유저가 조작할 수 없도록 마스킹할 플래그를 지정한다. 즉, 시스템 콜
	진입 시 위 플래그들은 자동으로 0이되어, 유저 프로세스가 커널에 영향을 주지 못하게 막는다.
 */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	uint64_t syscall_num = f->R.rax;
	uint64_t arg1 = f->R.rdi;
	uint64_t arg2 = f->R.rsi;
	uint64_t arg3 = f->R.rdx;
	uint64_t arg4 = f->R.r10;
	uint64_t arg5 = f->R.r8;
	uint64_t arg6 = f->R.r9;

	switch (syscall_num)
	{
	case SYS_HALT:
		sys_halt();
		break;
	case SYS_EXIT:
		sys_exit(arg1);
		break;
	case SYS_FORK:
		f->R.rax = process_fork(arg1, f);
		break;
	case SYS_EXEC:
		f->R.rax = sys_exec((const char *)arg1);
		break;
	case SYS_CREATE:
		f->R.rax = sys_create(arg1, arg2);
		break;
	case SYS_REMOVE:
		break;
	case SYS_OPEN:
		break;
	case SYS_FILESIZE:
		break;
	case SYS_READ:
		break;
	case SYS_WRITE:
		sys_write(arg1, arg2, arg3);
		break;
	case SYS_SEEK:
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
		break;
	case SYS_WAIT:
		f->R.rax = process_wait(arg1);
		break;

	default:
		thread_exit();
		break;
	}
}

void check_address(void *addr)
{
	if (addr == NULL)
		sys_exit(-1);
	if (!is_user_vaddr(addr))
		sys_exit(-1);
	if (pml4_get_page(thread_current()->pml4, addr) == NULL)
		sys_exit(-1);
}

static void sys_halt() {
	power_off();
}

static int sys_write(int fd, const void *buffer, unsigned size)
{
	if (fd == 1)
	{
		putbuf(buffer, size);
		return size;
	}
	return -1;
}

void sys_exit(int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool sys_create(const char *file, unsigned initial_size) {
	check_address(file);

	char kernel_buf[NAME_MAX + 1];
    if (!strlcpy_user(kernel_buf, file, sizeof kernel_buf)) {
        return false;  // null terminator 없음 or 너무 김
    }

	if (strlen(kernel_buf) == 0) {
		return false;
	}

	struct dir *dir = dir_open_root();
	if (dir == NULL) {
		return false;
	}
	struct inode *inode;

    if (dir_lookup(dir, kernel_buf, &inode)) {
		dir_close(dir);
		return false;
	}
	
	bool success = filesys_create(kernel_buf, initial_size);

	dir_close(dir);
	return success;
}

bool strlcpy_user(char *dst, const char *src_user, size_t size) {
    for (size_t i = 0; i < size; i++) {
        check_address((void *)(src_user + i));  // 유저 메모리 접근 안전성 확인
        char c = *(uint8_t *)(src_user + i);
        dst[i] = c;
        if (c == '\0'){
			// printf("[DEBUG] strlcpy_user: copied string = '%s'\n", dst);
    		return true;
		}
    }
    dst[size - 1] = '\0';
    return false;
}

static tid_t sys_exec(const char *cmd_line) {
	validate_ptr(cmd_line, 1);

	char *kbuf = palloc_get_page(0);
	if (kbuf == NULL) return -1;

	strlcpy(kbuf, cmd_line, PGSIZE);	// 커널 버퍼에 복사 (안전성)

	tid_t tid = process_execute(kbuf);	// page는 자식이 free
	palloc_free_page(kbuf);	// 복사가 끝났으므로 kbuf 해제

	if (tid == TID_ERROR)
		return -1;

	int status = process_wait(tid);     // 자식 종료를 기다림

	return (status == -1) ? TID_ERROR : tid;
}