#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/validate.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/kernel/console.h"
#include "lib/user/syscall.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_halt();
bool sys_create(const char *file, unsigned initial_size);
bool strlcpy_user(char *dst, const char *src_user, size_t size);
static int64_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
bool sys_remove(const char *file);
int sys_filesize(int fd);
static tid_t sys_exec(const char *cmd_line);
int sys_wait(int pid);

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

	lock_init(&filesys_lock);
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
		f->R.rax = sys_fork((const char *)arg1, f);
		break;
	case SYS_EXEC:
		f->R.rax = sys_exec((const char *)arg1);
		break;
	case SYS_CREATE:
		f->R.rax = sys_create(arg1, arg2);
		break;
	case SYS_REMOVE:
		f->R.rax = sys_remove(arg1);
		break;
	case SYS_OPEN:
		f->R.rax = sys_open(arg1);
		break;
	case SYS_FILESIZE:
		f->R.rax = sys_filesize(arg1);
		break;
	case SYS_READ:
		f->R.rax = sys_read(arg1, arg2, arg3);
		break;
	case SYS_WRITE:
		f->R.rax = sys_write(arg1, arg2, arg3);
		break;
	case SYS_SEEK:
		sys_seek(arg1, arg2);
		break;
	case SYS_TELL:
		f->R.rax = sys_tell(arg1);
		break;
	case SYS_CLOSE:
		sys_close(arg1);
		break;
	case SYS_WAIT:
		f->R.rax = sys_wait(arg1);
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


/* 사용자 주소 UADDR의 바이트를 읽음 */
static int64_t get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
        "movabsq $done_get, %0\n"
        "movzbq %1, %0\n"
        "done_get:\n"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* 사용자 주소 UDST에 BYTE를 씀 */
static bool put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
	printf("[put_user] trying to write to %p\n", udst);
    __asm __volatile (
        "movabsq $done_put, %0\n"
        "movb %b2, %1\n"
        "done_put:\n"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}



static void sys_halt() {
	power_off();
}

static int sys_write(int fd, const void *buffer, unsigned size)
{
	// 유저 포인터가 유효한지 검증 (전체 영역 검사 이전에 시작 주소 먼저)
	check_address(buffer);

    // buffer가 가리키는 전체 메모리 영역이 유저 공간에 있는지 확인
    for (unsigned i = 0; i < size; i++) {
        check_address((const uint8_t *)buffer + i);
    }

	// stdin, stderr은 write 대상이 아님 → 에러 반환
	if (fd == 0 || fd == 2) {
		return -1;
	}

	// stdout (fd == 1): 콘솔 출력 → putbuf로 출력하고 size만큼 썼다고 리턴
	if (fd == 1)
	{
		putbuf(buffer, size);  // 콘솔에 buffer 내용을 출력
		return size;           // 실제 쓴 바이트 수 반환
	}
	
	// 일반 파일에 대해 file descriptor 테이블에서 file 객체를 가져옴
	struct file *file = process_get_file(fd);
    if (file == NULL)
        return -1;  // 해당 fd에 해당하는 파일이 없으면 에러 반환

	// 파일 시스템 접근 시 동시성 제어 위해 lock 획득
    lock_acquire(&filesys_lock);

	// 파일에 buffer 내용을 size 바이트만큼 write
    int bytes_write = file_write(file, buffer, size);

	// 파일 시스템 락 해제
    lock_release(&filesys_lock);

	// write 실패 시 음수 반환 (보통 -1)
    if (bytes_write < 0)
        return -1;

	// 성공 시 실제로 write한 바이트 수 반환
    return bytes_write;
}
void sys_exit(int status)
{
	// 현재 실행 중인 스레드(프로세스)를 가져옴
	struct thread *cur = thread_current();

	// 종료 상태(status)를 현재 스레드에 저장
	// 부모 프로세스가 wait()로 이 값을 조회할 수 있도록 하기 위함
	cur->exit_status = status;

	// 종료 메시지 출력 (테스트 시스템에서 검증에 사용함)
	// 예: "echo: exit(0)"
	printf("%s: exit(%d)\n", thread_name(), status);

	// 현재 스레드를 종료하고 정리 → scheduler에 의해 다른 스레드로 전환됨
	thread_exit();
}


// 자식 프로세스 pid를 기다리고, 종료될 때까지 블록됨
int sys_wait(int pid)
{
	// 실제 로직은 process_wait() 내부에 있음
	return process_wait(pid);
}


// 현재 프로세스를 복제(fork)하여 자식 프로세스를 생성함
tid_t sys_fork(const char *thread_name, struct intr_frame *f)
{
	// 자식 프로세스에 넘겨줄 이름과 인터럽트 프레임 복사본을 인자로 전달
	return process_fork(thread_name, f);
}

// 파일을 삭제하는 시스템 콜 구현
bool sys_remove(const char *file) {
	// 유저가 넘긴 포인터가 유효한 사용자 공간 주소인지 검증
	check_address(file);

	// 만약 포인터 자체가 NULL이면 삭제 실패 (방어 코드)
	if (file == NULL) {
		return false;
	}

	// 파일 시스템에서 파일 삭제 시도, 성공 여부 반환
	return filesys_remove(file); 
}


// 열린 파일 디스크립터 fd의 파일 크기를 바이트 단위로 반환
int sys_filesize(int fd) {
	// fd를 이용해 현재 프로세스의 파일 디스크립터 테이블에서 file 객체를 가져옴
	struct file *file = process_get_file(fd);

	// fd가 유효하지 않거나 열린 파일이 없을 경우 에러로 -1 반환
	if (file == NULL) {
		return -1;
	}

	// 파일의 전체 크기(바이트)를 반환
	return file_length(file);
}


// 시스템 콜: fd로부터 size만큼 읽어 buffer에 저장하고, 실제 읽은 바이트 수 반환
int sys_read(int fd, void *buffer, unsigned size)
{
	// 유저 공간 포인터가 유효한지 확인 (시작 주소만 검사)
	check_address(buffer);

	// buffer를 char 포인터로 변환해서 문자 단위로 접근
	char *ptr = (char *)buffer;
	int bytes_read = 0;

	// 파일 시스템 동시 접근 방지용 글로벌 락 획득
	lock_acquire(&filesys_lock);

	if (fd == STDIN_FILENO)  // 표준 입력인 경우
	{
		// 한 글자씩 키보드 입력 받아서 buffer에 저장
		for (int i = 0; i < size; i++)
		{
			*ptr++ = input_getc();  // 키보드에서 한 글자 입력 받아 저장
			bytes_read++;          // 실제 읽은 바이트 수 증가
		}
		lock_release(&filesys_lock);  // 락 해제
	}
	else
	{
		// 잘못된 fd(1: stdout, 2:stderr이거나 음수인 경우)는 읽을 수 없음 → 에러
		if (fd < 3)
		{
			lock_release(&filesys_lock);
			return -1;
		}

		// 현재 프로세스의 fd 테이블에서 해당 파일 객체 조회
		struct file *file = process_get_file(fd);
		if (file == NULL)
		{
			lock_release(&filesys_lock);
			return -1;  // 파일이 없으면 실패
		}

		// 파일에서 size만큼 읽어서 buffer에 저장
		bytes_read = file_read(file, buffer, size);

		lock_release(&filesys_lock);  // 락 해제
	}

	// 실제로 읽은 바이트 수 반환 (0 이상)
	return bytes_read;
}

// 파일 디스크립터 fd에 해당하는 열린 파일의 오프셋을 position으로 설정
void sys_seek(int fd, unsigned position) {
	// 현재 프로세스의 파일 디스크립터 테이블에서 해당 파일 객체를 가져옴
	struct file *file = process_get_file(fd);

	// 해당 fd에 열린 파일이 없다면 (유효하지 않으면) 조용히 실패 처리
	if (file == NULL) {
		return;
	}

	// 파일의 읽기/쓰기 offset을 지정된 위치로 이동
	file_seek(file, position);
}


// 파일 디스크립터 fd에 해당하는 열린 파일의 현재 오프셋(읽기/쓰기 위치)을 반환
unsigned sys_tell(int fd)
{
	// 현재 프로세스의 파일 디스크립터 테이블에서 해당 fd에 대한 파일 객체를 가져옴
	struct file *file = process_get_file(fd);

	// 파일이 유효하지 않으면 0 반환 (사실은 return -1이 더 안전할 수 있지만, 타입이 unsigned라면 0으로 방어)
	if (file == NULL)
		return 0;

	// 현재 파일의 읽기/쓰기 offset을 반환
	return file_tell(file);
}


// 파일 디스크립터 fd에 해당하는 열린 파일을 닫고, FDT에서 제거
void sys_close(int fd) {
	// 현재 프로세스의 파일 디스크립터 테이블(FDT)에서 해당 파일 포인터를 가져옴
	struct file *file = process_get_file(fd);

	// 해당 fd가 유효하지 않거나 열려 있지 않은 경우는 아무 작업 없이 종료
	if (file == NULL) {
		return;
	}

	// 파일을 닫아 관련 자원 해제
	file_close(file);

	// 현재 스레드의 FDT에서 해당 엔트리를 NULL로 설정해 제거
	thread_current()->FDT[fd] = NULL;
}


// 파일 이름(file)을 받아, initial_size만큼의 크기를 가진 새 파일을 생성함
bool sys_create(const char *file, unsigned initial_size) {
	// 유저 포인터가 유효한지 검사
	check_address(file);

	// 유저 영역 문자열을 커널 버퍼로 안전하게 복사
	char kernel_buf[NAME_MAX + 1];
    if (!strlcpy_user(kernel_buf, file, sizeof kernel_buf)) {
        return false; // 복사 실패 → 파일 이름을 읽지 못했음
    }

	// 빈 문자열이면 생성 불가
	if (strlen(kernel_buf) == 0) {
		return false;
	}

	// 루트 디렉토리 열기 (기본 디렉토리)
	struct dir *dir = dir_open_root();
	if (dir == NULL) {
		return false;
	}

	struct inode *inode;

	// 동일한 이름의 파일이 이미 존재하면 실패
    if (dir_lookup(dir, kernel_buf, &inode)) {
		dir_close(dir);
		return false;
	}
	
	// 파일 시스템 락을 잡고 생성 시도
	lock_acquire(&filesys_lock);
	bool success = filesys_create(kernel_buf, initial_size);
	lock_release(&filesys_lock);

	// 디렉토리 자원 해제
	dir_close(dir);
	return success;
}


// 유저 공간의 문자열을 커널 버퍼(dst)로 안전하게 복사 (최대 size 바이트)
// null-terminator까지 복사되면 true 반환, 실패하거나 초과하면 false
bool strlcpy_user(char *dst, const char *src_user, size_t size) {
    for (size_t i = 0; i < size; i++) {
        // 유저 공간 주소가 유효한지 확인
        check_address((void *)(src_user + i));

        // 유저 메모리에서 한 글자 읽기
        int val = get_user((const uint8_t *)src_user + i);
		if (val == -1) {
    		return false; // 잘못된 주소거나 읽기 실패
		}

		// 커널 버퍼에 문자 저장
		dst[i] = val;

		// null 문자('\0') 만나면 문자열 끝 → 복사 성공
		if (val == '\0') {
    		return true;
		}
    }

    // 만약 null 문자 없이 size를 다 채운 경우 → 강제로 null 종료, 하지만 실패 반환
    dst[size - 1] = '\0';
    return false;
}


// 파일을 열고, 해당 파일을 가리키는 새로운 파일 디스크립터를 반환
int sys_open(const char *file_name) {
	// 유저 포인터가 유효한 사용자 주소인지 확인
	check_address(file_name);

	// 파일 시스템 접근 전 lock 획득 (동시성 제어)
	lock_acquire(&filesys_lock);

	// 파일 시스템에서 파일 열기
	struct file *file = filesys_open(file_name);

	// 파일이 존재하지 않거나 열기에 실패한 경우
	if (file == NULL)
	{
		lock_release(&filesys_lock);
		return -1;
	}

	// 프로세스의 파일 디스크립터 테이블(FDT)에 파일 등록 후 fd 할당
	int fd = process_add_file(file);

	// FDT가 꽉 차서 fd 할당 실패 시 → 파일 닫고 리소스 해제
	if (fd == -1)
		file_close(file);

	// 파일 시스템 lock 해제
	lock_release(&filesys_lock);

	// 성공 시 fd 반환, 실패 시 -1
	return fd;
}


// 명령어 문자열을 받아 새로운 프로세스를 실행하고, 현재 프로세스는 그 코드로 대체됨
static tid_t sys_exec(const char *cmd_line) {
	validate_str(cmd_line);

	char *cmd_line_copy = palloc_get_page(PAL_ZERO);
	if (cmd_line_copy == NULL) {
		sys_exit(-1);
	}
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);	// 커널 버퍼에 복사 (안전성)

	if (process_exec(cmd_line_copy) == -1) {
		sys_exit(-1);
	}
}
