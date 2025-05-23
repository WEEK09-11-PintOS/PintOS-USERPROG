#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h" 
#ifdef VM
#include "vm/vm.h"
#endif

#define MAX_ARGS 128
#define MAX_BUF 128
#define FDT_COUNT_LIMIT 128


static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
static int parse_args(char *, char *[]);
static bool setup_stack(struct intr_frame *if_);
static void argument_stack(char *argv[], int argc, struct intr_frame *if_);

/* General process initializer for initd and other process. */
static void
process_init(void)
{
	struct thread *current = thread_current();

	current->FDT = palloc_get_multiple(PAL_ZERO, FDT_PAGES);
	current->running_file = NULL;
	current->next_FD = 2;
}

/* 첫 번째 사용자 프로그램인 "initd"를 FILE_NAME에서 로드하여 시작합니다.
 * 새 스레드는 스케줄링 될 수 있으며 (그리고 심지어 종료될 수도 있음)
 * process_create_initd()가 반환되기 전에.
 * initd의 스레드 ID를 반환하거나, 생성할 수 없으면 TID_ERROR를 반환합니다.
 * 이 함수는 반드시 한 번만 호출되어야 합니다. */
tid_t process_create_initd(const char *file_name)
{
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE);

	/* 이 코드를 넣어줘야 thread_name이 file name이 됩니다  */
	char *save_ptr;
	strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);
	return tid;
}

/* 첫 번째 사용자 프로세스를 시작하는 스레드 함수입니다. */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED();
}

/* 현재 프로세스를 `name`이라는 이름으로 복제합니다.
 * 새 프로세스의 스레드 ID를 반환하거나, 생성할 수 없으면 TID_ERROR를 반환합니다. */

tid_t process_fork(const char *name, struct intr_frame *if_)
{
	memcpy(&thread_current()->intr_frame, if_, sizeof(struct intr_frame));
	//스트럭쳐 말록해서 다시..?
	tid_t fork_tid = thread_create(name, PRI_DEFAULT, __do_fork, thread_current());
	if(fork_tid == TID_ERROR)
		return TID_ERROR;

	struct thread *child = get_child_by_tid(fork_tid);


	if (child != NULL) {
	sema_down(&child->fork_sema); // 자식의 초기화가 끝날 때까지 대기
	}

	

	return fork_tid;
}

#ifndef VM
/* 부모의 주소 공간을 복제하기 위해 이 함수를 pml4_for_each에 전달합니다.
 * 이 함수는 project 2에서만 사용됩니다. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *)aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: parent_page가 커널 페이지이면 즉시 반환해야 합니다. */
	if(is_kernel_vaddr(va))
		return true;

	/* 2. 부모의 page map level 4에서 VA를 해석합니다. */
	parent_page = pml4_get_page(parent->pml4, va);

	if(parent_page == NULL)
		return false;
	/* 3. TODO: 자식 프로세스를 위해 새로운 PAL_USER 페이지를 할당하고 결과를
	 *    TODO: NEWPAGE에 저장해야 합니다. */

	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if(newpage == NULL)
		return false;
	/* 4. TODO: 부모 페이지를 새 페이지에 복사하고
	 *    TODO: 부모 페이지가 쓰기 가능한지 여부를 검사합니다.
	 *    TODO: 결과에 따라 WRITABLE을 설정합니다. */

	memcpy(newpage, parent_page, PGSIZE);
	/* 5. VA 주소에 WRITABLE 권한으로 새 페이지를 자식의 페이지 테이블에 추가합니다. */

	writable = is_writable(pte);
	if (!pml4_set_page(current->pml4, va, newpage, writable))
		return false;
	return true;
}
#endif

/* 부모의 실행 컨텍스트를 복사하는 스레드 함수입니다.
 * 힌트) parent->tf는 프로세스의 사용자 영역 컨텍스트를 저장하지 않습니다.
 *       즉, 이 함수에는 process_fork의 두 번째 인자인 if_를 넘겨야 합니다. */
static void
__do_fork(void *aux)
{
	struct intr_frame if_;
	struct thread *parent = (struct thread *)aux;
	struct thread *current = thread_current();
	struct intr_frame *parent_if = &parent->intr_frame;
	bool succ = true;


	process_init();


	/* 1. CPU 컨텍스트를 지역 스택으로 복사합니다. */
	memcpy(&if_, parent_if, sizeof(struct intr_frame));

	/* 2. 페이지 테이블 복제 */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate(current);
#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: 이 아래에 코드를 작성해야 합니다.
	 * TODO: 힌트) 파일 객체를 복제하려면 include/filesys/file.h의 `file_duplicate`를 사용하세요.
	 * TODO:       이 함수가 부모의 자원을 성공적으로 복제할 때까지 부모는 fork()에서 반환되면 안 됩니다. */
	int fd_end = parent->next_FD;

	for (int fd = 0; fd < fd_end; fd++) {
		if (fd <= 2)
			current->FDT[fd] = parent->FDT[fd];
		else {
			if (parent->FDT[fd] != NULL) 
				current->FDT[fd] = file_duplicate(parent->FDT[fd]);
		}
	}

	current->next_FD = fd_end;

	if_.R.rax = 0;
	if_.ds = if_.es = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF;

	/* 마침내 새로 생성된 프로세스로 전환합니다. */
	sema_up(&current->fork_sema);
	if (succ)
		do_iret(&if_);
error:
	current->exit_status = -1;
	sema_up(&current->fork_sema);
	thread_exit();
}

/* 현재 실행 컨텍스트를 f_name으로 전환합니다.
 * 실패 시 -1을 반환합니다. */
int process_exec(void *f_name)
{
	char *argv[MAX_ARGS];
	int argc = parse_args(f_name, argv);
	bool success;

	/* intr_frame을 thread 구조체 안의 것을 사용할 수 없습니다.
	 * 이는 현재 스레드가 재스케줄될 때,
	 * 그 실행 정보를 해당 멤버에 저장하기 때문입니다. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* 현재 컨텍스트를 제거합니다. */
	process_cleanup();

	/* 그리고 이진 파일을 로드합니다. */
	ASSERT(argv[0] != NULL);
	success = load(argv[0], &_if);

	/* 로드 실패 시 종료합니다. */
	if (!success) {
		palloc_free_page(f_name);
		return -1;
	}
	argument_stack(argv, argc, &_if);
	palloc_free_page(f_name);

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true);
	/* 프로세스를 전환합니다. */
	do_iret(&_if);
	NOT_REACHED();
}

static int parse_args(char *target, char *argv[])
{
	int argc = 0;
	char *token;
	char *save_ptr; // 파싱 상태를 저장할 변수!

	for (token = strtok_r(target, " ", &save_ptr);
		 token != NULL;
		 token = strtok_r(NULL, " ", &save_ptr))
	{
		argv[argc++] = token; // 각 인자의 포인터 저장
	}
	argv[argc] = NULL; // 마지막에 NULL로 끝맺기(C 관례)

	return argc;
}

/* TID 프로세스가 종료되기를 기다리고, exit status를 반환합니다.
 * 만약 커널에 의해 종료되었다면 (즉, 예외로 인해 kill된 경우), -1을 반환합니다.
 * TID가 유효하지 않거나 호출 프로세스의 자식이 아니거나,
 * 이미 해당 TID에 대해 process_wait()가 호출된 적이 있다면,
 * 즉시 -1을 반환하고 기다리지 않습니다.
 *
 * 이 함수는 문제 2-2에서 구현될 예정입니다. 지금은 아무 것도 하지 않습니다. */
struct thread 
*get_child_by_tid(tid_t child_tid){
	struct thread *cur = thread_current();
	struct thread *v = NULL;

	for(struct list_elem *i =list_begin(&cur->children); i != list_end(&cur->children); i = i->next){
		struct thread *t = list_entry(i, struct thread, child_elem);
		if(t->tid == child_tid){
			v = t;
			break;
		}

	}
	
	return v;
}

int
process_wait (tid_t child_tid) {
	//for문으로 인자값 서치, 있으면 바로 child status 반환 없으면 블록
	enum intr_level old_level = intr_disable();
	struct thread *cur = thread_current();

	struct thread *search_cur = get_child_by_tid(child_tid);
	intr_set_level(old_level);
	if (search_cur == NULL)
		return -1;
	
	sema_down(&search_cur->wait_sema);
	int stat = search_cur->exit_status;
	list_remove(&search_cur->child_elem);

	sema_up(&search_cur->exit_sema);

	return stat;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *cur = thread_current ();

	for(int i = 3; i<cur->next_FD; i++){
		if (cur->FDT[i] != NULL)
			file_close(cur->FDT[i]);
		cur->FDT[i] = NULL;
	}
	
	// 실행 중인 파일에 대한 별도 처리 필요 ex cur->runngin_file

	palloc_free_multiple(cur->FDT, FDT_PAGES);

	file_close(cur->running_file);

	//syscall의 exit에서 exit_status 설정이 선행되어야함
	// printf("exit: %s: %d\n", thread_name(), cur->exit_status);
	
	if (cur->parent != NULL){
		sema_up(&cur->wait_sema);
	}

	//이 사이에 부모가 삭제될 수도 있으니 분기 또한 구별
	if (cur->parent != NULL){
		sema_down(&cur->exit_sema);
	}
	//근데 부모 스레드가 wait을 안걸면 어떻게 되는거지...? down이 해제가 안되나..?
	//전제 조건 1: wait / exit sema 둘다 0으로 기본 세팅 되어있어야함
	//전제 조건 2: thread_exit 내부 로직에 자식 스레드 관련 부모 삭제와 sema up 처리가 추가되어야함
	process_cleanup ();
}

/* 현재 프로세스의 자원을 해제합니다. */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* 현재 프로세스의 페이지 디렉터리를 제거하고,
	 * 커널 전용 페이지 디렉터리로 전환합니다. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{

		/* 여기서의 순서가 매우 중요합니다. 우리는
		 * cur->pagedir를 NULL로 설정한 후에 페이지 디렉터리를 전환해야 합니다.
		 * 그렇지 않으면 timer 인터럽트가 다시 프로세스의 페이지 디렉터리로 전환될 수 있습니다.
		 * 활성 페이지 디렉터리를 제거하기 전에 커널 전용 페이지 디렉터리로 전환해야 합니다.
		 * 그렇지 않으면 현재 활성 페이지 디렉터리가 제거된 것(혹은 초기화된 것)이 될 수 있습니다. */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
		// power_off();
	}
}

/* 사용자 코드 실행을 위해 CPU를 설정합니다.
 * 이 함수는 매 context switch 때마다 호출됩니다. */
void process_activate(struct thread *next)
{
	/* 스레드의 페이지 테이블을 활성화합니다. */
	pml4_activate(next->pml4);

	/* 인터럽트 처리를 위해 스레드의 커널 스택을 설정합니다. */
	tss_update(next);
}

/* ELF 실행 파일을 로드합니다.
다음 정의들은 ELF 사양서 [ELF1]에서 가져온 것입니다. */

/* ELF 타입. [ELF1] 1-2 참고. */
#define EI_NIDENT 16

#define PT_NULL 0			/* Ignore. */
#define PT_LOAD 1			/* Loadable segment. */
#define PT_DYNAMIC 2		/* Dynamic linking info. */
#define PT_INTERP 3			/* Name of dynamic loader. */
#define PT_NOTE 4			/* Auxiliary info. */
#define PT_SHLIB 5			/* Reserved. */
#define PT_PHDR 6			/* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* ELF 실행 파일의 헤더. [ELF1] 1-4 ~ 1-8 참고.
 * ELF 바이너리의 가장 앞에 위치합니다. */
struct ELF64_hdr
{
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* FILE_NAME에서 현재 스레드로 ELF 실행 파일을 로드합니다.
 * 실행 진입점은 *RIP에, 초기 스택 포인터는 *RSP에 저장됩니다.
 * 성공 시 true, 실패 시 false를 반환합니다. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;

	/* 페이지 디렉터리를 할당하고 활성화합니다. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current());

	/* 실행 파일을 엽니다. */
	file = filesys_open(file_name);
	if (file == NULL)
	{
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	/* 실행 헤더를 읽고 검증합니다. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* 프로그램 헤더들을 읽습니다. */
	file_ofs = ehdr.e_phoff;
	for (int i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

		// off_t phdr_ofs = ehdr.e_phoff + i * sizeof(struct Phdr);
		// file_seek(file, phdr_ofs);
		// if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
		// 	goto done;
		// printf("i=%d, p_type=%d, p_vaddr=0x%lx\n", i, phdr.p_type, phdr.p_vaddr);

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* 이 segment는 무시합니다. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 * Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					 * Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* 스택을 설정합니다. */
	if (!setup_stack(if_))
		goto done;

	/* 시작 주소를 설정합니다. */
	if_->rip = ehdr.e_entry;

	success = true;
	file_deny_write(file);
	t->running_file = file;
	goto done;

done:
	/* load의 성공 여부와 상관없이 여기로 도달 */
	if (!success && file != NULL)
		file_close(file); // 성공하지 못한 경우에만 닫음
	return success;
}

/* PHDR가 FILE에서 유효하고 로드 가능한 세그먼트를 설명하는지 확인하고,
 * 그렇다면 true, 아니라면 false를 반환합니다. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset과 p_vaddr은 같은 페이지 오프셋을 가져야 합니다. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset은 FILE 내부를 가리켜야 합니다. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz는 최소한 p_filesz보다 크거나 같아야 합니다. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* 세그먼트는 비어 있으면 안 됩니다. */
	if (phdr->p_memsz == 0)
		return false;

	/* 가상 메모리 영역은 사용자 주소 공간 범위 내에 있어야 합니다. */

	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* 메모리 영역은 커널 가상 주소 공간을 넘어 wrap-around 되면 안 됩니다. */

	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* 페이지 0 매핑을 금지합니다.
	 * 페이지 0을 매핑하는 것은 좋은 아이디어가 아닐 뿐만 아니라,
	 * 허용할 경우, 사용자 코드가 null 포인터를 시스템 콜에 넘길 때
	 * 커널에서 null 포인터 예외 (ex: memcpy 등)로 패닉이 발생할 수 있습니다. */

	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* 이 블록의 코드는 project 2에서만 사용됩니다.
 * 전체 project 2를 위해 이 함수를 구현하려면, #ifndef 바깥에 구현하세요. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* segment를 FILE의 OFS 오프셋에서 UPAGE 주소에 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다:
 *
 * - READ_BYTES 바이트는 FILE에서 읽어옵니다.
 * - UPAGE + READ_BYTES 위치에서 ZERO_BYTES 바이트를 0으로 초기화합니다.
 *
 * 이 함수로 초기화된 페이지는 WRITABLE이 true이면 사용자 프로세스가 수정할 수 있으며,
 * 아니라면 읽기 전용입니다.
 *
 * 성공 시 true, 메모리 할당 오류나 디스크 읽기 오류 발생 시 false를 반환합니다. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* 이 페이지를 어떻게 채울지 계산합니다.
		 * FILE에서 PAGE_READ_BYTES 바이트를 읽고
		 * 남은 PAGE_ZERO_BYTES 바이트는 0으로 초기화합니다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* 메모리 한 페이지를 가져옵니다. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* 이 페이지를 로드합니다. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* 프로세스 주소 공간에 페이지를 추가합니다. */
		if (!install_page(upage, kpage, writable))
		{
			printf("install page 실패: upage = %p\n", upage);
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* 한 페이지씩 앞으로 진행합니다. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* USER_STACK 위치에 zero 페이지를 매핑하여 최소한의 스택을 생성합니다. */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	/* USER_STACK : 유저 스택의 최상단 주소, 즉 맨 마지막 페이지 (아래로 자라니까) */
	kpage = palloc_get_page(PAL_USER | PAL_ZERO); // 유저 공간에, 0으로 초기화된 페이지 할당
	if (kpage != NULL)
	{
		/* 유저 스택의 맨 마지막 페이지를 매핑 */
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK; /* 유저 스택 포인터 (rsp)를 맨 위로 지정 */
		else
			palloc_free_page(kpage); /* 실패하면 할당받은 페이지를 free */
	}
	return success;
}

/* 사용자 가상 주소 UPAGE를 커널 가상 주소 KPAGE에 매핑합니다.
 * WRITABLE이 true이면 사용자 프로세스는 해당 페이지를 수정할 수 있습니다.
 * 아니라면 읽기 전용입니다.
 * UPAGE는 이미 매핑되어 있으면 안 됩니다.
 * KPAGE는 보통 palloc_get_page()로 얻은 페이지여야 합니다.
 * 성공 시 true, 실패 시 false를 반환합니다. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}

static void argument_stack(char *argv[], int argc, struct intr_frame *if_) {
	uint64_t rsp_arr[argc];

	// 문자열 역순 복사 및 rsp push
	for (int i = argc - 1; i >= 0; i--)
	{
		size_t len = strlen(argv[i]) + 1;
		if_->rsp -= len;
		rsp_arr[i] = if_->rsp;
		memcpy((void *)if_->rsp, argv[i], len);
	}

	// 16바이트 정렬
	if_->rsp = if_->rsp & ~0xF;

	// NULL sentinel
    if_->rsp -= 8;
	memset(if_->rsp, 0, sizeof(char **));
    // *(uint64_t *)if_->rsp = 0;

    // argv[i] 포인터들 (역순 push)
	for (int i = argc - 1; i >= 0; i--)
	{
		if_->rsp -= 8; // 8바이트만큼 rsp감소
		memcpy(if_->rsp, &rsp_arr[i], sizeof(char **));
		// *(uint64_t *)if_->rsp = (uint64_t)argv_addr[i];
	}

	/* fake return address */
	if_->rsp -= 8;
	memset(if_->rsp, 0, sizeof(void *));
	// *(uint64_t *)if_->rsp = 0;

	// intr_frame 갱신
	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp + 8;
}

// 주어진 file 객체를 FDT에서 비어 있는 슬롯에 추가하고, 할당된 fd를 반환
// 실패 시 -1 반환
int process_add_file(struct file *file) {
	struct thread *curr = thread_current();

	// fd는 0(stdin), 1(stdout), 2(stderr)을 건너뛰고 3부터 시작
	for (int fd = 3; fd < MAX_FD; fd++) {
		// 비어 있는 슬롯 찾기
		if (curr->FDT[fd] == NULL) {
			curr->FDT[fd] = file;  // 파일 등록
			if (curr->next_FD <= fd)
				curr->next_FD = fd + 1;
			return fd;             // 해당 fd 반환
		}
	}
	return -1;  // 여유 공간 없음 → 실패
}


// 주어진 fd에 해당하는 파일 객체를 반환
// 유효하지 않거나 열려 있지 않으면 NULL 반환
struct file *process_get_file(int fd) {
	struct thread *curr = thread_current();

	// stdin(0), stdout(1), stderr(2)은 시스템 콜에서 직접 처리하므로 제외
	// 유효한 범위가 아니면 NULL
	if (fd < 3 || fd >= MAX_FD) {
		return NULL;
	}

	// FDT에서 해당 fd 위치의 파일 반환
	return curr->FDT[fd];
}


// 주어진 fd에 해당하는 열린 파일을 닫고 FDT에서 제거
void process_close_file(int fd) {
	struct thread *curr = thread_current();
	
	// stdin, stdout, stderr 제외 + 유효한 범위인지 확인
	if (fd >= 3 && fd < MAX_FD) {
		// 실제로 열려 있는 파일이 있으면 닫기
		if (curr->FDT[fd] != NULL) {
			file_close(curr->FDT[fd]);      // 파일 자원 해제
			curr->FDT[fd] = NULL;           // FDT에서 제거
		}
	}
}

// 현재 프로세스가 열고 있는 모든 파일을 닫고 FDT를 초기화
void process_close_all_files(void) {
	struct thread *curr = thread_current();

	// fd = 3 이상부터 시작 → 유저 파일 디스크립터만 닫음
	for (int fd = 3; fd < MAX_FD; fd++) {
		if (curr->FDT[fd] != NULL) {
			file_close(curr->FDT[fd]);      // 파일 닫기
			curr->FDT[fd] = NULL;           // 슬롯 초기화
		}
	}
}


#else
/* 여기부터 코드는 project 3 이후 사용됩니다.
 * project 2만을 위해 함수를 구현하려면 위쪽 블록에서 구현하세요. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
											writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
