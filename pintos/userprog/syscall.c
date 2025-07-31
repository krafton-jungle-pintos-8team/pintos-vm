#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/lib/user/syscall.h"
#include "include/userprog/process.h"
#include "include/filesys/filesys.h"
#include "filesys/file.h"
#include "../include/threads/synch.h"
#include <string.h>
#define ERROR_NUM -1
#define NAME_MAX 14
#define FILE_START 3
#define FILE_LIMIT 128

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void check_bad_ptr(const void *check_ptr);
static int get_filesize(int fd);

static struct lock file_lock;

/* 시스템 콜.
 *
 * 이전에는 시스템 콜 서비스가 인터럽트 핸들러에 의해 처리되었습니다
 * (예: 리눅스의 int 0x80). 하지만 x86-64에서는 제조사가 시스템 콜을
 * 요청하는 효율적인 경로인 `syscall` 명령어를 제공합니다.
 *
 * syscall 명령어는 모델 특정 레지스터(MSR)에서 값을 읽어서 작동합니다.
 * 자세한 내용은 매뉴얼을 참조하세요. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* 인터럽트 서비스 루틴은 syscall_entry가 사용자 스택을 커널 모드
	 * 스택으로 교체할 때까지 어떤 인터럽트도 처리하지 않아야 합니다.
	 * 따라서 FLAG_FL을 마스크했습니다. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	 uint64_t sys_num = f->R.rax; // 시스템 콜 번호 가져오기
	switch (sys_num)
	{
	case SYS_HALT:
		sys_halt();
		break;
	case SYS_EXIT:
		sys_exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = sys_fork (f->R.rdi, f);
		break;
	case SYS_EXEC:
		f->R.rax = sys_exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = sys_wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = sys_create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = sys_remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = sys_open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = sys_filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		sys_seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = sys_tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		sys_close(f->R.rdi);
		break;
	default:
		thread_exit ();
	}
}

void sys_halt() {
	power_off();
}

void sys_exit(int status) {
	struct thread *t = thread_current();
	/* 종료 상태 저장 */
	t->exit_status = status;
	thread_exit();	
}

tid_t sys_fork (const char *thread_name, struct intr_frame *f) {
	/*
		1. create new process clone of current process : process_fork 실행
		2. don't need to clone the value of the registers : __do_fork 2번에서 실행 
		- need %rbx, %rsp, %rbp %r12 - %r15 (호출된 레지스터)
		3. must return child process valid pid : valid pid는 어떤 pid이지?
		4. 하위 프로세스에서 반환 값이 0이여야 한다. : 이건 무슨 말일까?
		5. child는 부모의 자원 file, memory를 포함해야 한다. : __do_fork에서 1번에서 Memory 복사, file 복사
		6. 부모 프로세스는 자식 프로세스의 클론이 성공할 때까지 절대 return 되서는 안된다. : sema로 lock되어 있는
		7. 자식 프로세스가 부모의 자원 복사를 실패하면 return TID_ERROR
	*/
	check_bad_ptr(thread_name);
	return process_fork(thread_name, f);
}

int sys_wait (tid_t tid) {
	return process_wait(tid);
}

int sys_exec (const char *cmd_line) {
	/* 
		- 현재 프로세스를 `cmd_line`에 명시된 실행 파일로 교체하고, 그 인자들을 전달합니다.
		- 실행에 성공하면 이 함수는 복귀하지 않고, 실패하면 `exit(-1)`로 종료됩니다.
		- 이 함수는 호출한 스레드의 이름은 변경하지 않습니다. 
			파일 디스크립터는 `exec` 호출 후에도 유지됩니다.
	*/
	check_bad_ptr(cmd_line);

	char *cmd_line_copy = palloc_get_page(0); // page를 0으로 초기화 후 받음
	if (cmd_line_copy == NULL) {
		sys_exit(-1);
	}
		
	/* cmd_line 복사 */
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	/* 로드되거나 실행될 수 없는 경우 */
	if (process_exec(cmd_line_copy) == -1) {
		sys_exit(-1);
	}
}

bool sys_create (const char *file, unsigned initial_size) { 
	struct thread *curr = thread_current();
	check_bad_ptr((char *)file);

	if (strlen(file) > NAME_MAX)
		return false;
	
	lock_acquire(&file_lock);
	bool result = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return result;
}

bool sys_remove(const char *file) {
	check_bad_ptr(file); /* 유효성 검사 */
	
	return filesys_remove(file);
}

int sys_open (const char *file) {
	struct thread *curr = thread_current();
	int result;

	check_bad_ptr((char *)file); /* null, user address, boundary 검사*/

	lock_acquire(&file_lock);
	struct file *open_file = filesys_open(file); // 성공 시 파일 반환, 실패 시 NULL
	lock_release(&file_lock);

	if (open_file == NULL)
		return ERROR_NUM;

	

	for (int i=FILE_START; i<curr->fd; i++) {
		if (curr->fdt[i] == NULL) {
			curr->fdt[i] = open_file;
			return i;
		}
	}
	
	return -1;
}

int sys_write (
    int fd,
    const void *buffer,
    unsigned length
) {
	check_bad_ptr(buffer);

	if (fd == 1)
		/// TODO: 표준 출력 (콘솔).  
		// return 읽은 바이트 수
		putbuf((char *) buffer, length);
	else if (fd < FILE_START || fd > FILE_LIMIT) 
		return ERROR_NUM;
	else {
		struct file *curr_fd = thread_current()->fdt[fd];
		if (curr_fd == NULL)
			return ERROR_NUM;

		lock_acquire(&file_lock);
		file_write(curr_fd, buffer, length);
		lock_release(&file_lock);
	}

	return length;
}

int sys_filesize(int fd) {
	return get_filesize(fd);
}

int sys_read(int fd, void *buffer, unsigned size) {
	check_bad_ptr(buffer);		// bad_ptr일 경우 exit 종료

	if (fd == 0) {
		for (int i=0; i<size; i++) 
			*((char *)buffer + i) = input_getc();
	}
	else if (fd < FILE_START || fd > FILE_LIMIT) {
		return ERROR_NUM;
	}
	else {
		struct file *curr_fd = thread_current()->fdt[fd];
		if (curr_fd == NULL)
			return ERROR_NUM;

		lock_acquire(&file_lock);
		file_read(curr_fd, buffer, size);
		lock_release(&file_lock);
	}
	return size;
}

void sys_seek(int fd, unsigned position) {
	struct file *curr_fd = thread_current()->fdt[fd];

	if (curr_fd == NULL)
		sys_exit(-1);
	
	file_seek(curr_fd, position);
}

unsigned sys_tell(int fd) {
	struct file *curr_fd = thread_current()->fdt[fd];

	if (curr_fd == NULL)
		sys_exit(-1);

	return file_tell(curr_fd);
}

void sys_close(int fd) {
	/* 
		종료될 때 생각해야 할 것
		1. fd의 값이 유효한 값인가?
		2. 중복 close가 될 수 있기 때문에 status가 이미 닫힌 상태인가?
		3. bad_fd를 방지하기 위해서는 fd값이 유효하지 않다는 것인데 
	*/
	struct thread *curr = thread_current();
	if (fd < FILE_START || fd > FILE_LIMIT)
		return;

	struct file *close_file = curr->fdt[fd];
	if (close_file == NULL)
		return;
		
	lock_acquire(&file_lock);
	file_close(close_file);
	curr->fdt[fd] = NULL; /* 사용 후 NULL로 값 변경 */
	lock_release(&file_lock);
}

static void check_bad_ptr(const void *check_ptr) {
	// struct thread *curr = thread_current();
	if (check_ptr == NULL  
		|| !is_user_vaddr(check_ptr)
		// || !is_user_base_vaddr(check_ptr) // 추가로 만든 매크로 함수
		|| pml4_get_page(thread_current()->pml4, check_ptr) == NULL
	) 
		sys_exit(ERROR_NUM);	
}

static int get_filesize(int fd) {
	struct file *curr_fd = thread_current()->fdt[fd];
	if (fd < FILE_START 
		|| fd > FILE_LIMIT 
		|| curr_fd == NULL)
		return ERROR_NUM;
	
	return file_length(curr_fd);
}