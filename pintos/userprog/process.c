#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"

#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
/**
 현재 스레드의 자식 프로세스 중에서 특정 PID를 가진 자식을 찾는 함수
 */
struct thread *get_child_with_pid(tid_t pid) {
    struct thread *curr = thread_current();  // 현재 실행 중인 스레드(부모) 가져오기
    struct list_elem *e;                     // 리스트 순회용 요소 포인터

    /* 현재 스레드의 자식 리스트를 순회하며 해당 PID를 가진 자식 찾기 */
    for (e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = list_next(e)) {
        /* list_elem에서 실제 thread 구조체 포인터 추출 */
        struct thread *child = list_entry(e, struct thread, child_elem);

        /* 찾는 PID와 자식의 TID가 일치하는지 확인 */
        if (child->tid == pid) {
            return child;  // 일치하면 해당 자식 스레드 반환
        }
    }

    return NULL;  // 해당 PID를 가진 자식을 찾지 못한 경우 NULL 반환
}
/* General process initializer for initd and other process. */
static void process_init(void) {
    struct thread *current = thread_current();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
    char *fn_copy;
    tid_t tid;

    /* Make a copy of FILE_NAME.
     * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    // 원본 file_name 은 수정하면 안되므로, 복사본 thread_name 만들기
    char thread_name[16];
    strlcpy(thread_name, file_name, sizeof(thread_name));

    // 복사본인 thread_name 파싱
    char *save_ptr;
    strtok_r(thread_name, " ", &save_ptr);

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(thread_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR)
        palloc_free_page(fn_copy);
    return tid;
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif

    process_init();

    if (process_exec(f_name) < 0)
        PANIC("Fail to launch initd\n");

    NOT_REACHED();
}

// ../userprg/process.c

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) {
    struct thread *curr = thread_current();  // 부모 쓰레드 가져오기

    /* 부모의 인터럽트 프레임을 저장(복사용임) */
    curr->parent_if = if_;

    // 새 스레드 생성
    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, curr);
    if (tid == TID_ERROR) {
        return TID_ERROR;
    }

    /* 방금 생성한 자식 프로세스를 자식 리스트에서 찾기 */
    struct thread *child = get_child_with_pid(tid);

    // 생성 대기
    sema_down(&child->fork_sema);

    if (child->exit_status == -1)
        return TID_ERROR;

    return tid;
}

#ifndef VM

static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    if (is_kernel_vaddr(va))
        return true;
    /* 2. 부모의 페이지 맵 레벨 4에서 VA를 해결합니다. */
    /* 2. Resolve VA from the parent's page map level 4. */
    parent_page = pml4_get_page(parent->pml4, va);
    if (parent_page == NULL) {
        return false;
    }

    newpage = palloc_get_page(PAL_USER);
    if (newpage == NULL) {
        return false;
    }

    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);
    /* 5. 새 페이지를 주소 VA에 WRITABLE 권한으로 자식의 페이지 테이블에 추가합니다. */
    /* 5. Add new page to child's page table at address VA with WRITABLE
     *    permission. */
    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        palloc_free_page(newpage);
        return false;
    }
    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
/* 자식 프로세스에서 실행되는 함수 - 부모 프로세스의 실행 컨텍스트를 복제
 * thread_create로 생성된 새 스레드가 실행하는 함수
 *
 * @param aux: 부모 스레드의 포인터 (process_fork에서 전달)
 */
static void __do_fork(void *aux) {
    struct intr_frame if_;                             // 자식이 사용할 인터럽트 프레임
    struct thread *parent = (struct thread *)aux;      // 부모 스레드 포인터
    struct thread *current = thread_current();         // 현재 스레드(자식)
    struct intr_frame *parent_if = parent->parent_if;  // 부모의 실행 컨텍스트
    bool succ = true;                                  // 성공 여부 플래그

    /* 부모의 CPU 컨텍스트를 자식의 로컬 스택으로 복사 */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));
    if_.R.rax = 0;  // 자식 프로세스는 fork()에서 0을 반환받음

    /* 페이지 테이블 복제 - 메모리 공간 복사 */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL) {
        succ = false;
        goto error;
    }

    process_activate(current);  // 새로운 페이지 테이블 활성화

#ifdef VM
    /* 가상 메모리 사용 시: 보조 페이지 테이블 초기화 및 복사 */
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt)) {
        succ = false;
        goto error;
    }
#else
    /* 기본 페이징 시: 부모의 모든 페이지를 자식으로 복사 */
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) {
        succ = false;
        goto error;
    }
#endif

    /* 3. 파일 디스크립터 테이블(FDT) 복제 */
    for (int fd = 0; fd < FDT_MAX_SIZE; fd++) {
        struct file *file = parent->fdt[fd];
        if (file == NULL) {
            continue;
        }
        struct file *new_file;
        if (fd <= 1) {
            new_file = file;
        } else {
            /* 일반 파일은 새로운 파일 객체로 복제 */
            new_file = file_duplicate(file);
            if (new_file == NULL) {
                succ = false;
                goto error;
            }
        }
        current->fdt[fd] = new_file;
    }
    current->fd_idx = parent->fd_idx;

    /* 성공적으로 완료되면 부모에게 알리기 */
    if (succ) {
        current->exit_status = 0;
        sema_up(&current->fork_sema);
    }
    do_iret(&if_);

error:
    current->exit_status = -1;     // 실패 상태로 설정
    sema_up(&current->fork_sema);  // 실패 알리기
    thread_exit();                 // 자식 스레드 종료
}

// 유저 스택에 파싱된 토큰을 저장하는 함수 - 수정 07.22

static void argument_stack(char **argv, int argc, struct intr_frame *if_, void *buffer) {
    char **arg_addresses = buffer;

    // 1. 문자열 데이터 저장 (역순)
    for (int i = argc - 1; i >= 0; i--) {
        int str_len = strlen(argv[i]) + 1;
        if_->rsp -= str_len;
        memcpy(if_->rsp, argv[i], str_len);
        arg_addresses[i] = (char *)if_->rsp;
    }

    // 2. 패딩 정렬
    int padding = if_->rsp % 8;
    if (padding != 0) {
        if_->rsp -= padding;
        memset(if_->rsp, 0, padding);
    }

    // 3. argv 배열 저장 (역순)
    if_->rsp -= sizeof(char *);
    *(uint64_t *)if_->rsp = 0;  // argv[argc] (NULL)

    for (int i = argc - 1; i >= 0; i--) {
        if_->rsp -= sizeof(char *);
        *(char **)if_->rsp = arg_addresses[i];
    }

    // 4. 레지스터 설정
    if_->R.rdi = argc;
    if_->R.rsi = if_->rsp;

    // 5. 가짜 반환 주소 push => 함수 호출규약 준수

    if_->rsp -= sizeof(void *);
    *(uint64_t *)if_->rsp = 0;
}

// 현재 실행 프로세스 내용 파괴 & 덮어쓰기
// 현재 실행 컨텍스트를 f_name 으로 스위칭한다. (실패시 -1 return)
int process_exec(void *f_name) {
    char *file_name = f_name;
    bool success;
    struct intr_frame _if;

    // 임시 버퍼를 위한 페이지를 한 번만 할당
    void *buffer = palloc_get_page(0);
    if (buffer == NULL) {
        palloc_free_page(f_name);
        return -1;
    }
    char **arg_list = buffer;

    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    /* We first kill the current context */
    process_cleanup();

    char *ptr, *arg;
    int arg_cnt = 0;

    for (arg = strtok_r(file_name, " ", &ptr); arg != NULL; arg = strtok_r(NULL, " ", &ptr)) {
        if (arg_cnt >= 512) {
            break;
        }

        arg_list[arg_cnt++] = arg;
    }

    // 파싱된 인자가 없으면 로드 실패 처리
    if (arg_cnt == 0) {
        success = false;
    } else {
        success = load(arg_list[0], &_if);
    }

    // 로드 실패 시 할당된 모든 페이지를 해제
    if (!success) {
        palloc_free_page(buffer);
        palloc_free_page(f_name);
        return -1;
    }

    argument_stack(arg_list, arg_cnt, &_if, buffer);

    // 모든 임시 메모리를 해제
    palloc_free_page(buffer);
    palloc_free_page(f_name);

    /* Start switched process. */
    do_iret(&_if);
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid) {
    /*
     문제점 : OS가, 프로세스가 끝나는것을 기다리지 않고 먼저 종료됨

     목표 : 자식 프로세스가 끝날 때까지 부모 프로세스를 잠시 대기(block) 시켜놓고
     자식이 종료되면 그 상태 값을 받아 오기

     부모가 fork(), wait() -> 자식이 exit() 할때까지 대기
    */
    struct thread *cur = thread_current();
    struct thread *child_thread = NULL;

    // 1. 현재 프로세스의 child_list 중, child_tid 를 가진 자식 쓰레드 찾기
    struct list_elem *e;
    for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e)) {
        // list_entry 통해서 쓰레드 구조체의 주소 얻기
        struct thread *t = list_entry(e, struct thread, child_elem);
        if (t->tid == child_tid) {
            child_thread = t;
            break;
        }
    }

    // 못찾았으면 -1 리턴
    if (child_thread == NULL) {
        return -1;
    }

    //  wait-twice.c TC 통과 위해서, 이미 wait이 호출된 자식인지 확인
    if (child_thread->is_waited) {
        return -1;
    }
    // wait 호출여부 표시
    child_thread->is_waited = true;

    // 자식 프로세스가 종료될 때까지 부모는 대기
    sema_down(&child_thread->wait_sema);

    // 자식의 종료 상태 가져오기
    int exit_status = child_thread->exit_status;

    // 자식 리스트에서 제거
    list_remove(&child_thread->child_elem);

    // 자식이 exit() 호출 -> 부모를 깨움
    sema_up(&child_thread->exit_sema);

    return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
    struct thread *curr = thread_current();
    /* TODO: Your code goes here.
     * TODO: Implement process termination message (see
     * TODO: project2/process_termination.html).
     * TODO: We recommend you to implement process resource cleanup here. */

    // 모든 FDT 닫기
    for (int i = 2; i < FDT_MAX_SIZE; i++) {
        if (curr->fdt[i] != NULL) {
            file_close(curr->fdt[i]);
        }
    }
    palloc_free_page(curr->fdt);  // fdt 메모리 해제

    if (curr->running_file != NULL) {
        // file_allow_write(curr->running_file);
        file_close(curr->running_file);  // 실행 중인 파일 닫기
    }

    /* 자식 프로세스가 종료될 때 부모에게 알리기 */
    if (curr->parent != NULL) {
        /* 부모가 wait 중이라면 깨우기 */
        sema_up(&curr->wait_sema);
        /* 부모가 자식 정리를 완료할 때까지 대기 */
        sema_down(&curr->exit_sema);
    }

     process_cleanup();
}

/* Free the current process's resources. */
static void process_cleanup(void) {
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);
#endif

    uint64_t *pml4;
    /* Destroy the current process's page directory and switch back
     * to the kernel-only page directory. */
    pml4 = curr->pml4;
    if (pml4 != NULL) {
        /* Correct ordering here is crucial.  We must set
         * cur->pagedir to NULL before switching page directories,
         * so that a timer interrupt can't switch back to the
         * process page directory.  We must activate the base page
         * directory before destroying the process's page
         * directory, or our active page directory will be one
         * that's been freed (and cleared). */
        curr->pml4 = NULL;
        pml4_activate(NULL);
        pml4_destroy(pml4);
    }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
    /* Activate thread's page tables. */
    if (next->pml4 != NULL) {
        pml4_activate(next->pml4);
    } else {
        pml4_activate(NULL);
    }

    /* Set thread's kernel stack for use in processing interrupts. */
    tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
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

struct ELF64_PHDR {
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

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char *file_name, struct intr_frame *if_) {
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pml4 = pml4_create();
    if (t->pml4 == NULL)
        goto done;
    process_activate(thread_current());

    /* Open executable file. */
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    /* ===== 수정 부분 시작  07.29 ===== */

    // 쓰기 권한 금지
    file_deny_write(file);

    // 현재 스레드에 실행 파일 정보 저장
    t->running_file = file;

    /* ===== 수정 부분 끝  ===== */

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 0x3E  // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment(&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                         * Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                    } else {
                        /* Entirely zero.
                         * Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void *)mem_page, read_bytes, zero_bytes,
                                      writable))
                        goto done;
                } else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(if_))
        goto done;

    /* Start address. */
    if_->rip = ehdr.e_entry;

    /* TODO: Your code goes here.
     * TODO: Implement argument passing (see project2/argument_passing.html). */

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t)file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            printf("fail\n");
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    return (pml4_get_page(t->pml4, upage) == NULL &&
            pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        void *aux = NULL;
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment, aux))
            return false;

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
    bool success = false;
    void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

    /* TODO: Map the stack on stack_bottom and claim the page immediately.
     * TODO: If success, set the rsp accordingly.
     * TODO: You should mark the page is stack. */
    /* TODO: Your code goes here */

    return success;
}
#endif /* VM */
