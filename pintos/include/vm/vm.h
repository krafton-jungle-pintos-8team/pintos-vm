#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/vm_type.h"
#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#include "vm/uninit.h"
#include "vm/vm_type.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

/* 프레임 테이블은 무엇이 필요할까?
    1. 프레임들을 담을 수 있는 리스트, 이걸 hash로 갖고 있어도 괜찮나?
    그리고 또?
*/
struct frame_table {
    struct list frames;
};

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
struct page {
    const struct page_operations *operations;
    void *va;              /* 사용자 공간의 주소 */
    struct frame *frame;   /* 해당 프레임에 대한 역참조 */

    /* Your implementation */
    struct hash_elem hash_elem;
    bool writable;

    /* Per-type data are binded into the union.
     * Each function automatically detects the current union */
    union {
        struct uninit_page uninit;
        struct anon_page anon;
        struct file_page file;
#ifdef EFILESYS
        struct page_cache page_cache;
#endif
    };
};

/* The representation of "frame" */
/* 프레임 관리 인터페이스를 구현하는 과정에서 더 많은 멤버를 추가해도 됩니다. */
struct frame {
    void *kva;
    struct page *page;
    // 추가된 멤버 변수 프레임 마다 관리하여 clock algorithm 구현 시 사용
    bool reference_bit;
    struct list_elem elem; // 프레임 테이블에 넣기 위한 리스트 요소
};

/* 페이지 작업을 위한 함수 테이블입니다.
이것은 C에서 "인터페이스"를 구현하는 한 가지 방법입니다.
구조체의 멤버로 메서드(함수) 테이블을 넣고,
필요할 때마다 해당 함수를 호출하면 됩니다. */
struct page_operations {
    bool (*swap_in)(struct page *, void *);
    bool (*swap_out)(struct page *);
    void (*destroy)(struct page *);
    enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in((page), v)
#define swap_out(page) (page)->operations->swap_out(page)
#define destroy(page)                \
    if ((page)->operations->destroy) \
    (page)->operations->destroy(page)

/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */
struct supplemental_page_table {
    struct hash pages;
    struct lock spt_lock;
};

#include "threads/thread.h"
void supplemental_page_table_init(struct supplemental_page_table *spt);
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src);
void supplemental_page_table_kill(struct supplemental_page_table *spt);
struct page *spt_find_page(struct supplemental_page_table *spt, void *va);
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page);
void spt_remove_page(struct supplemental_page_table *spt, struct page *page);

void vm_init(void);
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
    vm_alloc_page_with_initializer((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux);
void vm_dealloc_page(struct page *page);
bool vm_claim_page(void *va);
enum vm_type page_get_type(struct page *page);

/* 여기로 옮겨서 사용해야 하나 for anon.c 08.08 */
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
void page_destructor(struct hash_elem *e, void *aux);

#endif /* VM_VM_H */
