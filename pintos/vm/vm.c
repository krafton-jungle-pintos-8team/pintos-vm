/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include "threads/malloc.h"
#include "vm/inspect.h"

unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) {
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */

        /* TODO: Insert the page into the spt. */
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    /* TODO: Fill this function. */
    /*
        목적: spt 구조체를 활용하여 page를 찾는다.
        
        1. hash를 이용해 page를 받아오기 위해선 hash를 반복 시켜야한다.
        2. hash_iterator 라는 구조체가 있고 이를 활용하면 되지 않을까?
        3. hash_first 를 통해 첫번째 hash를 받아와 반복한다.
    */    

    struct hash_iterator hash_iter;
    // hash, bucket, elem(head) 초기화 - 순회를 시작할 준비만 한다..?
    hash_first(&hash_iter, &spt->pages);

    // hash_next 이후 첫 번째 요소를 얻는다. 그러므로, 모든 요소 순회 가능
    while (hash_next (&hash_iter)) {  
        struct page *page = hash_entry(hash_cur(&hash_iter), struct page, hash_elem);
        if (page->va == va) {
            return page;
        }
    }
    return NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
    /* TODO: Fill this function. */
    // find page
    if (spt_find_page(spt, page->va) != NULL) {
        return false;
    }

    // insert page
    if (hash_insert(&spt->pages, &page->hash_elem) != NULL) {
        return false;
    }

    return true;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* 
    한 페이지를 축출하고 해당 프레임을 반환합니다.
    오류가 발생하면 NULL을 반환합니다.
*/
static struct frame *vm_evict_frame(void) {
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* 
palloc()을 사용하여 프레임을 가져옵니다. 
사용 가능한 페이지가 없으면 페이지를 축출(evict)하고 반환합니다. 
이 함수는 항상 유효한 주소를 반환합니다. 
즉, 사용자 풀 메모리가 가득 찬 경우, 
이 함수는 사용 가능한 메모리 공간을 확보하기 위해 프레임을 축출합니다.
*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = NULL;
    /* TODO: Fill this function. */
    /*
        1. palloc으로 프레임을 가져온다.
        2. 사용 가능한 페이지가 없다? (메모리가 부족한 경우)
            - 사용자 풀의 공간이 모두 할당되었다는 의미인가?
            - 그럼 page fault가 발생할거 같음.
        3. 프레임 축출(evict policy 축출 정책)을 사용하여 페이지 축출
    */
    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED,
                         bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */

    return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {
    struct page *page = NULL;
    /* TODO: Fill this function */
    /* 
        주어진 가상 주소 va에 대해 페이지를 확보한다. 
        페이지를 확보한다?
        페이지를 할당한다?
        그럼 page에 va를 넣으면 되는거 아닌가?
        그리고 page를 보내면 끝?
    */
    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
    struct frame *frame = vm_get_frame();
    /*
        1. 페이지에 물리 프레임을 할당
        2. vm_get_frame을 호출하여 프레임을 확보한 뒤, MMU 설정
        3. 가상 주소 -> 물리 주소 매핑, 매핑 성공 여부 반환
    */
    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: page table entry를 삽입하여 페이지의 VA를 프레임의 PA에 매핑합니다. */

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
}

/* 추가한 함수들 by git book 08.04 */
/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}