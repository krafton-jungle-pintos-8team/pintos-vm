/* vm.c: Generic interface for virtual memory objects. */

#include <debug.h>
#include <string.h>

#include "vm/vm.h"
#include "threads/mmu.h"
#include "threads/malloc.h"
#include "vm/inspect.h"

unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

static struct frame_table ft;

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

    // 프레임 테이블 초기화
    list_init(&ft.frames);
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

/* 초기화 함수를 사용해 **대기 중인 페이지 객체(pending page object)**를 생성한다.
만약 페이지를 생성하고 싶다면, 직접 생성하지 말고 이 함수나 vm_alloc_page를 통해 만들어야 한다. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) {

    // 메모리를 실제로 할당하지 않고, 초기화할 페이지가 필요하다고 등록만 한다.
    ASSERT(VM_TYPE(type) != VM_UNINIT);

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check whether the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */

        /* TODO: Insert the page into the spt. */
        struct page *page = malloc(sizeof(struct page));
        if (type == VM_ANON) {
            uninit_new(page, upage, init, type, aux, anon_initializer);
            page->writable = writable;
        }
        else if (type == VM_FILE){
            uninit_new(page, upage, init, type, aux, file_backed_initializer);
            page->writable = writable;
        }

        /* TODO: Insert the page into the spt. */

        if (!spt_insert_page(spt, page)) {
            goto err;
        }
    }
    return true;
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
// spt 안에 있는 해시 테이블을 직접 순회하면서, va와 일치하는 struct page를 찾아서 리턴하는 함수
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    /* TODO: Fill this function. */
    /*
        목적: spt 구조체를 활용하여 page를 찾는다.
        
        1. hash를 이용해 page를 받아오기 위해선 hash를 반복 시켜야한다.
        2. hash_iterator 라는 구조체가 있고 이를 활용하면 되지 않을까?
        3. hash_first 를 통해 첫번째 hash를 받아와 반복한다.
    */    

    // hash_iterator는 해시 테이블을 순회할 때 사용하는 구조체
    lock_acquire(&spt->spt_lock);
    struct hash_iterator hash_iter;
    // hash, bucket, elem(head) 초기화 - 순회를 시작할 준비만 한다..?
    hash_first(&hash_iter, &spt->pages); // 순회를 시작할 준비만 해 줌(아직 아무것도 가리키지 않음)

    // hash_next 이후 첫 번째 요소를 얻는다. 그러므로, 모든 요소 순회 가능
    while (hash_next (&hash_iter)) {  
        // hash_next()를 호출하면 다음 요소로 이동하면서, 내부 포인터가 그 요소를 가리킴.
        // hash_cur()로 현재 요소(해시 테이블에 들어있는 하나의 hash_elem)를 가져옴.
        // hash_entry()는 이 해시 요소가 속한 전체 struct page 객체를 반환해줌.
        // 그런 다음, 그 page->va가 우리가 찾는 주소와 같으면 return page.
        struct page *page = hash_entry(hash_cur(&hash_iter), struct page, hash_elem);
        if (page->va == va) {
            lock_release(&spt->spt_lock);
            return page;
        }
    }
    lock_release(&spt->spt_lock);
    return NULL;
}

/* spt에 page를 중복 없이 삽입하려는 함수 */
// 이미 같은 va를 가진 page가 들어있으면 삽입하지 않음.
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
    /* TODO: Fill this function. */
    // find page
    if (spt_find_page(spt, page->va) != NULL) {
        return false;
    }

    lock_acquire(&spt->spt_lock);
    // insert page
    if (hash_insert(&spt->pages, &page->hash_elem) != NULL) {
        lock_release(&spt->spt_lock);
        return false;
    }
    lock_release(&spt->spt_lock);
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
    /* TODO: Fill this function. */
    /*
        1. palloc으로 프레임을 가져온다.
        2. 사용 가능한 페이지가 없다? (메모리가 부족한 경우)
            - 사용자 풀의 공간이 모두 할당되었다는 의미인가?
            - 그럼 page fault가 발생할거 같음.
        3. 프레임 축출(evict policy 축출 정책)을 사용하여 페이지 축출
    */

    // 물리 메모리의 공간 할당 및 주소 얻어오기
    void *kva = palloc_get_page(PAL_USER);
    if (kva == NULL) {
        PANIC("todo");
    }

    // frame 구조체를 위한 공간 할당 -> 커널 페이지
    struct frame *frame = malloc(sizeof(struct frame));
    if (frame == NULL) {
        PANIC("todo");
    }

    frame->kva = kva;
    frame->page = NULL;
    frame->reference_bit = 1;

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);

    // 4. 프레임 테이블에 등록
    list_push_back(&ft.frames, &frame->elem);

    // 5. 프레임 반환
    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {
    vm_alloc_page(VM_ANON, addr, true);
    vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED,
                         bool write UNUSED, bool not_present UNUSED) {
    // addr: 오류를 일으킨 주소
    // user: 사용자가 접근, 커널이 접근?
    // write: 쓰기 접근이었는지, 읽기 접근이었는지.
    // not_present: 페이지가 존재하지 않는지, 읽기 전용 페이지에 쓰기 시도한건지.
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    // 유효한 페이지 폴트
    // 1. 사용자가, kernel 영역에 접근
    if (user && is_kernel_vaddr(addr)) {
        return false;
    }

    // 2. 사용자 영역 내에서 invalid 한 영역에 접근
    if (USER_STACK < (uint64_t) addr && (uint64_t) addr < KERN_BASE) {
        return false;
    }
    if (0 <= (uint64_t) addr && (uint64_t) addr < INVALID_USER_ADDR) {
        return false;
    }

    // 3. 접근 권한 잘못됨
    if (!not_present) { // write flag 정확한 의미와, 포함 여부
        /* TODO(선하): 쓰기 방지 페이지(extra) */
        return false;
    }

    // 유효하지 않은 페이지 폴트 -> 해결 가능한(할수도있는) 페이지 폴트

    // stack growth
    if (addr >= thread_current()->rsp-8 && addr > (void *)USER_STACK_LIMIT) {
        vm_stack_growth(pg_round_down(addr));
    }

    // 일단 spt에 있는지 확인
    page = spt_find_page(spt, pg_round_down(addr)); // 해당 addr가 속해있는 page의 va를 통해 spt를 탐색해야함.

    // 없는 경우 -> palloc 같은게 선행되지 않음.
    if (page == NULL) {
        return false;
    }

    // 새 프레임을 받아와서 매핑 해주고, swap_in을 해줌 (uninit: 새로운 타입의 페이지로 다시 세팅, other: swap in)
    return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
/* 주어진 가상 주소 va에 해당하는 페이지를 생성하고, 그 페이지에 물리 프레임을 할당하는 함수 */
bool vm_claim_page(void *va UNUSED) {
    /* TODO: Fill this function */
    /*
        va에 페이지 할당
        해당 페이지에 프레임 할당
        한 페이지를 얻어야 하고,
        그 이후에 해당 페이지를 인자로 갖는 vm_do_claim_page 호출
    */
    // 1. va를 기준으로 해당 가상 페이지가 존재하는지 확인
    struct page *page = spt_find_page(&thread_current()->spt, va);

    // 2. 만약 존재하지 않으면 실패
    if (page == NULL) {
        return false;
    }

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
/*
    실제 메모리의 물리 프레임과 가상 주소를 연결하는 것
    이건 운영체제가 MMU를 통해 CPU가 주소를 해석할 수 있게 해주는 작업
*/
static bool vm_do_claim_page(struct page *page) {
    // 물리 프레임 가져오기
    struct frame *frame = vm_get_frame();
    if (frame == NULL) {
        return false;
    }
    struct thread *curr = thread_current();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: page table entry를 삽입하여 페이지의 VA를 프레임의 PA에 매핑합니다. */
    if(!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)){
        return false;
    }

    // swap_in으로 실제 데이터를 프레임에 채움
    return swap_in(page, frame->kva);
}

/*
  spt(supplemental page table)를 초기화하는 함수.
  이 함수는 spt->pages라는 해시 테이블을 초기화해서, 앞으로 이 테이블에 가상 주소에 대응하는 페이지 정보를 저장할 수 있도록 준비하는 것.
*/
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
  /*
    spt->pages라는 해시 테이블을 초기화함.
    해시 테이블을 쓰려면 "어떤 방식으로 비교하고", "어떻게 해시 값을 만들지" 알려줘야 함.
    - &spt->pages: 실제 해시 테이블
    - page_hash: 가상 주소로 해시값을 만드는 함수
    - page_less: 가상 주소를 기준으로 두 페이지를 비교하는 함수
    - NULL: 필요하면 추가 정보 전달(여기선 안 씀)

    -> 앞으로 spt_insert_page, spt_find_page 같은 함수들이 이 spt->pages에 접근해서 va 주소 기준으로 페이지 정보 저장/검색 가능해짐.
  */
  hash_init(&spt->pages, page_hash, page_less, NULL);
  lock_init(&spt->spt_lock);
}

bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src) {
    // 순회
    struct hash_iterator hash_iter;
    hash_first(&hash_iter, &src->pages);

    while (hash_next (&hash_iter)) {
        struct page *page = hash_entry(hash_cur(&hash_iter), struct page, hash_elem);
        enum vm_type type = page_get_type(page);

        // 1. 새로운 uninit page 하나 세팅하기
        if (!vm_alloc_page(page_get_type(page), page->va, page->writable)){
            return false;
        }

        struct page *new_page = spt_find_page(dst, page->va);

        // 2. frame이 설정되어있었으면,
        if (page->frame != NULL) {
            // 3. vm_claim_page해서 frame 하나 받아오고
            if (!vm_claim_page(new_page->va)) {
                return false;
            }
            // 4. frame 내부의 내용 채워넣기
            memcpy(new_page->frame->kva, page->frame->kva,PGSIZE);
        }
    }
    return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_destroy(&spt->pages, page_destructor);
}

/* 추가한 함수들 by git book 08.04 */
/* 페이지의 가상 주소 va를 기반으로 해시값을 만드는 함수 */
// 해시 테이블은 내부적으로 빠르게 찾기 위해 키(va)를 해시값으로 바꾸어서 저장함.
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
  // hash_entry()는 hash_elem 구조체 포인터를 struct page 포인터로 바꿔주는 매크로!
  const struct page *p = hash_entry(p_, struct page, hash_elem);
  return hash_bytes(&p->va, sizeof p->va); // p->va: 페이지의 가상 주소. 가상 주소의 바이트 값을 이용해 해시값을 계산함.
}

/* 두 페이지의 va 중 어느 게 더 작은지 비교해서 정렬 기준을 정하는 함수 */
// 해시 테이블 내부에 충돌이 발생하면 비교 함수가 필요함. 같은 해시값일 때 정확히 어떤 페이지인지 비교해서 구분해야 하기 때문.
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
  // a, b: 각각 해시 테이블에 저장된 페이지들
  // a->va < b->va: 가상 주소 기준으로 비교함. 주소가 더 작은 페이지가 "먼저"라고 판단하는 기준임.
  const struct page *a = hash_entry(a_, struct page, hash_elem);
  const struct page *b = hash_entry(b_, struct page, hash_elem);

  return a->va < b->va;
}

void page_destructor(struct hash_elem *e, void *aux) {
    struct page *page = hash_entry(e, struct page, hash_elem);

    if (page->frame != NULL) {
        list_remove(&page->frame->elem); // 프레임 테이블에서 제거
//        palloc_free_page(page->frame->kva); // 할당받은 물리메모리 공간 해제 -> pml4 측에서 해줌
        free(page->frame);      // frame 구조체 공간 해제
    }

    vm_dealloc_page(page);  // page 해제
}