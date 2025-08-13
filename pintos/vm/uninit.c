/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/uninit.h"

#include "vm/vm.h"

static bool uninit_initialize(struct page *page, void *kva);
static void uninit_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
    .swap_in = uninit_initialize,
    .swap_out = NULL,
    .destroy = uninit_destroy,
    .type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
/* lazy loading을 위해 미리 페이지의 정보를 설정해두는 것 */
void uninit_new(struct page *page, void *va, vm_initializer *init, enum vm_type type, void *aux,
                bool (*initializer)(struct page *, enum vm_type, void *)) {
    ASSERT(page != NULL);

    *page = (struct page){.operations = &uninit_ops,
                          .va = va,                         // upage
                          .frame = NULL,                    /* no frame for now */
                          .uninit = (struct uninit_page){
                              .init = init,                 
                              .type = type,                 
                              .aux = aux,                   
                              .page_initializer = initializer,
                          }};
}

/* 첫 번째 오류 발생 시 페이지를 초기화합니다. */
static bool uninit_initialize(struct page *page, void *kva) {
    struct uninit_page *uninit = &page->uninit;

    /* 먼저 값을 가져오세요. page_initialize가 그 값들을 덮어쓸 수 있습니다. */
    vm_initializer *init = uninit->init;
    void *aux = uninit->aux;

    /* TODO: You may need to fix this function. */
    return uninit->page_initializer(page, uninit->type, kva) && (init ? init(page, aux) : true);
}

/* 
    uninit_page가 가지고 있는 자원을 해제하세요.
    대부분의 페이지는 다른 페이지 객체로 변환되지만,
    프로세스가 종료될 때까지 한 번도 참조되지 않은 uninit 페이지가 남아 있을 수도 있습니다.
    페이지 자체(PAGE)는 호출자가 해제합니다.
 */
static void uninit_destroy(struct page *page) {
    struct uninit_page *uninit UNUSED = &page->uninit;
    /* TODO: Fill this function.
     * TODO: If you don't have anything to do, just return. */

    /* 
        uninit->init = lazy_load_segment 가 들어오고,
        uninit->aux = load_segment에서 malloc으로 할당해준 커널 영역 가상 주소
    */
    
    /* aux는 process.c load_segment에서 malloc으로 할당해준 메모리 주소인거 같음 */
    if (uninit->aux != NULL) {
        free(uninit->aux);
    }
}
