/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

/* uninit.c: 초기화되지 않은 페이지 구현
 *
 * 모든 페이지는 초기화되지 않은 페이지로 생성됩니다. 첫 페이지 폴트가 발생하면,
 * 핸들러 체인은 uninit_initialize (page->operations.swap_in)를 호출합니다.
 * uninit_initialize 함수는 페이지 객체를 초기화하여 페이지를 특정 페이지 객체
 * (익명, 파일, 페이지 캐시)로 변형(transmute)시키고, vm_alloc_page_with_initializer
 * 함수로부터 전달받은 초기화 콜백을 호출합니다.
*/

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
                              .init = init,                 // lazy_load_segment
                              .type = type,                 // type
                              .aux = aux,                   // 파일 정보 구조체
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

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void uninit_destroy(struct page *page) {
    struct uninit_page *uninit UNUSED = &page->uninit;
    /* TODO: Fill this function.
     * TODO: If you don't have anything to do, just return. */
}
