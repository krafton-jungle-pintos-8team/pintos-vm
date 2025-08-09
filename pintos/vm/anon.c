/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "devices/disk.h"
#include "vm/vm.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
    /* TODO: Set up the swap_disk. */
    /* swap_disk가 되어 있는데 disk 내부에 무언갈 해주어야 하는가? */
    swap_disk = anon_ops.swap_out;
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &anon_ops;
    struct anon_page *anon_page = &page->anon;
    /* anon init 추가 08.08 */
    anon_page->type = type;
    anon_page->kva = kva;
    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
    struct anon_page *anon_page = &page->anon;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
    /* 
        이 값들을 destory 하기 위한 방법...음 
        1. 밑에 처럼 모든 값들을 NULL 처리 해준다.
        2. free 해준다 아마 주소값을 넘기기 때문에 free 해주는게 좋을거 같은데...
    */
    struct anon_page *anon_page = &page->anon;
    // anon_page->kva = NULL;
    free(anon_page->kva);
    free(anon_page);
    /* 왜 free 하니까 error 발생하지? 08.09 */
    // free(anon_page);
    /* 구현을 해줘야 하는거 같음 */
    /* 1차원적인 방법 모든 자원을 NULL로 바꿔준다. */
    
    // anon_page->type = 0;
    // anon_page = NULL;
    /* anon_page 이 page 포인터 자체도 free 해줘야 하는거 아닌가? */
    
}
