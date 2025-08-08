#ifndef VM_UNINIT_H
#define VM_UNINIT_H
#include <stdbool.h>
#include "vm/vm_type.h"

struct page;
enum vm_type;

typedef bool vm_initializer(struct page *, void *aux);

/* Uninitlialized page. The type for implementing the
 * "Lazy loading". */
struct uninit_page {
    /* Initiate the contets of the page */
    vm_initializer *init;
    enum vm_type type;
    void *aux;
    /* 물리 주소를 가상 주소에 매핑 초기화 */
    bool (*page_initializer)(struct page *, enum vm_type, void *kva);
};

void uninit_new(struct page *page, void *va, vm_initializer *init, enum vm_type type, void *aux,
                bool (*initializer)(struct page *, enum vm_type, void *kva));
#endif
