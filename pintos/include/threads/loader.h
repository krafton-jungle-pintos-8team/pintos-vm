#ifndef THREADS_LOADER_H
#define THREADS_LOADER_H

/* Constants fixed by the PC BIOS. */ // PC BIOS에 의해 고정된 상수들.
#define LOADER_BASE 0x7c00 /* Physical address of loader's base. */ // 로더의 시작 물리 주소.
#define LOADER_END 0x7e00  /* Physical address of end of loader. */ // 로더의 끝 물리 주소.

/* Physical address of kernel base. */
#define LOADER_KERN_BASE 0x8004000000   // 커널의 시작 물리 주소.

/* Kernel virtual address at which all physical memory is mapped. */
#define LOADER_PHYS_BASE 0x200000       // 모든 물리 메모리가 매핑되는 커널 가상 주소.

/* Multiboot infos */ // 멀티부트 정보
#define MULTIBOOT_INFO 0x7000
#define MULTIBOOT_FLAG MULTIBOOT_INFO
#define MULTIBOOT_MMAP_LEN MULTIBOOT_INFO + 44
#define MULTIBOOT_MMAP_ADDR MULTIBOOT_INFO + 48

#define E820_MAP MULTIBOOT_INFO + 52
#define E820_MAP4 MULTIBOOT_INFO + 56

/* Important loader physical addresses. */  // 중요한 로더 물리 주소들.
#define LOADER_SIG (LOADER_END - LOADER_SIG_LEN)          /* 0xaa55 BIOS signature. */
#define LOADER_ARGS (LOADER_SIG - LOADER_ARGS_LEN)        /* Command-line args. */
#define LOADER_ARG_CNT (LOADER_ARGS - LOADER_ARG_CNT_LEN) /* Number of args. */

/* Sizes of loader data structures. */  // 로더 데이터 구조체들의 크기.
#define LOADER_SIG_LEN 2
#define LOADER_ARGS_LEN 128
#define LOADER_ARG_CNT_LEN 4

/* GDT selectors defined by loader.
   More selectors are defined by userprog/gdt.h. */
#define SEL_NULL 0x00  /* Null selector. */
#define SEL_KCSEG 0x08 /* Kernel code selector. */
#define SEL_KDSEG 0x10 /* Kernel data selector. */
#define SEL_UDSEG 0x1B /* User data selector. */
#define SEL_UCSEG 0x23 /* User code selector. */
#define SEL_TSS 0x28   /* Task-state segment. */
#define SEL_CNT 8      /* Number of segments. */

#endif /* threads/loader.h */
