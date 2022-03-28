#include "image.h"

typedef unsigned long u64;
typedef unsigned int u32;

/* Physical memory address space: 0-1G */
#define PHYSMEM_START   (0x0UL)
#define PERIPHERAL_BASE (0x3F000000UL)
#define PHYSMEM_END     (0x40000000UL)

/* The number of entries in one page table page */
#define PTP_ENTRIES 512
/* The size of one page table page */
#define PTP_SIZE 4096
#define ALIGN(n) __attribute__((__aligned__(n)))
u64 boot_ttbr0_l0[PTP_ENTRIES] ALIGN(PTP_SIZE);
u64 boot_ttbr0_l1[PTP_ENTRIES] ALIGN(PTP_SIZE);
u64 boot_ttbr0_l2[PTP_ENTRIES] ALIGN(PTP_SIZE);

u64 boot_ttbr1_l0[PTP_ENTRIES] ALIGN(PTP_SIZE);
u64 boot_ttbr1_l1[PTP_ENTRIES] ALIGN(PTP_SIZE);
u64 boot_ttbr1_l2[PTP_ENTRIES] ALIGN(PTP_SIZE);

#define IS_VALID (1UL << 0)
#define IS_TABLE (1UL << 1)

#define UXN            (0x1UL << 54)
#define ACCESSED       (0x1UL << 10)
#define NG             (0x1UL << 11)
#define INNER_SHARABLE (0x3UL << 8)
#define NORMAL_MEMORY  (0x0UL << 2)
#define DEVICE_MEMORY  (0x1UL << 2)

#define SIZE_2M (2UL * 1024 * 1024)

#define GET_L0_INDEX(x) (((x) >> (12 + 9 + 9 + 9)) & 0x1ff)
#define GET_L1_INDEX(x) (((x) >> (12 + 9 + 9)) & 0x1ff)
#define GET_L2_INDEX(x) (((x) >> (12 + 9)) & 0x1ff)

void init_boot_pt(void)
{
        u64 vaddr = PHYSMEM_START;
	/*
        /* TTBR0_EL1 0-1G */
    	// TTBR0 就是用户态的页表
    	// l0就是最大的那个页表entry，我们让它对应index指向l1
        boot_ttbr0_l0[GET_L0_INDEX(vaddr)] = ((u64)boot_ttbr0_l1) | IS_TABLE
                                             | IS_VALID | NG;
    	// l0就是第二大的那个页表entry(每个entry对应1G)，我们让它对应index指向l2
        boot_ttbr0_l1[GET_L1_INDEX(vaddr)] = ((u64)boot_ttbr0_l2) | IS_TABLE
                                             | IS_VALID | NG;

        /* Normal memory: PHYSMEM_START ~ PERIPHERAL_BASE */
        /* Map with 2M granularity */
    	// 对于用户态地址来说，此时虚拟页和物理页的地址一一对应
        
        for (; vaddr < PERIPHERAL_BASE; vaddr += SIZE_2M) {
                boot_ttbr0_l2[GET_L2_INDEX(vaddr)] =
                        (vaddr) // low mem, va = pa
                        | UXN // Unprivileged execute never
                        | ACCESSED // Set access flag
                        | NG // Mark as not global
                        | INNER_SHARABLE // Sharebility
                        | NORMAL_MEMORY // Normal memory
                        | IS_VALID;
        }
	

        /* Peripheral memory: PERIPHERAL_BASE ~ PHYSMEM_END */
        /* Map with 2M granularity */
        // 对于用户态地址来说，此时虚拟页和物理页的地址一一对应
        
        for (vaddr = PERIPHERAL_BASE; vaddr < PHYSMEM_END; vaddr += SIZE_2M) {
                boot_ttbr0_l2[GET_L2_INDEX(vaddr)] =
                        (vaddr) // low mem, va = pa
                        | UXN // Unprivileged execute never
                        | ACCESSED // Set access flag
                        | NG // Mark as not global
                        | DEVICE_MEMORY // Device memory
                        | IS_VALID;
        }
	
        /* TTBR1_EL1 0-1G */
        /* LAB 2 TODO 1 BEGIN */
        /* Step 1: set L0 and L1 page table entry */
    	vaddr = PHYSMEM_START + KERNEL_VADDR;
        boot_ttbr1_l0[GET_L0_INDEX(vaddr)] = ((u64) boot_ttbr1_l1)
            | IS_TABLE | IS_VALID;
        boot_ttbr1_l1[GET_L1_INDEX(vaddr)] = ((u64) boot_ttbr1_l2)
            | IS_TABLE | IS_VALID;

        /* Step 2: map PHYSMEM_START ~ PERIPHERAL_BASE with 2MB granularity */
        /*
         * Map each 2M page
         * Usuable memory: PHYSMEM_START ~ PERIPHERAL_BASE
         */
    	for (; vaddr < (PERIPHERAL_BASE + KERNEL_VADDR); vaddr += SIZE_2M) {
                boot_ttbr1_l2[GET_L2_INDEX(vaddr)] =
                        (vaddr - KERNEL_VADDR) /* high mem, va = pa + kernel_vaddr */
                        | UXN /* Unprivileged execute never */
                        | ACCESSED /* Set access flag */
                        | INNER_SHARABLE /* Sharebility */
                        | NORMAL_MEMORY /* Normal memory */
                        | IS_VALID;
        }

        /* Step 3: map PERIPHERAL_BASE ~ PHYSMEM_END with 2MB granularity */
        /* Peripheral memory: PERIPHERAL_BASE ~ PHYSMEM_END */
    	for (vaddr = (PERIPHERAL_BASE + KERNEL_VADDR); vaddr < (PHYSMEM_END + KERNEL_VADDR); vaddr += SIZE_2M) {
                boot_ttbr1_l2[GET_L2_INDEX(vaddr)] =
                        (vaddr - KERNEL_VADDR) /* low mem, va = pa */
                        | UXN /* Unprivileged execute never */
                        | ACCESSED /* Set access flag */
                        | DEVICE_MEMORY /* Device memory */
                        | IS_VALID;
        }

        /* LAB 2 TODO 1 END */

        /*
         * Local peripherals, e.g., ARM timer, IRQs, and mailboxes
         *
         * 0x4000_0000 .. 0xFFFF_FFFF
         * 1G is enough (for Mini-UART). Map 1G page here.
         */
        vaddr = KERNEL_VADDR + PHYSMEM_END;
        boot_ttbr1_l1[GET_L1_INDEX(vaddr)] = PHYSMEM_END | UXN /* Unprivileged
                                                                  execute never
                                                                */
                                             | ACCESSED /* Set access flag */
                                             | NG /* Mark as not global */
                                             | DEVICE_MEMORY /* Device memory */
                                             | IS_VALID;
}
