/*
 * Copyright 2014, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(NICTA_BSD)
 */

//#include "mapping.h"
#include "vmem_layout.h"

#include <vka/object.h>

#include <sel4utils/mapping.h>

#define verbose 0
#include "panic.h"
#include "debug.h"

int 
map_page(vka_t *vka, seL4_CPtr frame_cap, seL4_ARM_PageDirectory pd, seL4_Word vaddr, 
                seL4_CapRights rights, seL4_ARM_VMAttributes attr){
    int err;

    /* Attempt the mapping */
    err = seL4_ARM_Page_Map(frame_cap, pd, vaddr, rights, attr);
    if(err == seL4_FailedLookup){
        /* Assume the error was because we have no page table */

        /* create and map a page table */
        vka_object_t pt_object = {0};
        err =  vka_alloc_page_table(vka, &pt_object);

        err = seL4_ARCH_PageTable_Map(pt_object.cptr, pd, vaddr, seL4_ARCH_Default_VMAttributes);
        if(!err){
            /* Try the mapping again */
            err = seL4_ARM_Page_Map(frame_cap, pd, vaddr, rights, attr);
        }
    }

    return err;
}

void* 
map_device(vka_t *vka, void* paddr, int size){
    static seL4_Word virt = DEVICE_START;
    seL4_Word phys = (seL4_Word)paddr;
    seL4_Word vstart = virt;

    printf("Mapping device memory 0x%x -> 0x%x (0x%x bytes)\n",
                phys, vstart, size);
    while(virt - vstart < size){
        seL4_Error err;
        /* Retype the untype to a frame */
        vka_object_t frame_obj = {0};
        err = vka_alloc_frame(vka, seL4_PageBits, &frame_obj);

        /*err = cspace_ut_retype_addr(phys,
                                    seL4_ARM_SmallPageObject,
                                    seL4_PageBits,
                                    cur_cspace,
                                    &frame_cap);*/
        conditional_panic(err, "Unable to retype device memory");
        /* Map in the page */
        err = map_page(vka,
		       frame_obj.cptr, 
                       seL4_CapInitThreadPD, 
                       virt, 
                       seL4_AllRights,
                       0);
        conditional_panic(err, "Unable to map device");
        /* Next address */
        phys += (1 << seL4_PageBits);
        virt += (1 << seL4_PageBits);
    }
    printf("Map succeeded\n");
    return (void*)vstart;
}


