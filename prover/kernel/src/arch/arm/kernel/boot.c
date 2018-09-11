/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(GD_GPL)
 */

#include <assert.h>
#include <kernel/boot.h>
#include <machine/io.h>
#include <model/statedata.h>
#include <object/interrupt.h>
#include <arch/machine.h>
#include <arch/kernel/boot.h>
#include <arch/kernel/vspace.h>
#include <arch/benchmark.h>
#include <arch/user_access.h>
#include <arch/linker.h>
#include <plat/machine/hardware.h>
#include <machine.h>


/* pointer to the end of boot code/data in kernel image */
/* need a fake array to get the pointer from the linker script */
extern char ki_boot_end[1];
/* pointer to end of kernel image */
extern char ki_end[1];

/**
 * Split mem_reg about reserved_reg. If memory exists in the lower
 * segment, insert it. If memory exists in the upper segment, return it.
 */
BOOT_CODE static region_t
insert_region_excluded(region_t mem_reg, region_t reserved_reg)
{
    region_t residual_reg = mem_reg;
    bool_t result UNUSED;

    if (reserved_reg.start < mem_reg.start) {
        /* Reserved region is below the provided mem_reg. */
        mem_reg.end = 0;
        mem_reg.start = 0;
        /* Fit the residual around the reserved region */
        if (reserved_reg.end > residual_reg.start) {
            residual_reg.start = reserved_reg.end;
        }
    } else if (mem_reg.end > reserved_reg.start) {
        /* Split mem_reg around reserved_reg */
        mem_reg.end = reserved_reg.start;
        residual_reg.start = reserved_reg.end;
    } else {
        /* reserved_reg is completely above mem_reg */
        residual_reg.start = 0;
        residual_reg.end = 0;
    }
    /* Add the lower region if it exists */
    if (mem_reg.start < mem_reg.end) {
        result = insert_region(mem_reg);
        assert(result);
    }
    /* Validate the upper region */
    if (residual_reg.start > residual_reg.end) {
        residual_reg.start = residual_reg.end;
    }

    return residual_reg;
}

BOOT_CODE static void
init_freemem(region_t ui_reg)
{
    unsigned int i;
    bool_t result UNUSED;
    region_t cur_reg;
    region_t res_reg[] = {
        {
            .start = kernelBase,
            .end   = (pptr_t)ki_end
        },
        {
            .start = ui_reg.start,
            .end = ui_reg.end
        },
        {
            .start = (PD_ASID_SLOT + 0) << pageBitsForSize(ARMSection),
            .end   = (PD_ASID_SLOT + 1) << pageBitsForSize(ARMSection)
        }
    };

    for (i = 0; i < MAX_NUM_FREEMEM_REG; i++) {
        ndks_boot.freemem[i] = REG_EMPTY;
    }

    /* Force ordering and exclusivity of reserved regions. */
    assert(res_reg[0].start < res_reg[0].end);
    assert(res_reg[1].start < res_reg[1].end);
    assert(res_reg[2].start < res_reg[2].end);
    assert(res_reg[0].end  <= res_reg[1].start);
    assert(res_reg[1].end  <= res_reg[2].start);
    for (i = 0; i < get_num_avail_p_regs(); i++) {
        cur_reg = paddr_to_pptr_reg(get_avail_p_reg(i));
        /* Adjust region if it exceeds the kernel window
         * Note that we compare physical address in case of overflow.
         */
        if (pptr_to_paddr((void*)cur_reg.end) > PADDR_TOP) {
            cur_reg.end = PPTR_TOP;
        }
        if (pptr_to_paddr((void*)cur_reg.start) > PADDR_TOP) {
            cur_reg.start = PPTR_TOP;
        }

        cur_reg = insert_region_excluded(cur_reg, res_reg[0]);
        cur_reg = insert_region_excluded(cur_reg, res_reg[1]);
        cur_reg = insert_region_excluded(cur_reg, res_reg[2]);
        if (cur_reg.start != cur_reg.end) {
            result = insert_region(cur_reg);
            assert(result);
        }
    }
}

BOOT_CODE static void
init_irqs(cap_t root_cnode_cap)
{
    irq_t i;

    for (i = 0; i <= maxIRQ; i++) {
        setIRQState(IRQInactive, i);
    }
    setIRQState(IRQTimer, KERNEL_TIMER_IRQ);

    /* provide the IRQ control cap */
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), BI_CAP_IRQ_CTRL), cap_irq_control_cap_new());
}

/* Create a frame cap for the initial thread. */

static BOOT_CODE cap_t
create_it_frame_cap(pptr_t pptr, vptr_t vptr, asid_t asid, bool_t use_large)
{
    if (use_large)
        return
            cap_frame_cap_new(
                ARMSection,                    /* capFSize           */
                ASID_LOW(asid),                /* capFMappedASIDLow  */
                wordFromVMRights(VMReadWrite), /* capFVMRights       */
                vptr,                          /* capFMappedAddress  */
                ASID_HIGH(asid),               /* capFMappedASIDHigh */
                pptr                           /* capFBasePtr        */
            );
    else
        return
            cap_small_frame_cap_new(
                ASID_LOW(asid),                /* capFMappedASIDLow  */
                wordFromVMRights(VMReadWrite), /* capFVMRights       */
                vptr,                          /* capFMappedAddress  */
                ASID_HIGH(asid),               /* capFMappedASIDHigh */
                pptr                           /* capFBasePtr        */
            );
}

BOOT_CODE cap_t
create_unmapped_it_frame_cap(pptr_t pptr, bool_t use_large)
{
    return create_it_frame_cap(pptr, 0, asidInvalid, use_large);
}

BOOT_CODE cap_t
create_mapped_it_frame_cap(cap_t pd_cap, pptr_t pptr, vptr_t vptr, asid_t asid, bool_t use_large, bool_t executable)
{
    cap_t cap = create_it_frame_cap(pptr, vptr, asid, use_large);
    map_it_frame_cap(pd_cap, cap, executable);
    return cap;
}

/* Create a page table for the initial thread */

static BOOT_CODE cap_t
create_it_page_table_cap(cap_t pd, pptr_t pptr, vptr_t vptr, asid_t asid)
{
    cap_t cap;
    cap = cap_page_table_cap_new(
              1,    /* capPTIsMapped      */
              asid, /* capPTMappedASID    */
              vptr, /* capPTMappedAddress */
              pptr  /* capPTBasePtr       */
          );
    if (asid != asidInvalid) {
        map_it_pt_cap(pd, cap);
    }
    return cap;
}

/* Create an address space for the initial thread.
 * This includes page directory and page tables */
BOOT_CODE static cap_t
create_it_address_space(cap_t root_cnode_cap, v_region_t it_v_reg)
{
    cap_t      pd_cap;
    vptr_t     pt_vptr;
    pptr_t     pt_pptr;
    slot_pos_t slot_pos_before;
    slot_pos_t slot_pos_after;
    pptr_t pd_pptr;

    /* create PD obj and cap */
    pd_pptr = alloc_region(PD_SIZE_BITS);
    if (!pd_pptr) {
        return cap_null_cap_new();
    }
    memzero(PDE_PTR(pd_pptr), 1 << PD_SIZE_BITS);
    copyGlobalMappings(PDE_PTR(pd_pptr));
    cleanCacheRange_PoU(pd_pptr, pd_pptr + (1 << PD_SIZE_BITS) - 1,
                        addrFromPPtr((void *)pd_pptr));
    pd_cap =
        cap_page_directory_cap_new(
            true,    /* capPDIsMapped   */
            IT_ASID, /* capPDMappedASID */
            pd_pptr  /* capPDBasePtr    */
        );
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), BI_CAP_IT_VSPACE), pd_cap);

    /* create all PT objs and caps necessary to cover userland image */
    slot_pos_before = ndks_boot.slot_pos_cur;

    for (pt_vptr = ROUND_DOWN(it_v_reg.start, PT_BITS + PAGE_BITS);
            pt_vptr < it_v_reg.end;
            pt_vptr += BIT(PT_BITS + PAGE_BITS)) {
        pt_pptr = alloc_region(PT_SIZE_BITS);
        if (!pt_pptr) {
            return cap_null_cap_new();
        }
        memzero(PTE_PTR(pt_pptr), 1 << PT_SIZE_BITS);
        if (!provide_cap(root_cnode_cap,
                         create_it_page_table_cap(pd_cap, pt_pptr, pt_vptr, IT_ASID))
           ) {
            return cap_null_cap_new();
        }
    }

    slot_pos_after = ndks_boot.slot_pos_cur;
    ndks_boot.bi_frame->ui_pt_caps = (slot_region_t) {
        slot_pos_before, slot_pos_after
    };

    return pd_cap;
}

BOOT_CODE static bool_t
create_device_frames(cap_t root_cnode_cap)
{
    slot_pos_t     slot_pos_before;
    slot_pos_t     slot_pos_after;
    vm_page_size_t frame_size;
    region_t       dev_reg;
    bi_dev_reg_t   bi_dev_reg;
    cap_t          frame_cap;
    uint32_t       i;
    pptr_t         f;

    ndks_boot.bi_frame->num_dev_regs = get_num_dev_p_regs();
    if (ndks_boot.bi_frame->num_dev_regs > CONFIG_MAX_NUM_BOOTINFO_DEVICE_REGIONS) {
        printf("Kernel init: Too many device regions for boot info\n");
        ndks_boot.bi_frame->num_dev_regs = CONFIG_MAX_NUM_BOOTINFO_DEVICE_REGIONS;
    }

    for (i = 0; i < ndks_boot.bi_frame->num_dev_regs; i++) {
        /* write the frame caps of this device region into the root CNode and update the bootinfo */
        dev_reg = paddr_to_pptr_reg(get_dev_p_reg(i));
        /* use 1M frames if possible, otherwise use 4K frames */
        if (IS_ALIGNED(dev_reg.start, pageBitsForSize(ARMSection)) &&
                IS_ALIGNED(dev_reg.end,   pageBitsForSize(ARMSection))) {
            frame_size = ARMSection;
        } else {
            frame_size = ARMSmallPage;
        }

        slot_pos_before = ndks_boot.slot_pos_cur;

        /* create/provide frame caps covering the region */
        for (f = dev_reg.start; f < dev_reg.end; f += BIT(pageBitsForSize(frame_size))) {
            frame_cap = create_it_frame_cap(f, 0, asidInvalid, frame_size == ARMSection);
            if (!provide_cap(root_cnode_cap, frame_cap)) {
                return false;
            }
        }

        slot_pos_after = ndks_boot.slot_pos_cur;

        /* add device-region entry to bootinfo */
        bi_dev_reg.base_paddr = pptr_to_paddr((void*)dev_reg.start);
        bi_dev_reg.frame_size_bits = pageBitsForSize(frame_size);
        bi_dev_reg.frame_caps = (slot_region_t) {
            slot_pos_before, slot_pos_after
        };
        ndks_boot.bi_frame->dev_reg_list[i] = bi_dev_reg;
    }

    return true;
}

/* This and only this function initialises the CPU. It does NOT initialise any kernel state. */

BOOT_CODE static void
init_cpu(void)
{
    activate_global_pd();
}

/* This and only this function initialises the platform. It does NOT initialise any kernel state. */

BOOT_CODE static void
init_plat(void)
{
    initIRQController();
    initTimer();
    initL2Cache();
}

/*------------------------------------------------------------------------------------------------*/
typedef struct {
    uint8_t             hash[32];       // Changed by RKW, unsigned char becomes uint8_t
    uint32_t    buffer[16];     // Changed by RKW, unsigned long becomes uint32_t
    uint32_t    state[8];       // Changed by RKW, unsinged long becomes uint32_t
    uint8_t             length[8];      // Changed by RKW, unsigned char becomes uint8_t
} sha256;

void sha256_initialize(sha256 *sha);

void sha256_update(sha256 *sha, const uint8_t *message, uint32_t length);

void sha256_finalize(sha256 *sha, const uint8_t *message, uint32_t length);

void sha256_get(uint8_t hash[32], const uint8_t *message, int length);

 
 

void sha256_initialize(sha256 *sha) {
    int i;
    for (i = 0; i < 16; ++i) sha->buffer[i] = 0;
    sha->state[0] = 0x6a09e667;
    sha->state[1] = 0xbb67ae85;
    sha->state[2] = 0x3c6ef372;
    sha->state[3] = 0xa54ff53a;
    sha->state[4] = 0x510e527f;
    sha->state[5] = 0x9b05688c;
    sha->state[6] = 0x1f83d9ab;
    sha->state[7] = 0x5be0cd19;
    for (i = 0; i < 8; ++i) sha->length[i] = 0;
}

//  Changed by RKW, formal args are now const uint8_t, uint_32
//    from const unsigned char, unsigned long respectively
void sha256_update(sha256 *sha,
                   const uint8_t *message,
                   uint32_t length) {
    int i, j;
    /* Add the length of the received message, counted in
     * bytes, to the total length of the messages hashed to
     * date, counted in bits and stored in 8 separate bytes. */
    for (i = 7; i >= 0; --i) {
        int bits;
                if (i == 7)
                        bits = length << 3;
                else if (i == 0 || i == 1 || i == 2)
                        bits = 0;
                else
                        bits = length >> (53 - 8 * i);
                bits &= 0xff;
        if (sha->length[i] + bits > 0xff) {
            for (j = i - 1; j >= 0 && sha->length[j]++ == 0xff; --j);
        }
        sha->length[i] += bits;
    }
    /* Add the received message to the SHA buffer, updating the
     * hash at each block (each time the buffer is filled). */
    while (length > 0) {
        /* Find the index in the SHA buffer at which to
         * append what's left of the received message. */
        int index = sha->length[6] % 2 * 32 + sha->length[7] / 8;
        index = (index + 64 - length % 64) % 64;
        /* Append the received message bytes to the SHA buffer until
         * we run out of message bytes or until the buffer is filled. */
        for (;length > 0 && index < 64; ++message, ++index, --length) {
            sha->buffer[index / 4] |= *message << (24 - index % 4 * 8);
        }
        /* Update the hash with the buffer contents if the buffer is full. */
        if (index == 64) {
            /* Update the hash with a block of message content. See FIPS 180-2
             * (<csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf>)
             * for a description of and details on the algorithm used here. */
                        // Changed by RKW, const unsigned long becomes const uint32_t
            const uint32_t k[64] = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };
                        // Changed by RKW, unsigned long becomes uint32_t
            uint32_t w[64], a, b, c, d, e, f, g, h;
            int t;
            for (t = 0; t < 16; ++t) {
                w[t] = sha->buffer[t];
                sha->buffer[t] = 0;
            }
            for (t = 16; t < 64; ++t) {
                                // Changed by RKW, unsigned long becomes uint32_t
                uint32_t s0, s1;
                s0 = (w[t - 15] >> 7 | w[t - 15] << 25);
                s0 ^= (w[t - 15] >> 18 | w[t - 15] << 14);
                s0 ^= (w[t - 15] >> 3);
                s1 = (w[t - 2] >> 17 | w[t - 2] << 15);
s1 ^= (w[t - 2] >> 19 | w[t - 2] << 13);
                s1 ^= (w[t - 2] >> 10);
                w[t] = (s1 + w[t - 7] + s0 + w[t - 16]) & 0xffffffffU;
            }
            a = sha->state[0];
            b = sha->state[1];
            c = sha->state[2];
            d = sha->state[3];
            e = sha->state[4];
            f = sha->state[5];
            g = sha->state[6];
            h = sha->state[7];
            for (t = 0; t < 64; ++t) {
                                // Changed by RKW, unsigned long becomes uint32_t
                uint32_t e0, e1, t1, t2;
                e0 = (a >> 2 | a << 30);
                e0 ^= (a >> 13 | a << 19);
                e0 ^= (a >> 22 | a << 10);
                e1 = (e >> 6 | e << 26);
                e1 ^= (e >> 11 | e << 21);
                e1 ^= (e >> 25 | e << 7);
                t1 = h + e1 + ((e & f) ^ (~e & g)) + k[t] + w[t];
                t2 = e0 + ((a & b) ^ (a & c) ^ (b & c));
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }
            sha->state[0] = (sha->state[0] + a) & 0xffffffffU;
            sha->state[1] = (sha->state[1] + b) & 0xffffffffU;
            sha->state[2] = (sha->state[2] + c) & 0xffffffffU;
            sha->state[3] = (sha->state[3] + d) & 0xffffffffU;
            sha->state[4] = (sha->state[4] + e) & 0xffffffffU;
            sha->state[5] = (sha->state[5] + f) & 0xffffffffU;
            sha->state[6] = (sha->state[6] + g) & 0xffffffffU;
            sha->state[7] = (sha->state[7] + h) & 0xffffffffU;
        }
    }
}
//    from const unsigned char, unsigned long respectively
void sha256_finalize(sha256 *sha,
                     const uint8_t *message,
                     uint32_t length) {
    int i;
        // Changed by RKW, unsigned char becomes uint8_t
    uint8_t terminator[64 + 8] = { 0x80 };
    /* Hash the final message bytes if necessary. */
    if (length > 0) sha256_update(sha, message, length);
    /* Create a terminator that includes a stop bit, padding, and
     * the the total message length. See FIPS 180-2 for details. */
    length = 64 - sha->length[6] % 2 * 32 - sha->length[7] / 8;
    if (length < 9) length += 64;
    for (i = 0; i < 8; ++i) terminator[length - 8 + i] = sha->length[i];
    /* Hash the terminator to finalize the message digest. */
    sha256_update(sha, terminator, length);
    /* Extract the message digest. */
    for (i = 0; i < 32; ++i) {
        sha->hash[i] = (sha->state[i / 4] >> (24 - 8 * (i % 4))) & 0xff;
    }
}

//  Changed by RKW, formal args are now uint8_t, const uint_8
//    from unsigned char, const unsigned char respectively
UNUSED void sha256_get(uint8_t hash[32],
                const uint8_t *message,
                int length) {
    int i;
    sha256 sha;
    sha256_initialize(&sha);
    sha256_finalize(&sha, message, length);
    for (i = 0; i < 32; ++i) hash[i] = sha.hash[i];
}

/* Main kernel initialisation function. */


static BOOT_CODE bool_t
try_init_kernel(
    paddr_t ui_p_reg_start,
    paddr_t ui_p_reg_end,
    int32_t pv_offset,
    vptr_t  v_entry
)
{
    cap_t root_cnode_cap;
    cap_t it_ap_cap;
    cap_t it_pd_cap;
    cap_t ipcbuf_cap;

    int i;
    uint8_t digest[32] = {0};

    region_t ui_reg = paddr_to_pptr_reg((p_region_t) {
        ui_p_reg_start, ui_p_reg_end
    });
    pptr_t bi_frame_pptr;
    vptr_t bi_frame_vptr;
    vptr_t ipcbuf_vptr;
    create_frames_of_region_ret_t create_frames_ret;

    /* convert from physical addresses to userland vptrs */
    v_region_t ui_v_reg;
    v_region_t it_v_reg;
    ui_v_reg.start = ui_p_reg_start - pv_offset;
    ui_v_reg.end   = ui_p_reg_end   - pv_offset;

    /* software secure boot for initial thread */
    //sha256_get(digest, (uint8_t*) ui_p_reg_start, ui_p_reg_end - ui_p_reg_start);

    ipcbuf_vptr = ui_v_reg.end;
    bi_frame_vptr = ipcbuf_vptr + BIT(PAGE_BITS);

    /* The region of the initial thread is the user image + ipcbuf and boot info */
    it_v_reg.start = ui_v_reg.start;
    it_v_reg.end = bi_frame_vptr + BIT(PAGE_BITS);

    /* setup virtual memory for the kernel */
    map_kernel_window();

    /* initialise the CPU */
    init_cpu();

    /* debug output via serial port is only available from here */
    printf("Bootstrapping kernel\n");


    printf("ui_p_reg_start: %x - ui_p_reg_end %x (size %x)\n", ui_p_reg_start, ui_p_reg_end, (ui_p_reg_end - ui_p_reg_start));
    printf("Checksum = 0x");
    for(i=0; i<32; i++) printf("%x", digest[i]);
    printf("\n");


    /* initialise the platform */
    init_plat();

    /* make the free memory available to alloc_region() */
    init_freemem(ui_reg);

    /* create the root cnode */
    root_cnode_cap = create_root_cnode();
    if (cap_get_capType(root_cnode_cap) == cap_null_cap) {
        return false;
    }

    /* create the cap for managing thread domains */
    create_domain_cap(root_cnode_cap);

    /* create the IRQ CNode */
    if (!create_irq_cnode()) {
        return false;
    }

    /* initialise the IRQ states and provide the IRQ control cap */
    init_irqs(root_cnode_cap);

    /* create the bootinfo frame */
    bi_frame_pptr = allocate_bi_frame(0, 1, ipcbuf_vptr);
    if (!bi_frame_pptr) {
        return false;
    }

    /* Construct an initial address space with enough virtual addresses
     * to cover the user image + ipc buffer and bootinfo frames */
    it_pd_cap = create_it_address_space(root_cnode_cap, it_v_reg);
    if (cap_get_capType(it_pd_cap) == cap_null_cap) {
        return false;
    }

    /* Create and map bootinfo frame cap */
    create_bi_frame_cap(
        root_cnode_cap,
        it_pd_cap,
        bi_frame_pptr,
        bi_frame_vptr
    );

    /* create the initial thread's IPC buffer */
    ipcbuf_cap = create_ipcbuf_frame(root_cnode_cap, it_pd_cap, ipcbuf_vptr);
    if (cap_get_capType(ipcbuf_cap) == cap_null_cap) {
        return false;
    }

    /* create all userland image frames */
    create_frames_ret =
        create_frames_of_region(
            root_cnode_cap,
            it_pd_cap,
            ui_reg,
            true,
            pv_offset
        );
    if (!create_frames_ret.success) {
        return false;
    }
    ndks_boot.bi_frame->ui_frame_caps = create_frames_ret.region;

    /* create/initialise the initial thread's ASID pool */
    it_ap_cap = create_it_asid_pool(root_cnode_cap);
    if (cap_get_capType(it_ap_cap) == cap_null_cap) {
        return false;
    }
    write_it_asid_pool(it_ap_cap, it_pd_cap);

    /* create the idle thread */
    if (!create_idle_thread()) {
        return false;
    }

    /* Before creating the initial thread (which also switches to it)
     * we clean the cache so that any page table information written
     * as a result of calling create_frames_of_region will be correctly
     * read by the hardware page table walker */
    cleanInvalidateL1Caches();

    /* create the initial thread */
    if (!create_initial_thread(
                root_cnode_cap,
                it_pd_cap,
                v_entry,
                bi_frame_vptr,
                ipcbuf_vptr,
                ipcbuf_cap
            )) {
        return false;
    }

    /* convert the remaining free memory into UT objects and provide the caps */
    if (!create_untypeds(
                root_cnode_cap,
    (region_t) {
    kernelBase, (pptr_t)ki_boot_end
    } /* reusable boot code/data */
            )) {
        return false;
    }

    /* create device frames */
    if (!create_device_frames(root_cnode_cap)) {
        return false;
    }

    /* no shared-frame caps (ARM has no multikernel support) */
    ndks_boot.bi_frame->sh_frame_caps = S_REG_EMPTY;

    /* finalise the bootinfo frame */
    bi_finalise();

    /* make everything written by the kernel visible to userland. Cleaning to PoC is not
     * strictly neccessary, but performance is not critical here so clean and invalidate
     * everything to PoC */
    cleanInvalidateL1Caches();

#ifdef CONFIG_BENCHMARK
    armv_init_ccnt();
#endif /* CONFIG_BENCHMARK */

    /* Export selected CPU features for access by PL0 */
    armv_init_user_access();

    /* kernel successfully initialized */
    return true;
}

BOOT_CODE VISIBLE void
init_kernel(
    paddr_t ui_p_reg_start,
    paddr_t ui_p_reg_end,
    int32_t pv_offset,
    vptr_t  v_entry
)
{
    bool_t result;

    result = try_init_kernel(ui_p_reg_start,
                             ui_p_reg_end,
                             pv_offset,
                             v_entry);
    if (!result) {
        fail ("Kernel init failed for some reason :(");
    }

}

