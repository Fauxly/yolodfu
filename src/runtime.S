.section .text
.global _start
.p2align 2

// T8020 port of the original yolo two-part runtime shape.
//
// The bootstrap runs from copied trampoline + 0xbc0.  It copies the owned
// continuation into DRAM, flushes it, and branches to its physical address.
// The continuation recreates ROM data/BSS and an owned EL1 translation
// regime.  After enabling that regime it changes PC to the 0x102... alias,
// exactly as required before ROM-global accesses and later ROM helpers.

.equ CONT_PA,          0x878058074
.equ CONT_VA,          0x102058074
.equ TABLE_PA,         0x87804c000
.equ L3_PA,            0x878050000
.equ VECTOR_PA,        0x19c3f8000
.equ VECTOR_VA,        VECTOR_PA
.equ STACK_EL1,        0x8780e0000
.equ STACK_EL0,        0x8780e1000
.equ RECEIVE_BASE,     0x878100000
.equ ARENA_BASE,       0x878200000
.equ ARENA_SIZE,       0x50000
.equ PONGO_BASE,       0x19c000000
.equ PONGO_MAP_SIZE,   0x200000

.equ ROM_DATA_SRC,     0x100024000
.equ ROM_DATA_DST,     0x19c008000
.equ ROM_DATA_LEN,     0x0b40
.equ ROM_BSS_DST,      0x19c008b40
.equ ROM_BSS_LEN,      0x0b500

_start:
    msr  daifset, #0xf
    mov  x28, x30
    mov  x27, x0

    // Original-yolo ordering: reset the event producer and run the callable
    // T8020 CPU/L2 setup block before touching the continuation DRAM backing.
    // DAIF remains masked until the owned, target-correct vector is installed
    // after TTBR0 replacement.
    ldr  x16, =0x23d2b0000
    str  wzr, [x16, #0x0c]
    str  wzr, [x16, #0x1c]
    ldr  x16, =0x100006660
    blr  x16

    // T8020's CAR producer is split across ROM reset and iBSS entry.  The
    // ROM block above restores geometry/ways/ready after the final trampoline
    // cleared them.  On PCORE, iBSS 0x19c070784..0x19c070790 additionally
    // enables bit 23 in s3_0_c15_c1_0.  Reproduce that target-owned half of
    // the producer exactly; T8011's ROM helper was self-contained here.
    mrs  x9, mpidr_el1
    ubfx x9, x9, #16, #8
    cbz  x9, 90f
    mrs  x12, s3_0_c15_c1_0
    orr  x12, x12, #0x800000
    msr  s3_0_c15_c1_0, x12
90:
    adr  x1, continuation_start
    ldr  x2, =CONT_PA
    adr  x3, continuation_end
    ldr  x0, =CONT_PA
    sub  x5, x3, x1
    add  x5, x2, x5
0:
    dc   civac, x0
    add  x0, x0, #0x40
    cmp  x0, x5
    b.lo 0b
    dsb  sy
1:
    ldr  w4, [x1], #4
    str  w4, [x2], #4
    cmp  x1, x3
    b.lo 1b

    ldr  x0, =CONT_PA
    mov  x1, x2
2:
    dc   cvac, x0
    add  x0, x0, #0x40
    cmp  x0, x1
    b.lo 2b
    dsb  sy
    ic   iallu
    dsb  sy
    isb
    ldr  x16, =CONT_PA
    br   x16

    // CONT_PA is 4 mod 8. Keep the source at the same congruence so copied
    // 64-bit literal-pool entries remain naturally aligned.
    nop
    nop
continuation_start:
    // Recreate the T8020 ROM data/BSS producer before consuming ROM globals.
    ldr  x1, =ROM_DATA_SRC
    ldr  x2, =ROM_DATA_DST
    mov  x3, #ROM_DATA_LEN
3:
    ldr  x4, [x1], #8
    str  x4, [x2], #8
    subs x3, x3, #8
    b.ne 3b

    ldr  x2, =ROM_BSS_DST
    mov  x3, #ROM_BSS_LEN
4:
    str  xzr, [x2], #8
    subs x3, x3, #8
    b.ne 4b

    // Produce the ROM Aff1 cache without entering its EL0-only SVC lock path.
    // The copied runtime remains EL1; with a zeroed cache, 0x1000006c8 would
    // execute SVC 0 before reading MPIDR. Read the same MPIDR_EL1[15:8] field
    // directly, publish the value first, then mark the cache valid.
    ldr  x1, =0x19c008b40
    mrs  x0, mpidr_el1
    ubfx w0, w0, #8, #8
    str  w0, [x1, #4]
    mov  w0, #1
    strb w0, [x1]
    ic   iallu

    // Relinquish old iBSS cache aliases before repurposing its backing as the
    // two verified table pages. A later dirty eviction must not resurrect old
    // image instructions over the new translation tables.
    ldr  x25, =TABLE_PA
    mov  x3, #0x8000
5:
    dc   civac, x25
    add  x25, x25, #0x40
    subs x3, x3, #0x40
    b.ne 5b
    dsb  sy

    ldr  x25, =TABLE_PA
    mov  x3, #0x8000
16:
    str  xzr, [x25], #8
    subs x3, x3, #8
    b.ne 16b

    ldr  x9, =TABLE_PA

    // Preserve original-yolo's first 32 MiB ROM identity block.
    ldr  x0, =0x100000000
    ldr  x5, =0x6a5
    mov  x1, #1
    bl   map_blocks

    // ROM-near EL1 continuation alias: VA 0x102000000 -> PA 0x878000000.
    // This keeps runtime code out of the loader/Pongo SRAM ABI while
    // requiring no additional L3 page. VA 0x102... is L2 entry +0x408.
    ldr  x0, =0x878000625
    str  x0, [x9, #0x408]

    // Original loader/Pongo SRAM mechanism, bound to T8020's current-cluster
    // CRAM alias at physical 0x19c000000; the producer above enables CRAM before
    // this owned translation regime is installed. Map exactly 2 MiB as 16 KiB
    // normal RWX pages, matching the original yolo loader output window.
    ldr  x0, =(L3_PA | 3)
    str  x0, [x9, #0x670]
    ldr  x0, =PONGO_BASE
    ldr  x1, =L3_PA
    mov  x2, #(PONGO_MAP_SIZE / 0x4000)
    ldr  x3, =0x607
6:
    orr  x4, x0, x3
    str  x4, [x1], #8
    add  x0, x0, #0x4000
    subs x2, x2, #1
    b.ne 6b

    // Keep the runtime vector alive until Pongo installs its own VBAR. Pongo
    // overwrites the low CRAM image but not this final 16 KiB CRAM page.
    ldr  x0, =(VECTOR_PA | 0x607)
    str  x0, [x1, #(0x7f0 - PONGO_MAP_SIZE / 0x4000 * 8)]

    // T8020 yolo remains EL1. Map ROM SRAM as NS normal EL1 memory; it contains
    // globals, the retired-trampoline vector, and the ROM exception stack.
    ldr  x5, =0x625
    ldr  x0, =0x19c000000
    mov  x1, #2
    bl   map_blocks

    // T8020 ROM-matched AttrIdx2 Device mapping, made privileged-only for the
    // owned EL1 runtime. Normal ROM uses ...0469 (AP=01); yolo must use AP=00
    // under PAN while preserving the target memory type: ...0429.
    ldr  x5, =0x60000000000429
    ldr  x0, =0x200000000
    mov  x1, #0x20
    bl   map_blocks
    // Native T8020 scheduler object 0x19c0081c0 owns controller base
    // 0x242400000 and accesses offsets 0x8100..0x810c. Map only its containing
    // 32 MiB block with the same accepted privileged AttrIdx2 contract.
    ldr  x0, =0x242000000
    mov  x1, #1
    bl   map_blocks
    ldr  x0, =0x600000000
    mov  x1, #0x10
    bl   map_blocks
    ldr  x0, =0x700c0000000
    mov  x1, #1
    bl   map_blocks

    // Keep the physical continuation/table backing reachable until PC changes
    // to the 0x102... alias.
    ldr  x5, =0x625
    ldr  x0, =0x878000000
    mov  x1, #1
    bl   map_blocks

    // Reuse the retired ROM-trampoline SRAM only after invalidating its old
    // cache lines. The vector occupies exactly one aligned 2 KiB VBAR table.
    ldr  x25, =VECTOR_PA
    mov  x3, #0x800
17:
    dc   civac, x25
    add  x25, x25, #0x40
    subs x3, x3, #0x40
    b.ne 17b
    dsb  sy

    adr  x1, vector_blob
    ldr  x2, =VECTOR_PA
    adr  x3, vector_blob_end
15:
    ldr  x4, [x1], #8
    str  x4, [x2], #8
    cmp  x1, x3
    b.lo 15b

    // Publish page tables and vector backing before changing translation.
    // Translation-table walks consume memory at PoC, not merely PoU; the
    // vector is also newly generated executable code. Clean the complete
    // owned window to PoC, then invalidate stale instruction-cache contents
    // before any exception can select the new VBAR.
    ldr  x25, =TABLE_PA
    mov  x3, #0x8000
7:
    dc   cvac, x25
    add  x25, x25, #0x40
    subs x3, x3, #0x40
    b.ne 7b
    ldr  x25, =VECTOR_PA
    mov  x3, #0x800
14:
    dc   cvac, x25
    add  x25, x25, #0x40
    subs x3, x3, #0x40
    b.ne 14b
    dsb  sy
    ic   iallu
    dsb  sy
    isb

    mov  w0, #0xff04
    msr  mair_el1, x0
    msr  ttbr0_el1, x9
    ldr  x0, =0x1659ca51c
    msr  tcr_el1, x0
    tlbi vmalle1
    dsb  sy
    isb
    mrs  x0, cpacr_el1
    orr  w0, w0, #0x300000
    msr  cpacr_el1, x0
    mov  w8, #0x100d
    mrs  x0, sctlr_el1
    orr  x0, x0, x8
    msr  sctlr_el1, x0
    isb

    // Do not keep executing through the physical alias after MMU enable.
    adr  x16, post_mmu
    adr  x17, continuation_start
    sub  x16, x16, x17
    ldr  x17, =CONT_VA
    add  x16, x17, x16
    br   x16

map_blocks:
    lsr  x4, x0, #22
    and  x4, x4, #0x3ff8
    add  x4, x9, x4
    mov  x7, #0x2000000
8:
    orr  x6, x0, x5
    str  x6, [x4], #8
    add  x0, x0, x7
    subs x1, x1, #1
    b.ne 8b
    ret

post_mmu:
    ldr  x16, =VECTOR_VA
    msr  vbar_el1, x16
    isb
    ldr  x16, =STACK_EL1
    msr  spsel, #1
    mov  sp, x16
    ldr  x16, =STACK_EL0
    msr  spsel, #0
    mov  sp, x16
    // Original yolo remains on SP_EL0 so current-EL IRQs enter vector +0x80.
    // Phase-1 discriminator: the previous runtime faulted when the ROM
    // receive path read this exact byte. A successful read reaches the hold
    // with x20=0x594f4c4f and x21 containing the byte value.
    ldr  x16, =0x19c01061a
    ldrb w21, [x16]

    // First independently verified T8020 migration of the original helper
    // sequence. 0x100009130 publishes 0x19c008470 at 0x19c011450 and selects
    // it as TPIDR_EL0 through its tail branch to 0x10000aaf4.
    ldr  x16, =0x100009130
    blr  x16
    mrs  x22, tpidr_el0

    // Original-yolo allocator mechanism with the independently derived T8020
    // PCORE CAR limit. 0x1b0000 + 0x30000 ends exactly at 0x1e0000.
    ldr  x16, =0x19c010cc0
    mov  w0, #1
    strb w0, [x16]

    // iBoot-3865's allocator validates that newly allocated payloads are
    // already zero. Own that producer contract for the complete yolo arena
    // before registering it; unlike the T8011 allocator, this ROM does not
    // clear a block before returning it.
    ldr  x8, =ARENA_BASE
    mov  x9, #ARENA_SIZE
13:
    stp  xzr, xzr, [x8], #16
    subs x9, x9, #16
    b.ne 13b
    dsb  sy

    ldr  x0, =ARENA_BASE
    mov  x1, #ARENA_SIZE
    mov  x2, #1
    ldr  x16, =0x10000fc5c
    blr  x16
    ldr  x16, =0x19c011468
    ldr  x23, [x16]

    // Reproduce the decision prefix of the T8020 normal buffer wrapper, but
    // register original yolo's fixed receive range through the real lower
    // producer instead of consuming the normal-startup buffer/length.
    ldr  x21, =0x19c00c1b0
    ldr  x8, =0x202c0000
    str  w8, [x21, #4]

    ldr  x16, =0x100011ed8
    blr  x16
    ldr  w8, [x21, #4]
    mov  w9, #0x10
    mov  w10, #0x10000000
    cmp  w0, #0
    csel w9, w10, w9, ne
    orr  w8, w8, w9
    str  w8, [x21, #4]

    ldr  x16, =0x100011ecc
    blr  x16
    cbnz w0, 9f
    ldr  w8, [x21, #4]
    ldr  w9, =0x20100000
    orr  w8, w8, w9
    str  w8, [x21, #4]
9:
    ldr  x16, =0x100006f2c
    blr  x16
    cbz  w0, 10f
    ldr  w8, [x21, #4]
    orr  w8, w8, #0x08000000
    str  w8, [x21, #4]
10:
    mov  x8, #-1
    stp  x8, xzr, [x21, #8]
    ldr  x0, =RECEIVE_BASE
    mov  x1, #0x100000
    mov  x2, #0
    ldr  x16, =0x100008d80
    blr  x16

    ldr  w24, [x21, #4]
    ldp  x25, x26, [x21, #8]

    // T8020 scheduler gate producer. The exact ROM entry, unlike the legacy
    // 0x1000115b8 data-table address, is 0x1000115f8.
    ldr  x0, =0x19c024000
    mov  x1, #0xc000
    ldr  x16, =0x1000115f8
    blr  x16
    ldr  x16, =0x19c011380
    ldrh w8, [x16]

    // Direct structural equivalent of original T8011 helper 0x10000a878:
    // counter/entropy seed, scheduler list, idle task, and task-state publish.
    ldr  x16, =0x100009144
    blr  x16
    ldr  x16, =0x19c0105d0
    ldr  w8, [x16]

    // T8020's USB complex has three ordered power-domain producers. Normal
    // ROM's enable mask and iBSS's working USB callback both apply
    // 0x67 -> 0x68 -> 0x6a; independent m1n1 T8020 code likewise enables
    // three ADT domains before touching PHY/DWC2. The receive-owned
    // 0x10000298c redundantly enables only 0x67/0x68, so produce the complete
    // target prerequisite here without replaying the broad PMGR bootstrap.
    mov  w0, #0x67
    mov  w1, #1
    ldr  x16, =0x100003b04
    blr  x16
    mov  w0, #0x68
    mov  w1, #1
    ldr  x16, =0x100003b04
    blr  x16
    mov  w0, #0x6a
    mov  w1, #1
    ldr  x16, =0x100003b04
    blr  x16

    // Preserve the original yolo gate-pulse edge. Receive owns the full
    // 0x10000298c controller initialization.
    ldr  x16, =0x100002c48
    blr  x16

    // T8020 AIC configuration producer. It programs SOUTH_BRIDGE_PMS_AIC at
    // 0x23b100000, clears pending interrupts through 0x10000276c, and owns
    // its internal guard leave. Adding an external 0x100011c70 guard-enter
    // changes the guard transition from 1 -> 0 to 2 -> 1 and leaves DAIF
    // masked.
    ldr  x16, =0x1000026f0
    blr  x16
    ldr  x16, =0x10000acf0
    blr  x16

    // Original serial producer. Its T8020 entry owns the main serial state at
    // 0x19c00bc50 and returns the serial backing store at 0x19c00bc58.
    mov  x0, #1
    ldr  x16, =0x1000061a0
    blr  x16
    mov  x22, x0
    ldr  x16, =0x19c00bc50
    ldr  w23, [x16]

    // Preserve the original direct-write mechanism and offsets. The base
    // serial producer leaves the separating space before serial+0x48.
    adr  x1, yolo_marker
    ldr  x2, =0x19c00bca0
    mov  x3, #(yolo_marker_end - yolo_marker)
11:
    ldrb w4, [x1], #1
    strb w4, [x2], #1
    subs x3, x3, #1
    b.ne 11b

    adr  x1, gang_marker
    ldr  x2, =0x19c00bcd7
    mov  x3, #(gang_marker_end - gang_marker)
12:
    ldrb w4, [x1], #1
    strb w4, [x2], #1
    subs x3, x3, #1
    b.ne 12b

    ldr  x16, =0x19c00bc54
    mov  w0, #2
    str  w0, [x16]
    ldr  x16, =0x19c010610
    strb wzr, [x16]

    // The exact T8020 ROM AUSB producer hard-codes 0x03000011 at
    // 0x239000048 because its native DMA backing lives in the 0x1... PA
    // window.  This port owns ARENA_BASE in the 0x8... window, while the
    // AUSB DART SID0 remains in bypass/no-table mode.  Run the complete ROM
    // producer first, then retarget both enabled 32-bit AUSB remap channels
    // to PA bits [35:32] == 8.  The producer's BSS guard makes the call from
    // rom_usb_device_stack_init idempotently skip this exact sub-edge; all
    // downstream stack/controller initialization remains receive-owned.
    ldr  x16, =0x10000298c
    blr  x16
    ldr  x16, =0x239000048
    ldr  w17, =0x03000088
    str  w17, [x16]
    dsb  sy

    // T8020 iBoot-3865.0.0.4.7 receive wrapper entry. Its unique ROM caller
    // supplies x0=destination and x1=maximum length. The local .4.6 reference
    // places the same function at 0x10000e234 and must not drive this target.
    ldr  x0, =RECEIVE_BASE
    mov  x1, #0x100000
    ldr  x16, =0x10000e274
    blr  x16
    // 0x10000e274 returns the receive result code from state+0x08, while the
    // transient byte counter at state+0x0c is cleared by the DFU termination
    // path before this wrapper returns. The original loader container owns a
    // persistent raw-LZ4 length at +0x1fc; consume the same producer as the
    // loader and include its 0x200-byte header.
    ldr  x5, =RECEIVE_BASE
    ldr  w24, [x5, #0x1fc]
    add  x24, x24, #0x200

    // Preserve the original loader mechanism. It copies its helper within the
    // 0x19c000000 CRAM window, decompresses Pongo there, disables the current
    // MMU regime, and branches to the same physical address. Validate the four
    // ABI-critical words but do not rewrite them.
    cmp  x24, #0x200
    b.lo loader_contract_fatal
    ldr  x6, =0x100000
    cmp  x24, x6
    b.hi loader_contract_fatal
    ldr  x5, =RECEIVE_BASE
    ldr  w6, [x5, #0x008]
    ldr  w7, =0x58000f61       // T8020 LDR X1, shared CRAM-base literal
    cmp  w6, w7
    b.ne loader_contract_fatal
    ldr  w6, [x5, #0x00c]
    ldr  w7, =0x321727e3       // original MOV W3,#0x7fe00
    cmp  w6, w7
    b.ne loader_contract_fatal
    ldr  w6, [x5, #0x09c]
    ldr  w7, =0xaa0e03e5       // relocated helper MOV X5,X14
    cmp  w6, w7
    b.ne loader_contract_fatal
    ldr  w6, [x5, #0x0c8]
    ldr  w7, =0xaa0e03f2       // relocated helper MOV X18,X14
    cmp  w6, w7
    b.ne loader_contract_fatal
    add  x6, x5, #0x1f4
    ldr  x6, [x6]
    ldr  x7, =PONGO_BASE
    cmp  x6, x7
    b.ne loader_contract_fatal

    // Original handoff ordering: stop asynchronous consumers, publish received
    // instructions, restore the loader ABI, and branch to the loader at EL1.
    msr  daifset, #0xf
    ldr  x5, =RECEIVE_BASE
    add  x6, x5, x24
18:
    dc   civac, x5
    add  x5, x5, #0x40
    cmp  x5, x6
    b.lo 18b
    dsb  sy
    ic   iallu
    dsb  sy
    isb
    mov  x30, x28
    mov  x0, x27
    ldr  x16, =RECEIVE_BASE
    br   x16

loader_contract_fatal:
    msr  daifset, #0xf
    b    loader_contract_fatal

yolo_marker:
    .asciz "YOLO:checkra1n"
yolo_marker_end:
gang_marker:
    .asciz "GANG:KJC HAXX:Axi0mX ETA:son"
gang_marker_end:

.p2align 3
    // All continuation LDR literals must share the copied lifetime.
    .ltorg

    // Keep the source blob in the copied continuation lifetime. It is only a
    // producer after the explicit copy into VECTOR_PA above.
vector_blob:
    .incbin "build/vector.bin"
vector_blob_end:
continuation_end:
