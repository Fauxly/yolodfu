.section .text
.global _start
.p2align 2

// Self-relocating raw-LZ4 loader used by the yoloDFU transport container.
// The first 0x200 bytes are copied to the receive buffer; compressed Pongo
// data follows immediately at compressed_payload. The container producer
// writes its compressed byte count into compressed_size before transfer.

_start:
    mov  x18, x30
    mov  x17, x0
    ldr  x1, t8020_sram_base
    mov  w3, #0x7fe00
    add  x5, x1, x3
    ldr  w2, compressed_size
wait_for_size:
    cbz  w2, wait_for_size
    sub  x0, x5, x2
    and  x0, x0, #0xfffffffffffffff0
    adr  x4, compressed_payload
    adr  x6, relocated_helper
    mov  x7, #0x1a0
copy_helper:
    ldr  w8, [x6], #4
    str  w8, [x5], #4
    sub  w7, w7, #4
    cbnz w7, copy_helper
    add  x5, x1, x3
    add  x6, x5, #0x1a0
    bl   clean_invalidate_range
    add  x5, x1, x3
    br   x5

relocated_helper:
    cmp  x0, x4
    b.eq helper_copy_done
    b.hi helper_copy_reverse
    mov  x6, x0
helper_copy_forward:
    ldp  x7, x8, [x4], #0x10
    stp  x7, x8, [x6], #0x10
    cmp  x6, x5
    b.lo helper_copy_forward
    b    helper_copy_done
helper_copy_reverse:
    add  x4, x4, x2
    add  x4, x4, #0xf
    and  x4, x4, #0xfffffffffffffff0
helper_copy_reverse_loop:
    ldp  x7, x8, [x4, #-0x10]!
    stp  x7, x8, [x5, #-0x10]!
    cmp  x5, x0
    b.hi helper_copy_reverse_loop
helper_copy_done:
    bl   raw_lz4_decompress
decompress_wait:
    cbz  x0, decompress_wait
    mov  x5, x14
    add  x6, x5, x0
    bl   clean_invalidate_range
    mrs  x8, currentel
    cmp  x8, #0xc
    b.ne 1f
    msr  sctlr_el3, xzr
1:
    msr  sctlr_el1, xzr
    isb
    mov  x0, x17
    mov  x30, x18
    mov  x18, x14
    br   x18

clean_invalidate_range:
    dsb  sy
2:
    dc   civac, x5
    add  x5, x5, #0x40
    cmp  x5, x6
    b.lo 2b
    dsb  sy
    isb
    ic   iallu
    isb
    ret

raw_lz4_decompress:
    mov  x15, x30
    mov  x14, x1
    adds x2, x0, x2
    b.hs lz4_failure
    adds x3, x1, x3
    b.hs lz4_failure
lz4_sequence:
    cmp  x0, x2
    b.hs lz4_failure
    ldrb w4, [x0], #1
    and  w5, w4, #0xf
    ubfx w4, w4, #4, #4
    cbz  w4, lz4_literals_done
    bl   lz4_extend_length
    cmp  x1, x0
    ccmp x1, x2, #2, hs
    ccmp x0, x2, #2, hs
    ccmp x1, x3, #2, lo
    sub  x6, x2, x0
    ccmp x4, x6, #2, lo
    sub  x6, x3, x1
    ccmp x4, x6, #2, ls
    b.hi lz4_failure
lz4_copy_literals:
    ldrb w6, [x0], #1
    strb w6, [x1], #1
    sub  x4, x4, #1
    cbnz x4, lz4_copy_literals
lz4_literals_done:
    cmp  w5, #0
    ccmp x0, x2, #0, eq
    b.hs lz4_success
    mov  w4, w5
    sub  x6, x2, x0
    cmp  x6, #2
    b.lo lz4_failure
    ldrb w5, [x0], #1
    ldrb w6, [x0], #1
    bfi  w5, w6, #8, #8
    cbz  w5, lz4_failure
    bl   lz4_extend_length
    adds x4, x4, #4
    b.hs lz4_failure
    subs x5, x1, x5
    ccmp x5, x14, #0, hs
    sub  x6, x3, x1
    ccmp x6, x4, #0, hs
    b.lo lz4_failure
lz4_copy_match:
    ldrb w6, [x5], #1
    strb w6, [x1], #1
    sub  x4, x4, #1
    cbnz x4, lz4_copy_match
    b    lz4_sequence

lz4_extend_length:
    cmp  w4, #0xf
    b.ne 3f
2:
    cmp  x0, x2
    b.hs lz4_failure
    ldrb w6, [x0], #1
    adds x4, x4, x6
    b.hs lz4_failure
    cmp  w6, #0xff
    b.eq 2b
3:
    ret

lz4_failure:
    mov  x1, x14
lz4_success:
    sub  x0, x1, x14
    ret  x15

t8020_sram_base:
    .quad 0x19c000000
compressed_size:
    // Preserved template value; build_container replaces it with the exact
    // compressed size for every produced container.
    .word 0x2421b
compressed_payload:
