.section .text
.global _vector_start
.p2align 11

// T8020 EL1-only yolo vector. The backing is the final 16 KiB page of the
// current-cluster 4 MiB CRAM window at 0x19c3f8000, outside Pongo's overwrite.
// Only current-EL SP0 IRQ is a live consumer. The prefix is the
// T8011 mechanism expressed with T8020's common-save/restore ABI.

.equ ROM_COMMON,       0x100001028
.equ ROM_RESTORE,      0x1000010c8
.equ ROM_GATE_ENTER,   0x100011d00
.equ ROM_DISPATCH,     0x1000028bc
.equ ROM_GATE_LEAVE,   0x100011d40
.equ EXCEPTION_STACK,  0x19c020000

.macro fatal_slot
1:  b 1b
.endm

.macro load_rom reg, low, mid=0
    movz \reg, #\low
    movk \reg, #\mid, lsl #16
    movk \reg, #0x1, lsl #32
.endm

_vector_start:
    fatal_slot

    .org 0x80
current_el_sp0_irq:
    // Current-EL SP0 exception entry exposes SPSel=1. Select the interrupted
    // SP0 bank before constructing the architectural frame.
    msr  spsel, #0
    sub  sp, sp, #0x340
    stp  x0, x1, [sp]
    stp  x2, x3, [sp, #0x10]
    add  x0, sp, #0x340
    str  x0, [sp, #0xf8]
    stp  x29, x30, [sp, #0xe8]
    mov  x0, sp

    // T8020 common does not preserve x0 for restore. It does consume x2 as
    // the handler target; x3 is free after the prefix saved its original value.
    movz x1, #0x9c02, lsl #16
    movk x1, #0x1, lsl #32
    mov  sp, x1
    mov  x1, #0
    adr  x2, owned_el1_irq_handler
    load_rom x3, 0x1028
    blr  x3
    load_rom x3, 0x10c8
    br   x3

    .org 0x100
    fatal_slot
    .org 0x180
    fatal_slot
    .org 0x200
    fatal_slot
    .org 0x280
    fatal_slot
    .org 0x300
    fatal_slot
    .org 0x380
    fatal_slot
    .org 0x400
    fatal_slot
    .org 0x480
    fatal_slot
    .org 0x500
    fatal_slot
    .org 0x580
    fatal_slot
    .org 0x600
    fatal_slot
    .org 0x680
    fatal_slot

    .org 0x700
owned_el1_irq_handler:
    // Exact EL1 semantic shape of T8011 0x10000bc90 using independently
    // derived T8020 equivalents. Preserve the T8020 restore frame in x0.
    stp  x29, x30, [sp, #-0x20]!
    str  x0, [sp, #0x10]
    mov  x29, sp
    load_rom x16, 0x1d00, 0x1
    blr  x16
    load_rom x16, 0x28bc
    blr  x16
    // Gate-leave calls the current-task accessor and therefore clobbers x0.
    // Complete it before recovering the exception-frame pointer.  The split
    // T8020 common/restore ABI consumes that pointer in x0; returning the task
    // object here makes restore load "task" as x0 and zero as ELR/SPSR.
    load_rom x16, 0x1d40, 0x1
    blr  x16
    ldr  x0, [sp, #0x10]
    ldp  x29, x30, [sp], #0x20
    ret

    .org 0x780
    fatal_slot
    .org 0x800
