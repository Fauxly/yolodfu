.section .text
.global _start
.p2align 2

// Image-resident producer at 0x19c0ef1f8.
// Input: x30 is copied-trampoline hook return (0x870000098).
// Output: installs runtime at copied trampoline + 0xbc0, patches the copied
// final RET, replays the displaced hook instructions, and returns to +0x98.
_start:
    mov  x18, x30
    and  x19, x30, #0xfffffffffffff000
    add  x20, x19, #0xbc0

    mov  x21, x30
1:
    ldr  w8, [x21], #4
    movz w9, #0x03c0
    movk w9, #0xd65f, lsl #16
    cmp  w8, w9
    b.ne 1b
    sub  x21, x21, #4

    // Encode B copied_runtime at the discovered final RET.
    sub  x8, x20, x21
    asr  x8, x8, #2
    and  w8, w8, #0x03ffffff
    movz w9, #0
    movk w9, #0x1400, lsl #16
    orr  w8, w8, w9
    str  w8, [x21]

    ldr  x22, =0x19c17d7b8
    ldr  x23, __yolodfu_runtime_size
    mov  x24, x20
2:
    cbz  x23, 3f
    ldr  x8, [x22], #8
    str  x8, [x24], #8
    sub  x23, x23, #8
    b    2b
3:
    mov  x8, x20
    mov  x9, x24
4:
    dc   cvau, x8
    add  x8, x8, #0x40
    cmp  x8, x9
    b.lo 4b
    dc   cvau, x21
    dsb  sy
    ic   iallu
    dsb  sy
    isb

    // Instructions displaced at the template hook.
    tlbi vmalle1
    dsb  sy
    isb
    mrs  x0, mpidr_el1
    br   x18

.p2align 3
__yolodfu_runtime_size:
    .quad YOLODFU_RUNTIME_SIZE
