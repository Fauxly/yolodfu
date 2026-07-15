.section .text
.global _start
.p2align 2

// Copied trampoline hook at runtime PC 0x870000088.
// The wrapper itself remains in the iBSS image at 0x19c0ef1f8.
_start:
    movz x16, #0xf1f8
    movk x16, #0x9c0e, lsl #16
    movk x16, #0x1, lsl #32
    blr  x16
