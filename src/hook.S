.section .text
.global _start
.p2align 2

// Copied trampoline hook at runtime PC 0x870000088.
// The wrapper itself remains in the iBSS image at WRAPPER_VA (per-build cave).
#ifndef WRAPPER_VA
#error "define WRAPPER_VA"
#endif
_start:
    movz x16, #(WRAPPER_VA & 0xffff)
    movk x16, #((WRAPPER_VA >> 16) & 0xffff), lsl #16
    movk x16, #((WRAPPER_VA >> 32) & 0xffff), lsl #32
    blr  x16
