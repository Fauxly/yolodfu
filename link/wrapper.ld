ENTRY(_start)
SECTIONS { . = WRAPPER_VA; .text : { *(.text*) *(.rodata*) } }
