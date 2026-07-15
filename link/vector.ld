ENTRY(_vector_start)
SECTIONS { . = 0x19c018800; .text : { *(.text*) *(.rodata*) } }
