ENTRY(_start)
SECTIONS { . = 0x870000bc0; .text : { *(.text*) *(.rodata*) } }
