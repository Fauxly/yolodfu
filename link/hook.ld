ENTRY(_start)
SECTIONS { . = 0x870000088; .text : { *(.text*) *(.rodata*) } }
