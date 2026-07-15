#!/usr/bin/env python3
"""Verify that an iBSS artifact contains the exact assembled yoloDFU stubs."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys


IMAGE_BASE = 0x19C040000
SLOTS = (
    ("hook", 0x19C073FC8, "hook.bin"),
    ("wrapper", 0x19C0EF1F8, "wrapper.bin"),
    ("runtime", 0x19C17D7B8, "runtime.bin"),
)
VECTOR_SIZE = 0x800
REQUIRED_RUNTIME_QWORDS = {
    0x102058074: "post-MMU EL1 continuation alias",
    0x87804C000: "TTBR page",
    0x19C3F8000: "Pongo-safe high-CRAM VBAR backing",
    0x8780E0000: "T8020 DRAM SP_EL1",
    0x8780E1000: "T8020 DRAM SP_EL0",
    0x878100000: "T8020 receive and loader base",
    0x878200000: "T8020 yolo runtime arena base",
    0x19C000000: "T8020 current-cluster CRAM loader and Pongo base",
    0x242000000: "native scheduler controller block",
    0x878000625: "EL1 continuation block alias descriptor",
    0x60000000000429: "T8020 AttrIdx2 privileged Device descriptor",
    0x10000298C: "complete T8020 AUSB producer entry",
    0x239000048: "T8020 AUSB USB-device DMA remap register",
    0x03000088: "AUSB 32-bit DMA remap to the 0x8 physical window",
}
FORBIDDEN_RUNTIME_QWORDS = {
    0x878054000: "unowned ROM L3 page",
    0x878050800: "vector overlap inside live L3 table",
    0x87805C000: "unowned dedicated vector page",
    0x0F805C000: "old vector alias",
    0x180058074: "loader-conflicting continuation alias",
    0x19C018800: "Pongo-overwritten low-CRAM VBAR backing",
    0x60000000000469: "EL0 Device descriptor",
    0x8780E4647: "receive-overlapping EL0 stack mapping",
    0x10000AC2C: "native lower-EL IRQ handler",
    0x1800A9000: "T8011-shaped SP_EL1",
    0x1800AA000: "T8011-shaped SP_EL0",
    0x1801B0000: "T8011 allocator arena base",
    0x1800B0000: "T8011 receive destination",
    0x60000000000421: "AttrIdx0 MMIO descriptor regression",
    0x100008218: "rejected standalone PMGR startup prefix",
}
REQUIRED_RUNTIME_OPCODES = {
    bytes.fromhex("08024079"): "scheduler observation in caller-scratch W8",
    bytes.fromhex("080240b9"): "task-state observation in caller-scratch W8",
    bytes.fromhex("610f0058"): "T8020 loader LDR X1,shared CRAM literal anchor",
    bytes.fromhex("e3271732"): "original loader MOV W3,#0x7fe00 anchor",
    bytes.fromhex("e5030eaa"): "relocated loader helper MOV X5,X14 anchor",
    bytes.fromhex("f2030eaa"): "relocated loader helper MOV X18,X14 anchor",
}
FORBIDDEN_RUNTIME_OPCODES = {
    bytes.fromhex("1b024079"): "scheduler observation clobbering saved ABI W27",
    bytes.fromhex("1c0240b9"): "task-state observation clobbering saved ABI W28",
    bytes.fromhex("a300a052"): "loader MOV W3,#0x50000 out-of-range helper placement",
    bytes.fromhex("25fb7f10"): "source-PC-relative helper ADR X5",
    bytes.fromhex("d2f97f10"): "source-PC-relative helper ADR X18",
    bytes.fromhex("650ce010"): "helper ADR X5 encoded for wrong copy-source offset",
    bytes.fromhex("120be010"): "helper ADR X18 encoded for wrong copy-source offset",
    bytes.fromhex("c1ff7f10"): "loader redirect from SRAM to yolo arena",
    bytes.fromhex("e3231732"): "loader bound rewritten for yolo arena",
    bytes.fromhex("c50de010"): "loader helper redirected to yolo arena",
    bytes.fromhex("720ce010"): "loader branch redirected to yolo arena",
    bytes.fromhex("c50a0058"): "relocated helper LDR X5 from unproduced SRAM literal",
    bytes.fromhex("72090058"): "relocated helper LDR X18 from unproduced SRAM literal",
    bytes.fromhex("e5c080d2"): "MOV X5,#0x607 T8011 CAR descriptor",
    bytes.fromhex("e5c480d2"): "MOV X5,#0x627 T8011 CAR descriptor variant",
}
VECTOR_WORDS = {
    0x080: 0xD50040BF,  # MSR SPSel,#0: current-EL SP0 IRQ prefix
    0x0A0: 0xD2B38041,  # exception stack low/mid = 0x19c020000
    0x0B0: 0x10003282,  # ADR X2, owned EL1 IRQ handler
    0x0C0: 0xD63F0060,  # BLR X3: T8020 common saver
    0x0D0: 0xD61F0060,  # BR X3: T8020 restore
    0x400: 0x14000000,  # lower-EL sync is fatal in EL1-only model
    0x480: 0x14000000,  # lower-EL IRQ is fatal in EL1-only model
    0x700: 0xA9BE7BFD,  # owned EL1 IRQ handler frame
    0x704: 0xF9000BE0,  # preserve T8020 common frame pointer X0
    0x718: 0xD63F0200,  # BLR X16: IRQ gate enter
    0x728: 0xD63F0200,  # BLR X16: event dispatcher
    0x738: 0xD63F0200,  # BLR X16: IRQ gate leave before frame recovery
    0x73C: 0xF9400BE0,  # restore T8020 common frame pointer X0
    0x744: 0xD65F03C0,  # RET to vector restore with frame pointer in X0
}
PCORE_CAR_AUGMENTATION = bytes.fromhex(
    "a90038d5"  # MRS X9,MPIDR_EL1
    "295d50d3"  # UBFX X9,X9,#16,#8
    "890000b4"  # CBZ X9,+0x10
    "0cf138d5"  # MRS X12,S3_0_C15_C1_0
    "8c0169b2"  # ORR X12,X12,#0x800000
    "0cf118d5"  # MSR S3_0_C15_C1_0,X12
)
EPRO_VALIDITY_VA = 0x19C065C8C
EPRO_VALIDITY_ORIGINAL = bytes.fromhex("53 f3 01 39")
NOP = bytes.fromhex("1f 20 03 d5")
RECFG_TYPE4_STORE_VA = 0x19C10140C
RECFG_TYPE3_STORE_VA = 0x19C1023B0
RECFG_FINAL_BRANCH_VA = 0x19C10187C
RECFG_TZ0_FILTER_VA = 0x19C0EF2F8
RECFG_TZ0_FILTER_MAX = 0x20
RECFG_WRITEBACK = bytes.fromhex("1c 49 29 b8")
PONGO_AES_DISABLE_KEYS_FUNC_VA = 0x19C071F38
PONGO_RECFG_LOCK_FUNC_VA = 0x19C0757B0
AP_LOCK_GATE_VA = 0x19C076BD8
SECURITY_HIGH_GATE_CMP_VA = 0x19C070878
SECURITY_HIGH_GATE_BRANCH_VA = 0x19C07087C
ROM_READ_DISABLE_TBZ_VA = 0x19C070894
IBOOT_OWNERSHIP_ORIGINALS = {
    PONGO_AES_DISABLE_KEYS_FUNC_VA: bytes.fromhex("7f 23 03 d5"),
    PONGO_RECFG_LOCK_FUNC_VA: bytes.fromhex("7f 23 03 d5"),
    AP_LOCK_GATE_VA: bytes.fromhex("40 01 00 34"),
    RECFG_TYPE4_STORE_VA: RECFG_WRITEBACK,
    RECFG_FINAL_BRANCH_VA: bytes.fromhex("08 0c 00 36"),
}
ROM_READABLE_PATCHES = {
    SECURITY_HIGH_GATE_CMP_VA: NOP,
    SECURITY_HIGH_GATE_BRANCH_VA: NOP,
    ROM_READ_DISABLE_TBZ_VA: bytes.fromhex("08 01 00 32"),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} <ibss.yolodfu.bin>")
    artifact_path = Path(sys.argv[1])
    artifact = artifact_path.read_bytes()
    build = Path(__file__).resolve().parents[1] / "build"
    print(f"artifact sha256={sha(artifact)} size={len(artifact)}")
    epro_off = EPRO_VALIDITY_VA - IMAGE_BASE
    if artifact[epro_off : epro_off + 4] != NOP:
        raise SystemExit(
            f"Image4 EPRO validity patch mismatch at VA 0x{EPRO_VALIDITY_VA:x}"
        )
    if EPRO_VALIDITY_ORIGINAL + bytes.fromhex("e0 49 8a 52 00 aa a8 72") in artifact:
        raise SystemExit("artifact retains original Image4 EPRO validity anchor")
    print(f"Image4 EPRO validity va=0x{EPRO_VALIDITY_VA:x} opcode=NOP")

    type3_off = RECFG_TYPE3_STORE_VA - IMAGE_BASE
    if artifact[type3_off : type3_off + 4] != RECFG_WRITEBACK:
        raise SystemExit("reconfig type3/CTRRB-enable store must remain original")
    for va, expected in IBOOT_OWNERSHIP_ORIGINALS.items():
        off = va - IMAGE_BASE
        actual = artifact[off : off + len(expected)]
        if actual != expected:
            raise SystemExit(
                f"iBoot ownership mismatch at VA 0x{va:x}: "
                f"expected={expected.hex()} actual={actual.hex()}"
            )
    filter_off = RECFG_TZ0_FILTER_VA - IMAGE_BASE
    if artifact[filter_off : filter_off + RECFG_TZ0_FILTER_MAX] != b"\0" * RECFG_TZ0_FILTER_MAX:
        raise SystemExit("artifact unexpectedly installs a TZ0 ownership filter")
    print(
        "iBoot ownership: AES disable, reconfig lock, AP_LOCK gate, TZ0 type4 "
        "store, and final validation branch preserved"
    )

    for va, expected in ROM_READABLE_PATCHES.items():
        off = va - IMAGE_BASE
        if artifact[off : off + len(expected)] != expected:
            raise SystemExit(f"ROM-readable patch mismatch at VA 0x{va:x}")

    for label, va, filename in SLOTS:
        expected = (build / filename).read_bytes()
        off = va - IMAGE_BASE
        actual = artifact[off : off + len(expected)]
        if actual != expected:
            raise SystemExit(f"{label} mismatch at VA 0x{va:x}")
        print(f"{label} va=0x{va:x} size=0x{len(expected):x} sha256={sha(expected)}")

    runtime = (build / "runtime.bin").read_bytes()
    vector = (build / "vector.bin").read_bytes()
    for value, label in REQUIRED_RUNTIME_QWORDS.items():
        if value.to_bytes(8, "little") not in runtime:
            raise SystemExit(f"runtime missing {label}: 0x{value:x}")
    for value, label in FORBIDDEN_RUNTIME_QWORDS.items():
        if value.to_bytes(8, "little") in runtime:
            raise SystemExit(f"runtime retains {label}: 0x{value:x}")
    for opcode, label in REQUIRED_RUNTIME_OPCODES.items():
        if runtime.count(opcode) != 1:
            raise SystemExit(f"runtime must contain exactly one {label}")
    for opcode, label in FORBIDDEN_RUNTIME_OPCODES.items():
        if opcode in runtime:
            raise SystemExit(f"runtime retains {label}")
    if runtime.count(PCORE_CAR_AUGMENTATION) != 1:
        raise SystemExit("runtime must contain exactly one T8020 PCORE CAR augmentation")
    if len(vector) != VECTOR_SIZE:
        raise SystemExit(
            f"vector size mismatch: expected=0x{VECTOR_SIZE:x} actual=0x{len(vector):x}"
        )
    vector_offsets = [
        off for off in range(len(runtime)) if runtime.startswith(vector, off)
    ]
    if len(vector_offsets) != 1:
        raise SystemExit(f"runtime must embed vector exactly once: {vector_offsets}")
    for off, expected_word in VECTOR_WORDS.items():
        actual_word = int.from_bytes(vector[off : off + 4], "little")
        if actual_word != expected_word:
            raise SystemExit(
                f"vector opcode mismatch at +0x{off:x}: "
                f"expected=0x{expected_word:08x} actual=0x{actual_word:08x}"
            )
    print(
        f"vector runtime_off=0x{vector_offsets[0]:x} size=0x{len(vector):x} "
        f"sha256={sha(vector)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
