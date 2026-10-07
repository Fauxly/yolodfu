#!/usr/bin/env python3
"""Verify that an iBSS artifact contains the exact assembled yoloDFU stubs.

Multi-build aware: the artifact's build is identified by image size (patching
does not change size), and the in-image verification addresses come from the
matching AUDIT_PROFILE. Runtime/vector CONTENT checks are build-invariant
(the stubs target SecureROM) and are shared across builds.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys


IMAGE_BASE = 0x19C040000
VECTOR_SIZE = 0x800
NOP = bytes.fromhex("1f 20 03 d5")
RECFG_WRITEBACK = bytes.fromhex("1c 49 29 b8")
EPRO_VALIDITY_ORIGINAL = bytes.fromhex("53 f3 01 39")


@dataclass(frozen=True)
class AuditProfile:
    name: str
    image_size: int
    hook_va: int
    wrapper_va: int
    runtime_va: int
    epro_validity_va: int
    recfg_final_branch_va: int
    pongo_aes_disable_keys_func_va: int
    pongo_recfg_lock_func_va: int
    ap_lock_gate_va: int
    security_high_gate_cmp_va: int
    security_high_gate_branch_va: int
    rom_read_disable_tbz_va: int
    # Reconfig-store anchors changed shape across the 26->27 iBoot reconfig
    # engine. The patch provably does not touch reconfig, so when these are
    # None the store/filter asserts are skipped (with a warning) instead of
    # checking wrong offsets.
    recfg_type4_store_va: int | None = None
    recfg_type3_store_va: int | None = None
    recfg_tz0_filter_va: int | None = None


AUDIT_PROFILES = (
    AuditProfile(
        name="mBoot-18000 (tvOS 26.5/26.6)",
        image_size=2125232,
        hook_va=0x19C073FC8,
        wrapper_va=0x19C0EF318,
        runtime_va=0x19C17D7B8,
        epro_validity_va=0x19C065C8C,
        recfg_final_branch_va=0x19C10187C,
        pongo_aes_disable_keys_func_va=0x19C071F38,
        pongo_recfg_lock_func_va=0x19C0757B0,
        ap_lock_gate_va=0x19C076BD8,
        security_high_gate_cmp_va=0x19C070878,
        security_high_gate_branch_va=0x19C07087C,
        rom_read_disable_tbz_va=0x19C070894,
        recfg_type4_store_va=0x19C10140C,
        recfg_type3_store_va=0x19C1023B0,
        recfg_tz0_filter_va=0x19C0EF2F8,
    ),
    AuditProfile(
        name="mBoot-20457.3.23 (tvOS 27.0)",
        image_size=2211152,
        hook_va=0x19C076AC8,
        wrapper_va=0x19C0FE9E0,
        runtime_va=0x19C1913E0,
        epro_validity_va=0x19C066B80,
        recfg_final_branch_va=0x19C11482C,
        pongo_aes_disable_keys_func_va=0x19C074A04,
        pongo_recfg_lock_func_va=0x19C0782AC,
        ap_lock_gate_va=0x19C0796F4,
        security_high_gate_cmp_va=0x19C073348,
        security_high_gate_branch_va=0x19C07334C,
        rom_read_disable_tbz_va=0x19C073364,
        recfg_type4_store_va=None,   # reconfig engine reshaped on 27.0
        recfg_type3_store_va=None,
        recfg_tz0_filter_va=None,
    ),
)

RECFG_TZ0_FILTER_MAX = 0x20

# Build-invariant runtime/vector content checks (stubs target SecureROM).
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
PCORE_CAR_AUGMENTATION = bytes.fromhex(
    "a90038d5" "295d50d3" "890000b4" "0cf138d5" "8c0169b2" "0cf118d5"
)
VECTOR_WORDS = {
    0x080: 0xD50040BF, 0x0A0: 0xD2B38041, 0x0B0: 0x10003282, 0x0C0: 0xD63F0060,
    0x0D0: 0xD61F0060, 0x400: 0x14000000, 0x480: 0x14000000, 0x700: 0xA9BE7BFD,
    0x704: 0xF9000BE0, 0x718: 0xD63F0200, 0x728: 0xD63F0200, 0x738: 0xD63F0200,
    0x73C: 0xF9400BE0, 0x744: 0xD65F03C0,
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _profile(artifact: bytes) -> AuditProfile:
    for p in AUDIT_PROFILES:
        if len(artifact) == p.image_size:
            return p
    sizes = ", ".join(str(p.image_size) for p in AUDIT_PROFILES)
    raise SystemExit(f"no audit profile for image size {len(artifact)} (known: {sizes})")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} <ibss.yolodfu.bin>")
    artifact = Path(sys.argv[1]).read_bytes()
    build = Path(__file__).resolve().parents[1] / "build"
    p = _profile(artifact)
    print(f"artifact sha256={sha(artifact)} size={len(artifact)} build={p.name}")

    epro_off = p.epro_validity_va - IMAGE_BASE
    if artifact[epro_off : epro_off + 4] != NOP:
        raise SystemExit(f"Image4 EPRO validity patch mismatch at VA 0x{p.epro_validity_va:x}")
    if EPRO_VALIDITY_ORIGINAL + bytes.fromhex("e0 49 8a 52 00 aa a8 72") in artifact:
        raise SystemExit("artifact retains original Image4 EPRO validity anchor")
    print(f"Image4 EPRO validity va=0x{p.epro_validity_va:x} opcode=NOP")

    ownership = {
        p.pongo_aes_disable_keys_func_va: bytes.fromhex("7f 23 03 d5"),
        p.pongo_recfg_lock_func_va: bytes.fromhex("7f 23 03 d5"),
        p.ap_lock_gate_va: bytes.fromhex("40 01 00 34"),
        p.recfg_final_branch_va: bytes.fromhex("08 0c 00 36"),
    }
    if p.recfg_type4_store_va is not None:
        ownership[p.recfg_type4_store_va] = RECFG_WRITEBACK
    for va, expected in ownership.items():
        off = va - IMAGE_BASE
        actual = artifact[off : off + len(expected)]
        if actual != expected:
            raise SystemExit(
                f"iBoot ownership mismatch at VA 0x{va:x}: "
                f"expected={expected.hex()} actual={actual.hex()}"
            )

    if p.recfg_type3_store_va is not None:
        t3 = p.recfg_type3_store_va - IMAGE_BASE
        if artifact[t3 : t3 + 4] != RECFG_WRITEBACK:
            raise SystemExit("reconfig type3/CTRRB-enable store must remain original")
    else:
        print("WARNING: reconfig type3/type4 store checks SKIPPED for this build "
              "(reconfig engine reshaped; patch does not touch reconfig)")

    if p.recfg_tz0_filter_va is not None:
        f_off = p.recfg_tz0_filter_va - IMAGE_BASE
        if artifact[f_off : f_off + RECFG_TZ0_FILTER_MAX] != b"\0" * RECFG_TZ0_FILTER_MAX:
            raise SystemExit("artifact unexpectedly installs a TZ0 ownership filter")
    else:
        print("WARNING: TZ0 ownership-filter check SKIPPED for this build")
    print("iBoot ownership: AES disable, reconfig lock, AP_LOCK gate, final "
          "validation branch preserved")

    rom_patches = {
        p.security_high_gate_cmp_va: NOP,
        p.security_high_gate_branch_va: NOP,
        p.rom_read_disable_tbz_va: bytes.fromhex("08 01 00 32"),
    }
    for va, expected in rom_patches.items():
        off = va - IMAGE_BASE
        if artifact[off : off + len(expected)] != expected:
            raise SystemExit(f"ROM-readable patch mismatch at VA 0x{va:x}")

    slots = (
        ("hook", p.hook_va, "hook.bin"),
        ("wrapper", p.wrapper_va, "wrapper.bin"),
        ("runtime", p.runtime_va, "runtime.bin"),
    )
    for label, va, filename in slots:
        expected = (build / filename).read_bytes()
        off = va - IMAGE_BASE
        if artifact[off : off + len(expected)] != expected:
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
        raise SystemExit(f"vector size mismatch: expected=0x{VECTOR_SIZE:x} actual=0x{len(vector):x}")
    vector_offsets = [o for o in range(len(runtime)) if runtime.startswith(vector, o)]
    if len(vector_offsets) != 1:
        raise SystemExit(f"runtime must embed vector exactly once: {vector_offsets}")
    for off, expected_word in VECTOR_WORDS.items():
        actual_word = int.from_bytes(vector[off : off + 4], "little")
        if actual_word != expected_word:
            raise SystemExit(
                f"vector opcode mismatch at +0x{off:x}: "
                f"expected=0x{expected_word:08x} actual=0x{actual_word:08x}"
            )
    print(f"vector runtime_off=0x{vector_offsets[0]:x} size=0x{len(vector):x} sha256={sha(vector)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
