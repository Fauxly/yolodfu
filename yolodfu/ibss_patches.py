"""Exact mBoot-18000.120.36 iBSS writes used by T8020 yoloDFU."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib


IMAGE_BASE = 0x19C040000
EXPECTED_INPUT_SHA256 = "c8d4aebc681d38a8925f3b86d0fa54cac23c39d525e53f088fd21c8045dc8f4d"

IMAGE4_PROPERTY_CALLBACK_RESULT_VA = 0x19C066268
IMAGE4_PROPERTY_CALLBACK_RESULT_OLD = bytes.fromhex("e0 03 14 aa")
MOV_X0_0 = bytes.fromhex("00 00 80 d2")

BPR_BIT5_RESULT_VA = 0x19C070EAC
BPR_BIT5_RESULT_OLD = bytes.fromhex("00 15 05 53")
MOV_W0_0 = bytes.fromhex("00 00 80 52")

HANDOFF_BOOTARGS_HOOK_VA = 0x19C096200
HANDOFF_BOOTARGS_RETURN_VA = 0x19C096204
HANDOFF_BOOTARGS_OFFSET = 0x6C
HANDOFF_BOOTARGS_HELPER_MIN_OFFSET = 0x100000
PREPARE_JUMP_DISPLACED_INSN = bytes.fromhex("ff c3 01 d1")

# The handoff path calls this helper after PACIBSP.  Its normal body queries
# `disable-boot-wdt`; when the variable is absent it arms the boot watchdog
# before transferring control to the next stage.  yoloDFU deliberately retains
# ownership after the iBoot trampoline, so the watchdog must not be armed.
BOOT_WDT_BODY_VA = 0x19C096328
BOOT_WDT_BODY_OLD = bytes.fromhex("fd 7b bf a9")
RETAB = bytes.fromhex("ff 0f 5f d6")

DEVICETREE_PATH_OLD = b"/usr/standalone/firmware/devicetree.img4\x00"
DEVICETREE_PATH_NEW = b"/usr/standalone/firmware/nolanadt.img4\x00"

YOLO_MARKER_VA = 0x19C040200
YOLO_MARKER_OLD = bytes.fromhex("69 42 6f 6f")
YOLO_MARKER_NEW = bytes.fromhex("69 4e 6f 6f")

IORVBAR_LOCK_INPUT_VA = 0x19C04E37C
IORVBAR_LOCK_INPUT_OLD = bytes.fromhex("17 01 09 aa")
IORVBAR_LOCK_INPUT_NEW = bytes.fromhex("17 01 1f aa")

SECURITY_HIGH_GATE_CMP_VA = 0x19C070878
SECURITY_HIGH_GATE_CMP_OLD = bytes.fromhex("1f 01 04 71")
SECURITY_HIGH_GATE_BRANCH_VA = 0x19C07087C
SECURITY_HIGH_GATE_BRANCH_OLD = bytes.fromhex("63 0b 00 54")
ROM_READ_DISABLE_TBZ_VA = 0x19C070894
ROM_READ_DISABLE_TBZ_OLD = bytes.fromhex("a8 0a 00 36")
NOP = bytes.fromhex("1f 20 03 d5")
ORR_W8_W8_1 = bytes.fromhex("08 01 00 32")

# Image4 EPRO parser sequence:
#   strb w19, [x26, #0x7c]  ; valid_effective_production_status = true
#   mov  w0, #0x4550524f   ; 'EPRO'
# The following store at +0x18 records the EPRO value itself. Suppressing only
# the validity flag preserves all other Image4 verification decisions while
# preventing a demoted device state from being compared with a production
# image's effective-production property.
EPRO_VALIDITY_ANCHOR = bytes.fromhex(
    "53 f3 01 39 e0 49 8a 52 00 aa a8 72"
)

@dataclass(frozen=True)
class PatchNote:
    name: str
    detail: str


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def raw_offset(va: int) -> int:
    return va - IMAGE_BASE


def u32le(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little")


def check_bytes(data: bytearray, offset: int, expected: bytes, label: str) -> None:
    actual = bytes(data[offset : offset + len(expected)])
    if actual != expected:
        raise SystemExit(
            f"{label} anchor mismatch at 0x{offset:x}: "
            f"expected {expected.hex(' ')} actual {actual.hex(' ')}"
        )


def write(data: bytearray, va: int, expected: bytes, replacement: bytes, label: str) -> None:
    if len(expected) != len(replacement):
        raise ValueError(f"{label}: replacement changes patch width")
    patch_offset = raw_offset(va)
    check_bytes(data, patch_offset, expected, label)
    data[patch_offset : patch_offset + len(replacement)] = replacement


def arm64_b(pc: int, target: int) -> int:
    delta = target - pc
    if delta % 4:
        raise SystemExit(f"unaligned branch pc=0x{pc:x} target=0x{target:x}")
    imm26 = delta >> 2
    if not -(1 << 25) <= imm26 < (1 << 25):
        raise SystemExit(f"branch out of range pc=0x{pc:x} target=0x{target:x}")
    return 0x14000000 | (imm26 & 0x03FFFFFF)


def cbz_x(reg: int, pc: int, target: int) -> int:
    delta = target - pc
    if delta % 4:
        raise SystemExit(f"unaligned CBZ pc=0x{pc:x} target=0x{target:x}")
    imm19 = delta >> 2
    if not -(1 << 18) <= imm19 < (1 << 18):
        raise SystemExit(f"CBZ out of range pc=0x{pc:x} target=0x{target:x}")
    return 0xB4000000 | ((imm19 & 0x7FFFF) << 5) | (reg & 0x1F)


def movz_x(reg: int, immediate: int, shift: int) -> int:
    return 0xD2800000 | ((shift // 16) << 21) | ((immediate & 0xFFFF) << 5) | reg


def movk_x(reg: int, immediate: int, shift: int) -> int:
    return 0xF2800000 | ((shift // 16) << 21) | ((immediate & 0xFFFF) << 5) | reg


def mov_x_imm64(reg: int, value: int) -> bytes:
    return b"".join(
        u32le((movz_x if shift == 0 else movk_x)(reg, (value >> shift) & 0xFFFF, shift))
        for shift in (0, 16, 32, 48)
    )


def stur_x(rt: int, rn: int, immediate: int) -> int:
    if not -0x100 <= immediate <= 0xFF:
        raise SystemExit(f"STUR immediate out of range: 0x{immediate:x}")
    return 0xF8000000 | ((immediate & 0x1FF) << 12) | (rn << 5) | rt


def find_zero_cave(data: bytearray, size: int, minimum: int) -> int:
    found = bytes(data).find(b"\0" * size, minimum)
    if found < 0:
        raise SystemExit(f"unable to find zero codecave of size 0x{size:x}")
    return (found + 3) & ~3


def build_bootargs_helper(helper_va: int, boot_args: str) -> bytes:
    encoded = boot_args.encode("ascii") + b"\0"
    writes = bytearray()
    for chunk_offset in range(0, len(encoded), 8):
        chunk = encoded[chunk_offset : chunk_offset + 8].ljust(8, b"\0")
        writes += mov_x_imm64(9, int.from_bytes(chunk, "little"))
        writes += u32le(stur_x(9, 2, HANDOFF_BOOTARGS_OFFSET + chunk_offset))

    skip_writes = helper_va + 4 + len(writes)
    branch_pc = helper_va + 4 + len(writes) + len(PREPARE_JUMP_DISPLACED_INSN)
    return (
        u32le(cbz_x(2, helper_va, skip_writes))
        + writes
        + PREPARE_JUMP_DISPLACED_INSN
        + u32le(arm64_b(branch_pc, HANDOFF_BOOTARGS_RETURN_VA))
    )


def apply_common_patches(data: bytearray, boot_args: str) -> list[PatchNote]:
    notes: list[PatchNote] = []

    write(
        data,
        BOOT_WDT_BODY_VA,
        BOOT_WDT_BODY_OLD,
        RETAB,
        "boot watchdog setup",
    )
    notes.append(
        PatchNote(
            "disable_boot_wdt",
            f"return before boot watchdog setup at 0x{BOOT_WDT_BODY_VA:x}",
        )
    )

    write(
        data,
        IMAGE4_PROPERTY_CALLBACK_RESULT_VA,
        IMAGE4_PROPERTY_CALLBACK_RESULT_OLD,
        MOV_X0_0,
        "Image4 property callback result",
    )
    notes.append(
        PatchNote(
            "image4_property_callback_result",
            "force Image4 property callback success at "
            f"0x{IMAGE4_PROPERTY_CALLBACK_RESULT_VA:x}",
        )
    )

    write(data, BPR_BIT5_RESULT_VA, BPR_BIT5_RESULT_OLD, MOV_W0_0, "BPR bit5 result")
    notes.append(PatchNote("bpr_local_boot", f"force local boot at 0x{BPR_BIT5_RESULT_VA:x}"))

    epro_offset = bytes(data).find(EPRO_VALIDITY_ANCHOR)
    if epro_offset < 0:
        raise SystemExit("unable to find Image4 EPRO validity anchor")
    if bytes(data).find(EPRO_VALIDITY_ANCHOR, epro_offset + 1) >= 0:
        raise SystemExit("multiple Image4 EPRO validity anchors found")
    epro_va = IMAGE_BASE + epro_offset
    data[epro_offset : epro_offset + 4] = NOP
    notes.append(
        PatchNote(
            "demoted_localboot",
            f"leave effective-production validity clear at 0x{epro_va:x}",
        )
    )

    hook_offset = raw_offset(HANDOFF_BOOTARGS_HOOK_VA)
    check_bytes(data, hook_offset, PREPARE_JUMP_DISPLACED_INSN, "handoff bootargs hook")
    provisional = build_bootargs_helper(IMAGE_BASE, boot_args)
    helper_offset = find_zero_cave(data, len(provisional), HANDOFF_BOOTARGS_HELPER_MIN_OFFSET)
    helper_va = IMAGE_BASE + helper_offset
    helper = build_bootargs_helper(helper_va, boot_args)
    data[helper_offset : helper_offset + len(helper)] = helper
    data[hook_offset : hook_offset + 4] = u32le(arm64_b(HANDOFF_BOOTARGS_HOOK_VA, helper_va))
    notes.append(
        PatchNote(
            "handoff_bootargs",
            f"hook=0x{hook_offset:x} helper=0x{helper_offset:x} "
            f"length=0x{len(helper):x} args={boot_args!r}",
        )
    )

    old_offset = bytes(data).find(DEVICETREE_PATH_OLD)
    if old_offset < 0:
        raise SystemExit("unable to find original DeviceTree firmware path")
    if bytes(data).find(DEVICETREE_PATH_OLD, old_offset + 1) >= 0:
        raise SystemExit("multiple DeviceTree firmware path anchors found")
    replacement = DEVICETREE_PATH_NEW.ljust(len(DEVICETREE_PATH_OLD), b"\0")
    data[old_offset : old_offset + len(replacement)] = replacement
    notes.append(PatchNote("devicetree_path", f"rewrite DeviceTree path at 0x{old_offset:x}"))

    return notes


def apply_yolodfu_base_patches(data: bytearray) -> PatchNote:
    patches = (
        (YOLO_MARKER_VA, YOLO_MARKER_OLD, YOLO_MARKER_NEW, "yolo marker word"),
        (IORVBAR_LOCK_INPUT_VA, IORVBAR_LOCK_INPUT_OLD, IORVBAR_LOCK_INPUT_NEW, "IORVBAR lock input"),
        (SECURITY_HIGH_GATE_CMP_VA, SECURITY_HIGH_GATE_CMP_OLD, NOP, "security high-bit gate CMP"),
        (SECURITY_HIGH_GATE_BRANCH_VA, SECURITY_HIGH_GATE_BRANCH_OLD, NOP, "security high-bit gate branch"),
        (ROM_READ_DISABLE_TBZ_VA, ROM_READ_DISABLE_TBZ_OLD, ORR_W8_W8_1, "ROM-read-disable bit check"),
    )
    for va, expected, replacement, label in patches:
        write(data, va, expected, replacement, label)

    return PatchNote(
        "yolodfu_runtime_base",
        "apply yolo runtime compatibility writes while preserving iBoot AES, "
        "reconfiguration, AP_LOCK, TZ0, and Boot TZ0 ownership",
    )


def build_yolodfu_base(input_data: bytes, boot_args: str) -> tuple[bytearray, list[PatchNote]]:
    input_hash = digest(input_data)
    if input_hash != EXPECTED_INPUT_SHA256:
        raise SystemExit(
            "input sha256 mismatch\n"
            f"expected: {EXPECTED_INPUT_SHA256}\n"
            f"actual:   {input_hash}"
        )

    data = bytearray(input_data)
    notes = apply_common_patches(data, boot_args)
    notes.append(apply_yolodfu_base_patches(data))
    return data, notes
