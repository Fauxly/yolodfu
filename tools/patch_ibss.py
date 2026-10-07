#!/usr/bin/env python3
"""Build the supported T8020 yoloDFU iBSS artifact (multi-build aware).

Static iBSS patches live in yolodfu.ibss_patches (selected per iBoot build by
input hash). Stub cave addresses live in tools/stub_addrs.py (the single
source shared with the Makefile). This driver installs the assembled
hook/wrapper/runtime stubs and cross-checks that the stubs encode the same
caves they are installed at, so a stub/slot mismatch can never ship.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from yolodfu.ibss_patches import build_yolodfu_base, digest
import stub_addrs


YOLODFU = ROOT
BUILD = YOLODFU / os.environ.get("YOLODFU_BUILD", "build")


@dataclass(frozen=True)
class SlotProfile:
    name: str
    hashes: frozenset
    image_base: int
    hook_va: int
    hook_old: bytes
    wrapper_max: int = 0x100
    runtime_max: int = 0x2000


SLOTS: tuple[SlotProfile, ...] = (
    SlotProfile(
        name="mBoot-18000 (tvOS 26.5/26.6)",
        hashes=frozenset({
            "c8d4aebc681d38a8925f3b86d0fa54cac23c39d525e53f088fd21c8045dc8f4d",
            "44b8df7038b23b1bda0e7d47a295c9e0cfdbf5c4aa414405d4f30855a6fbc0e8",
        }),
        image_base=0x19C040000,
        hook_va=0x19C073FC8,
        hook_old=bytes.fromhex("1f8708d59f3f03d5df3f03d5a00038d5"),
    ),
    SlotProfile(
        name="mBoot-20457.3.23 (tvOS 27.0)",
        hashes=frozenset({
            "d3fa7a7d6b06d40cca65557fbde0110917b776c14c5604213cbf26cc7e6d531f",
        }),
        image_base=0x19C040000,
        hook_va=0x19C076AC8,
        hook_old=bytes.fromhex("1f8708d59f3f03d5df3f03d5a00038d5"),
    ),
)


def _slots_by_hash(input_hash: str) -> SlotProfile:
    for s in SLOTS:
        if input_hash in s.hashes:
            return s
    accepted = sorted(h for s in SLOTS for h in s.hashes)
    raise SystemExit(
        "input sha256 mismatch (no matching slot profile)\n"
        f"accepted: {accepted}\n"
        f"actual:   {input_hash}"
    )


def digest_file(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def offset(image_base: int, va: int) -> int:
    return va - image_base


def require_bytes(image: bytearray, image_base: int, va: int, expected: bytes, label: str) -> None:
    o = offset(image_base, va)
    actual = bytes(image[o : o + len(expected)])
    if actual != expected:
        raise SystemExit(
            f"{label} mismatch at 0x{va:x}: expected={expected.hex()} actual={actual.hex()}"
        )


def install(image: bytearray, image_base: int, va: int, payload: bytes, maximum: int, label: str) -> None:
    if len(payload) > maximum:
        raise SystemExit(f"{label} too large: 0x{len(payload):x} > 0x{maximum:x}")
    o = offset(image_base, va)
    require_bytes(image, image_base, va, b"\0" * maximum, f"{label} slot")
    image[o : o + len(payload)] = payload


def _hook_encodes_va(hook: bytes) -> int:
    """Decode the movz/movk x16 sequence the hook uses to call the wrapper."""
    import struct
    words = struct.unpack("<4I", hook[:16])
    va = 0
    for w in words:
        if (w & 0x7F800000) == 0x52800000 and (w & 0x80000000):      # MOVZ x
            va |= ((w >> 5) & 0xFFFF) << (((w >> 21) & 3) * 16)
        elif (w & 0x7F800000) == 0x72800000 and (w & 0x80000000):    # MOVK x
            va |= ((w >> 5) & 0xFFFF) << (((w >> 21) & 3) * 16)
    return va


def _cross_check_stubs(hook: bytes, wrapper: bytes, wrapper_va: int, runtime_va: int) -> None:
    enc = _hook_encodes_va(hook)
    if enc != wrapper_va:
        raise SystemExit(
            f"stub/slot drift: hook calls wrapper at 0x{enc:x} but SlotProfile "
            f"installs wrapper at 0x{wrapper_va:x}. Rebuild stubs for this build "
            "(make clean) with the matching IBSS_INPUT."
        )
    if runtime_va.to_bytes(8, "little") not in wrapper:
        raise SystemExit(
            f"stub/slot drift: wrapper does not reference runtime cave "
            f"0x{runtime_va:x}. Rebuild stubs (make clean) with matching IBSS_INPUT."
        )


def build_stubs() -> tuple[bytes, bytes, bytes]:
    subprocess.run(["make", "runtime", f"BUILD={BUILD.name}"], cwd=YOLODFU, check=True)
    hook = (BUILD / "hook.bin").read_bytes()
    wrapper = (BUILD / "wrapper.bin").read_bytes()
    runtime = (BUILD / "runtime.bin").read_bytes()
    if len(hook) != 16:
        raise SystemExit(f"hook must be 16 bytes, got {len(hook)}")
    if len(runtime) % 8:
        raise SystemExit(f"runtime must be 8-byte aligned, got {len(runtime)}")
    return hook, wrapper, runtime


def build_yolodfu(input_path: Path, output_path: Path, boot_args: str) -> None:
    input_data = input_path.read_bytes()
    input_hash = digest(input_data)
    slots = _slots_by_hash(input_hash)
    caves = stub_addrs.caves_for_hash(input_hash)
    if not caves["ready"]:
        raise SystemExit(
            f"refusing to build: stubs not marked ready for {slots.name}. "
            "See PORT_27.0_STATUS.md."
        )

    hook, wrapper, runtime = build_stubs()
    if len(hook) != len(slots.hook_old):
        raise SystemExit(f"hook must be {len(slots.hook_old)} bytes, got {len(hook)}")
    _cross_check_stubs(hook, wrapper, caves["wrapper_va"], caves["runtime_va"])

    image, notes = build_yolodfu_base(input_data, boot_args)
    base = slots.image_base

    require_bytes(image, base, slots.hook_va, slots.hook_old, "copied-trampoline hook")
    install(image, base, caves["wrapper_va"], wrapper, slots.wrapper_max, "wrapper")
    install(image, base, caves["runtime_va"], runtime, slots.runtime_max, "runtime")
    image[offset(base, slots.hook_va) : offset(base, slots.hook_va) + len(hook)] = hook

    output_path.write_bytes(image)
    print(f"build:   {slots.name}")
    print(f"input:   {input_path} sha256={input_hash}")
    print(f"output:  {output_path} sha256={digest_file(image)}")
    for note in notes:
        print(f"applied: {note.name}: {note.detail}")
    print(f"hook:    0x{slots.hook_va:x} size=0x{len(hook):x}")
    print(f"wrapper: 0x{caves['wrapper_va']:x} size=0x{len(wrapper):x}")
    print(f"runtime: 0x{caves['runtime_va']:x} size=0x{len(runtime):x}")
    print("contract: owned EL1 yolo runtime; iBoot retains TZ0 and Boot TZ0 ownership")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--boot-args", default="serial=3")
    parser.add_argument("--yolodfu", action="store_true", required=True)
    args = parser.parse_args()
    build_yolodfu(args.input.resolve(), args.output.resolve(), args.boot_args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
