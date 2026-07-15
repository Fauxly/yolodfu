#!/usr/bin/env python3
"""Build the supported T8020 yoloDFU iBSS artifact."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from yolodfu.ibss_patches import build_yolodfu_base


YOLODFU = ROOT
BUILD = YOLODFU / os.environ.get("YOLODFU_BUILD", "build")

IMAGE_BASE = 0x19C040000
HOOK_VA = 0x19C073FC8
HOOK_OLD = bytes.fromhex("1f8708d59f3f03d5df3f03d5a00038d5")
WRAPPER_VA = 0x19C0EF1F8
WRAPPER_MAX = 0x100
RUNTIME_VA = 0x19C17D7B8
RUNTIME_MAX = 0x2000


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def offset(va: int) -> int:
    return va - IMAGE_BASE


def require_bytes(image: bytearray, va: int, expected: bytes, label: str) -> None:
    actual = bytes(image[offset(va) : offset(va) + len(expected)])
    if actual != expected:
        raise SystemExit(
            f"{label} mismatch at 0x{va:x}: expected={expected.hex()} actual={actual.hex()}"
        )


def install(image: bytearray, va: int, payload: bytes, maximum: int, label: str) -> None:
    if len(payload) > maximum:
        raise SystemExit(f"{label} too large: 0x{len(payload):x} > 0x{maximum:x}")
    require_bytes(image, va, b"\0" * maximum, f"{label} slot")
    image[offset(va) : offset(va) + len(payload)] = payload


def build_stubs() -> tuple[bytes, bytes, bytes]:
    subprocess.run(["make", "runtime", f"BUILD={BUILD.name}"], cwd=YOLODFU, check=True)
    hook = (BUILD / "hook.bin").read_bytes()
    wrapper = (BUILD / "wrapper.bin").read_bytes()
    runtime = (BUILD / "runtime.bin").read_bytes()
    if len(hook) != len(HOOK_OLD):
        raise SystemExit(f"hook must be 16 bytes, got {len(hook)}")
    if len(runtime) % 8:
        raise SystemExit(f"runtime must be 8-byte aligned, got {len(runtime)}")
    return hook, wrapper, runtime


def build_yolodfu(input_path: Path, output_path: Path, boot_args: str) -> None:
    hook, wrapper, runtime = build_stubs()
    input_data = input_path.read_bytes()
    image, notes = build_yolodfu_base(input_data, boot_args)

    require_bytes(image, HOOK_VA, HOOK_OLD, "copied-trampoline hook")
    install(image, WRAPPER_VA, wrapper, WRAPPER_MAX, "wrapper")
    install(image, RUNTIME_VA, runtime, RUNTIME_MAX, "runtime")
    image[offset(HOOK_VA) : offset(HOOK_VA) + len(hook)] = hook

    output_path.write_bytes(image)
    print(f"input:   {input_path} sha256={digest(input_data)}")
    print(f"output:  {output_path} sha256={digest(image)}")
    for note in notes:
        print(f"applied: {note.name}: {note.detail}")
    print(f"hook:    0x{HOOK_VA:x} size=0x{len(hook):x} sha256={digest(hook)}")
    print(f"wrapper: 0x{WRAPPER_VA:x} size=0x{len(wrapper):x} sha256={digest(wrapper)}")
    print(f"runtime: 0x{RUNTIME_VA:x} size=0x{len(runtime):x} sha256={digest(runtime)}")
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
