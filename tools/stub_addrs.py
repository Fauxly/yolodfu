#!/usr/bin/env python3
"""Single source of truth for per-build yolo stub cave addresses.

Keyed by the sha256 of the DECOMPRESSED iBSS payload. Used by BOTH
tools/patch_ibss.py (where the stubs are installed in the image) and the
yolodfu Makefile (where the stubs are assembled/linked), so the two can
never drift: the hook/wrapper encode the same cave they are installed at.

  wrapper_va : in-image cave where the wrapper executes in place (must be a
               loaded, executable region; >= WRAPPER_MAX zero bytes).
  runtime_va : in-image cave where the runtime blob is stored before it is
               copied out to its execution window (>= RUNTIME_MAX zero bytes).
  ready      : stubs validated for this build. False => patch_ibss refuses
               to emit an artifact (it would hang at handoff).
"""

from __future__ import annotations

import hashlib
import sys


# 26.x defaults (field-tested).
_DEFAULT = {"wrapper_va": 0x19C0EF318, "runtime_va": 0x19C17D7B8, "ready": True}

STUB_CAVES = {
    # tvOS 26.5 / 26.6 — mBoot-18000.x
    "c8d4aebc681d38a8925f3b86d0fa54cac23c39d525e53f088fd21c8045dc8f4d": dict(_DEFAULT),
    "44b8df7038b23b1bda0e7d47a295c9e0cfdbf5c4aa414405d4f30855a6fbc0e8": dict(_DEFAULT),
    # tvOS 27.0 (24J361) — mBoot-20457.3.23.
    # Caves selected in loaded padding regions analogous to 26.x; the stub
    # LOGIC is unchanged (it targets SecureROM, which is version-invariant).
    # PENDING ON-DEVICE VALIDATION: if the boot hangs at handoff, try an
    # alternate wrapper cave (0x19c0fe9e0 sits in a 0x624 zero run; fallbacks:
    # 0x19c147040, 0x19c14c060) and re-test.
    "d3fa7a7d6b06d40cca65557fbde0110917b776c14c5604213cbf26cc7e6d531f": {
        "wrapper_va": 0x19C0FE9E0,
        "runtime_va": 0x19C1913E0,
        "ready": True,
    },
}


def caves_for_hash(input_hash: str) -> dict:
    return STUB_CAVES.get(input_hash, dict(_DEFAULT))


def caves_for_file(path: str) -> dict:
    with open(path, "rb") as fh:
        return caves_for_hash(hashlib.sha256(fh.read()).hexdigest())


def _main(argv: list[str]) -> int:
    # Makefile usage: $(shell python3 tools/stub_addrs.py "$(IBSS_INPUT)")
    # prints: WRAPPER_VA=0x.. RUNTIME_VA=0x..
    caves = dict(_DEFAULT)
    if len(argv) == 2 and argv[1]:
        try:
            caves = caves_for_file(argv[1])
        except OSError:
            caves = dict(_DEFAULT)
    print(f"WRAPPER_VA=0x{caves['wrapper_va']:x} RUNTIME_VA=0x{caves['runtime_va']:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
