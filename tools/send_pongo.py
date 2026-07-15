#!/usr/bin/env /usr/bin/python3

import argparse
from pathlib import Path
import sys

import usb.core


APPLE_VID = 0x05AC
DFU_PID = 0x1227
DFU_DNLOAD = 1
DFU_ABORT = 4
TRANSFER_SIZE = 0x800


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a loader+Pongo container to yoloDFU")
    parser.add_argument("container", type=Path)
    args = parser.parse_args()

    payload = args.container.read_bytes()
    if not 0x200 <= len(payload) <= 0x100000:
        raise SystemExit(f"container size outside receive contract: 0x{len(payload):x}")

    device = usb.core.find(idVendor=APPLE_VID, idProduct=DFU_PID)
    if device is None:
        raise SystemExit("no Apple DFU device")
    serial = device.serial_number or ""
    if "YOLO:checkra1n" not in serial:
        raise SystemExit(f"device is not yoloDFU: {serial}")

    for offset in range(0, len(payload), TRANSFER_SIZE):
        chunk = payload[offset : offset + TRANSFER_SIZE]
        sent = device.ctrl_transfer(0x21, DFU_DNLOAD, 0, 0, chunk, timeout=1000)
        if sent != len(chunk):
            raise SystemExit(f"short transfer at 0x{offset:x}: {sent} != {len(chunk)}")
        print(f"\rsent 0x{offset + len(chunk):x}/0x{len(payload):x}", end="", flush=True)
    print()
    try:
        device.ctrl_transfer(0x21, DFU_ABORT, 0, 0, None, timeout=1000)
    except usb.core.USBError as error:
        if error.errno != 5:
            raise
        print("DFU_ABORT returned I/O error after full transfer; accepting consumer transition")
    return 0


if __name__ == "__main__":
    sys.exit(main())
