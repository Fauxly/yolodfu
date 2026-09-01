# T8020 yoloDFU

This branch packages the T8020 transport stage between a patched iBoot and
PongoOS. It preserves the original yolo two-part runtime mechanism: an
image-resident wrapper installs an owned EL1 continuation, the continuation
recreates the required ROM state and translation regime, and the ROM DFU
consumer receives a 512-byte loader plus compressed Pongo image.

The supported iBSS inputs are `mBoot-18000.120.36` (tvOS 26.5, `23L471`) and
`mBoot-18000.120.40` (tvOS 26.6, `23L772`) for j305. Accepted SHA-256 values:

```
c8d4aebc681d38a8925f3b86d0fa54cac23c39d525e53f088fd21c8045dc8f4d  (26.5)
44b8df7038b23b1bda0e7d47a295c9e0cfdbf5c4aa414405d4f30855a6fbc0e8  (26.6)
```

Firmware binaries are not included. Supply a decrypted iBSS and a separately
built PongoOS image.

## Build

Requirements: Clang, LLD, Python 3, pkg-config, liblz4, and PyUSB for transfer.

```sh
make all
make patch IBSS_INPUT=/path/to/ibss.bin
make container PONGO_INPUT=/path/to/Pongo.bin
python3 tools/send_pongo.py build/pongo-container.bin
```

`make patch` verifies the exact input hash and audits the resulting write set.
`make container` verifies that the loader is exactly 512 bytes and round-trips
the compressed Pongo payload before writing the container.

## Ownership boundary

- iBoot retains AES-disable, reconfiguration lock, AP lock, TZ0, and Boot TZ0
  ownership.
- yoloDFU owns the EL1 runtime, ROM receive state, page tables, exception
  vector, and loader transport.
- PongoOS owns the next-stage kernel handoff.

## Credits

The yoloDFU mechanism was developed with
[mineek/openra1n](https://github.com/mineek/openra1n) as source-level reference
evidence and [checkra1n](https://checkra.in/) as the behavioral compatibility
reference. The maintained loader is standalone ARM64 assembly and reproduces
the openra1n reference loader's 512-byte binary exactly; neither project is a
build dependency or Git upstream of this repository.

Thanks to the openra1n contributors and checkra1n team for publishing the
reference work that made this implementation possible.

## Disclaimer

This repository is for security research, device recovery research, and
devices you own or have permission to test. Use it responsibly and follow
local laws.