#!/usr/bin/env python3
"""Decompress a .cz file using the famchain decompressor (via QEMU).

Usage: python3 tools/decompress_resource.py <input.cz> <output>
"""
import os
import struct
import subprocess
import sys
import tempfile

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <input.cz> <output>", file=sys.stderr)
    sys.exit(1)

input_path = sys.argv[1]
output_path = sys.argv[2]

AS = "riscv64-unknown-elf-as"
OBJCOPY = "riscv64-unknown-elf-objcopy"
MARCH = "-march=rv32i_zicsr -mabi=ilp32"

input_size = os.path.getsize(input_path)
print(f"Decompressing {input_path} ({input_size} bytes)...", file=sys.stderr)

with tempfile.TemporaryDirectory() as tmp:
    asm_src = os.path.join(tmp, "decompress.S")
    with open("tools/decompress_resource.S") as f:
        src = f.read().replace("RESOURCE_PATH", input_path)
    with open(asm_src, "w") as f:
        f.write(src)

    obj = os.path.join(tmp, "decompress.o")
    binfile = os.path.join(tmp, "decompress.bin")
    r = subprocess.run(f"{AS} {MARCH} -I inc -o {obj} {asm_src}",
                       shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"Assembly failed:\n{r.stderr}", file=sys.stderr)
        sys.exit(1)

    r = subprocess.run(f"{OBJCOPY} -O binary {obj} {binfile}",
                       shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"Objcopy failed:\n{r.stderr}", file=sys.stderr)
        sys.exit(1)

    r = subprocess.run(
        ["timeout", "60", "qemu-system-riscv32",
         "-machine", "virt", "-nographic", "-bios", "none", "-smp", "1",
         "-m", "256M",
         "-device", f"loader,file={binfile},addr=0x80000000"],
        input=b"", capture_output=True)

    if r.returncode != 0:
        print(f"QEMU failed (exit {r.returncode})", file=sys.stderr)
        sys.exit(1)

    raw = r.stdout
    if len(raw) < 4:
        print(f"Output too short ({len(raw)} bytes)", file=sys.stderr)
        sys.exit(1)

    decompressed_size = struct.unpack('<I', raw[:4])[0]
    decompressed_data = raw[4:4 + decompressed_size]

    if len(decompressed_data) != decompressed_size:
        print(f"Size mismatch: header says {decompressed_size}, got {len(decompressed_data)}",
              file=sys.stderr)
        sys.exit(1)

    with open(output_path, 'wb') as f:
        f.write(decompressed_data)

    print(f"Wrote {output_path}: {decompressed_size} bytes", file=sys.stderr)
