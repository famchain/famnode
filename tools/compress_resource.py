#!/usr/bin/env python3
"""Compress a resource file using the famchain compressor (via QEMU).

Usage: python3 tools/compress_resource.py <input> <output>
"""
import os
import struct
import subprocess
import sys
import tempfile

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <input> <output>", file=sys.stderr)
    sys.exit(1)

input_path = sys.argv[1]
output_path = sys.argv[2]

AS = "riscv64-unknown-elf-as"
OBJCOPY = "riscv64-unknown-elf-objcopy"
MARCH = "-march=rv32i_zicsr -mabi=ilp32"

input_size = os.path.getsize(input_path)
print(f"Compressing {input_path} ({input_size} bytes)...", file=sys.stderr)

with tempfile.TemporaryDirectory() as tmp:
    # Patch the .incbin path
    asm_src = os.path.join(tmp, "compress.S")
    with open("tools/compress_resource.S") as f:
        src = f.read().replace("RESOURCE_PATH", input_path)
    with open(asm_src, "w") as f:
        f.write(src)

    # Assemble
    obj = os.path.join(tmp, "compress.o")
    binfile = os.path.join(tmp, "compress.bin")
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

    # Run in QEMU, capture stdout (binary compressed data)
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

    # First 4 bytes = compressed size (LE)
    compressed_size = struct.unpack('<I', raw[:4])[0]
    compressed_data = raw[4:4 + compressed_size]

    if len(compressed_data) != compressed_size:
        print(f"Size mismatch: header says {compressed_size}, got {len(compressed_data)}",
              file=sys.stderr)
        sys.exit(1)

    with open(output_path, 'wb') as f:
        f.write(compressed_data)

    ratio = compressed_size * 100 // input_size
    print(f"Wrote {output_path}: {compressed_size} bytes ({ratio}% of original)",
          file=sys.stderr)
