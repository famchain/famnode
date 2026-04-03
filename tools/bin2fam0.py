#!/usr/bin/env python3
"""Convert a RISC-V 32-bit binary to fam0 hex format with disassembly comments.

Usage: python3 bin2fam0.py <binary> [output_file]

Output format (one instruction per line):
    XX XX XX XX # asm_instruction

Data sections (where objdump can't decode valid instructions) are
emitted as .word/.byte annotations instead.

If output_file is omitted, writes to stdout.
"""
import struct
import subprocess
import sys
import os

PREFIX = os.environ.get('RISCV_PREFIX', 'riscv64-unknown-elf')

# Instructions that objdump emits for invalid/data bytes
INVALID_MARKERS = {'???', '.insn', 'unimp'}

def is_valid_instruction(asm):
    """Return True if objdump produced a real instruction, not garbage."""
    if not asm or asm == '???':
        return False
    mnemonic = asm.split()[0] if asm else ''
    # objdump uses .insn for unrecognized encodings, and various FP
    # instructions (fsw, flw, fsd, etc.) that are unlikely in integer-only code
    if mnemonic in ('.insn', 'unimp'):
        return False
    # FP instructions are a sign of data being misinterpreted
    if mnemonic.startswith('f') and mnemonic not in ('fence',):
        return False
    return True

def format_data_word(b):
    """Format 4 bytes as a data annotation."""
    word = struct.unpack('<I', b)[0]
    # Check if all bytes are printable ASCII
    if all(0x20 <= byte < 0x7f for byte in b):
        chars = ''.join(chr(byte) for byte in b)
        return f'.word\t0x{word:08X}\t; "{chars}"'
    # Check if all bytes are small (likely a byte table)
    if all(byte < 32 for byte in b):
        return f'.byte\t{b[0]}, {b[1]}, {b[2]}, {b[3]}'
    return f'.word\t0x{word:08X}'

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary> [output_file]", file=sys.stderr)
        sys.exit(1)

    binfile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) >= 3 else None

    # Read raw binary
    with open(binfile, 'rb') as f:
        data = f.read()

    if len(data) % 4 != 0:
        print(f"Warning: binary size {len(data)} not a multiple of 4, padding", file=sys.stderr)
        data += b'\x00' * (4 - len(data) % 4)

    # Run objdump to get disassembly
    result = subprocess.run(
        [f'{PREFIX}-objdump', '-D', '-m', 'riscv:rv32', '-b', 'binary', binfile],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"objdump failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Parse objdump output into a map of offset -> disassembly
    disasm = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line[0] not in '0123456789abcdef':
            continue
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        try:
            offset = int(parts[0].rstrip(':'), 16)
            asm = '\t'.join(parts[2:])
            # Strip trailing comments from objdump (e.g., "# 0x248")
            if ' # ' in asm:
                asm = asm[:asm.index(' # ')]
            disasm[offset] = asm.strip()
        except (ValueError, IndexError):
            continue

    # Classify each word as code or data
    n_words = len(data) // 4
    is_code = [False] * n_words
    for i in range(n_words):
        offset = i * 4
        asm = disasm.get(offset, '???')
        is_code[i] = is_valid_instruction(asm)

    # Find the transition point where code ends and data begins.
    # When we see a bad word, check the next 8 words — if majority are bad,
    # this is the data section start.
    WINDOW = 8
    data_start = n_words
    for i in range(n_words):
        if not is_code[i]:
            window_end = min(i + WINDOW, n_words)
            bad_count = sum(1 for j in range(i, window_end) if not is_code[j])
            if bad_count >= (window_end - i) // 2:
                data_start = i
                break

    # Generate fam0 format
    lines = []
    in_data = False
    for i in range(n_words):
        b = data[i*4:(i+1)*4]
        hex_str = ' '.join(f'{byte:02X}' for byte in b)
        offset = i * 4

        if i >= data_start:
            if not in_data:
                lines.append('')
                lines.append('# ── data section ──')
                in_data = True
            annotation = format_data_word(b)
            lines.append(f'{hex_str} # {annotation}')
        else:
            asm = disasm.get(offset, '???')
            lines.append(f'{hex_str} # {asm}')

    output = '\n'.join(lines) + '\n'

    if outfile:
        with open(outfile, 'w') as f:
            f.write(output)
        print(f"Wrote {outfile} ({len(data)} bytes, {data_start} instructions, {n_words - data_start} data words)", file=sys.stderr)
    else:
        print(output, end='')

if __name__ == '__main__':
    main()
