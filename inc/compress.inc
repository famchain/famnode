# compress.inc — LZ77+Huffman compression/decompression for RISC-V 32-bit
#
# Based on czip's combined match code model. Single-block, no chunking.
# Pure RV32I scalar implementation. Interleaved extra bits (DEFLATE-style).
#
# Usage:
#   .include "macros.inc"
#   .include "compress.inc"
#   ...
#   DEFINE_COMPRESS
#
# Public labels emitted by DEFINE_COMPRESS:
#   compress_block(a0=in, a1=len, a2=out, a3=match_array) → a0=compressed size
#   decompress_block(a0=in, a1=len, a2=out, a3=capacity) → a0=decompressed size
#
# Requires: SETUP/RETURN/LOAD_ADDRESS macros from macros.inc
#
# Memory requirements (caller-allocated):
#   match_array: input_len * 4 + 4 bytes (u32 per entry)
#   output:      input_len + 3 bytes (compress bound)
#   Internally uses ~130 KB stack (hash table + temp buffers)
#
# Compressed format:
#   [4 bytes LE: decompressed_size]
#   [15 × 3 bits: book code lengths]
#   [variable: RLE-encoded main code lengths, Huffman-coded with book codes]
#   [variable: Huffman-encoded symbols with interleaved match extra bits]

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

.equ	CZ_MAX_MATCH_LEN,	256
.equ	CZ_MIN_MATCH_LEN,	4
.equ	CZ_MAX_CODE_LENGTH,	11
.equ	CZ_MAX_BOOK_CODE_LENGTH, 7
.equ	CZ_MAX_BOOK_CODES,	(CZ_MAX_CODE_LENGTH + 4)	# 15
.equ	CZ_SYMBOL_TERM,		256
.equ	CZ_MATCH_OFFSET,	(CZ_SYMBOL_TERM + 1)		# 257
.equ	CZ_MAX_MATCH_CODE,	127
.equ	CZ_SYMBOL_COUNT,	(CZ_MATCH_OFFSET + CZ_MAX_MATCH_CODE + 1)  # 385
.equ	CZ_HASH_CONSTANT,	0x9e3779b9
.equ	CZ_LEN_SHIFT,		4
.equ	CZ_DIST_MASK,		0xF
.equ	CZ_REPEAT_VALUE_INDEX,	(CZ_MAX_CODE_LENGTH + 1)	# 12
.equ	CZ_REPEAT_ZERO_LONG,	(CZ_MAX_CODE_LENGTH + 2)	# 13
.equ	CZ_REPEAT_ZERO_SHORT,	(CZ_MAX_CODE_LENGTH + 3)	# 14
.equ	CZ_HASH_TABLE_SIZE,	(1 << 16)			# 65536 entries × 2 bytes = 128 KB

# CodeLength struct: u16 code + u16 length = 4 bytes per entry
.equ	CZ_CL_CODE,		0
.equ	CZ_CL_LEN,		2
.equ	CZ_CL_SIZE,		4

# HuffmanLookup struct: u16 symbol + u8 length + u8 pad = 4 bytes per entry
.equ	CZ_HL_SYMBOL,		0
.equ	CZ_HL_LEN,		2
.equ	CZ_HL_SIZE,		4

# ──────────────────────────────────────────────────────────────────────────────
# CLZ: count leading zeros for RV32I (no Zbb)
# Input: a0 = value (must be > 0)
# Output: a0 = number of leading zeros (0..31)
# Clobbers: t0
# ──────────────────────────────────────────────────────────────────────────────
.macro CLZ_FUNC
_cz_clz:
	li	a0, 0
	li	t0, 0x80000000
1:	and	t1, a0, t0
	bnez	t1, 2f
	addi	a0, a0, 1
	srli	t0, t0, 1
	bnez	t0, 1b
2:	ret
.endm

# ──────────────────────────────────────────────────────────────────────────────
# Inline CLZ: result in \dst, input in \src. Clobbers \tmp.
# Only valid for \src > 0.
# ──────────────────────────────────────────────────────────────────────────────
.macro INLINE_CLZ dst, src, tmp
	li	\dst, 0
	li	\tmp, 0x80000000
98:	and	\dst, \src, \tmp		# reuse dst as test temporarily
	bnez	\dst, 99f
	srli	\tmp, \tmp, 1
	bnez	\tmp, 98b
99:
	# now tmp has the highest set bit position, count from top
	li	\dst, 31
	li	\tmp, 1
97:	sll	\tmp, \tmp, \dst
	and	\tmp, \tmp, \src
	bnez	\tmp, 96f
	addi	\dst, \dst, -1
	bgez	\dst, 97b
96:
	# dst = bit position (31 = MSB), we want CLZ = 31 - position
	li	\tmp, 31
	sub	\dst, \tmp, \dst
.endm

# ──────────────────────────────────────────────────────────────────────────────
# MATCH_CODE: compute combined match code from length and distance
# \len = match length (>= 4), \dist = distance (>= 1)
# Result in \dst. Clobbers \tmp1, \tmp2.
# match_code = ((31 - clz(len - 3)) << 4) | (31 - clz(dist))
# ──────────────────────────────────────────────────────────────────────────────
.macro CALC_MATCH_CODE dst, len, dist, tmp1, tmp2
	# len_bits = 31 - clz(len - 3)
	addi	\tmp1, \len, -3
	# find highest set bit of tmp1
	li	\dst, 0
	li	\tmp2, 1
93:	sll	\tmp2, \tmp2, \dst
	bltu	\tmp2, \tmp1, 92f
	beq	\tmp2, \tmp1, 91f
	addi	\dst, \dst, -1
	j	91f
92:	addi	\dst, \dst, 1
	li	\tmp2, 1
	j	93b
91:	# dst = floor(log2(len-3)) = len_bits
	slli	\dst, \dst, CZ_LEN_SHIFT

	# dist_bits = 31 - clz(dist) = floor(log2(dist))
	li	\tmp1, 0
	li	\tmp2, 1
90:	sll	\tmp2, \tmp2, \tmp1
	bltu	\tmp2, \dist, 89f
	beq	\tmp2, \dist, 88f
	addi	\tmp1, \tmp1, -1
	j	88f
89:	addi	\tmp1, \tmp1, 1
	li	\tmp2, 1
	j	90b
88:	# tmp1 = dist_bits
	or	\dst, \dst, \tmp1
.endm

.macro DEFINE_COMPRESS

# ══════════════════════════════════════════════════════════════════════════════
# Bitstream helpers
#
# Convention: s8=base, s9=byte_offset, s10=accumulator, s11=bits_in_accum
# Bounds: s3 = byte limit for reads (0 = no limit). When s9 >= s3, reads
# feed zero bytes instead of reading past the buffer.
# These are leaf functions — they do NOT save/restore registers.
# Callers must use SETUP to protect s8-s11 if needed.
# ══════════════════════════════════════════════════════════════════════════════

# _cz_bsw: write a0 (value) using a1 (nbits) to bitstream
# Clobbers: t0
_cz_bsw:
	sll	t0, a0, s11
	or	s10, s10, t0
	add	s11, s11, a1
_cz_bsw_loop:
	li	t0, 8
	blt	s11, t0, _cz_bsw_done
	add	t0, s8, s9
	sb	s10, 0(t0)
	addi	s9, s9, 1
	srli	s10, s10, 8
	addi	s11, s11, -8
	j	_cz_bsw_loop
_cz_bsw_done:
	ret

# _cz_bsw_flush: flush remaining bits (partial byte)
_cz_bsw_flush:
	beqz	s11, _cz_bswf_done
	add	t0, s8, s9
	sb	s10, 0(t0)
	addi	s9, s9, 1
	li	s10, 0
	li	s11, 0
_cz_bswf_done:
	ret

# _cz_bsr: read a0 (nbits) from bitstream, return value in a0
# Clobbers: t0, t4
# Bounds: if s3 > 0, checks s9 < s3 before each byte load (set s3=0 to disable)
_cz_bsr:
	mv	t4, a0
_cz_bsr_load:
	bge	s11, t4, _cz_bsr_extract
	bnez	s3, _cz_bsr_check
_cz_bsr_ok:
	add	t0, s8, s9
	lbu	t0, 0(t0)
	sll	t0, t0, s11
	or	s10, s10, t0
	addi	s9, s9, 1
	addi	s11, s11, 8
	j	_cz_bsr_load
_cz_bsr_check:
	blt	s9, s3, _cz_bsr_ok
	# past end of input — feed zeros (safe termination)
	addi	s11, s11, 8
	j	_cz_bsr_load
_cz_bsr_extract:
	li	t0, 1
	sll	t0, t0, t4
	addi	t0, t0, -1
	and	a0, s10, t0
	srl	s10, s10, t4
	sub	s11, s11, t4
	ret

# _cz_bs_ensure: ensure at least a0 bits in accumulator
# Clobbers: t0
# Bounds: if s3 > 0, checks s9 < s3 before each byte load
_cz_bs_ensure:
	bge	s11, a0, _cz_bse_done
	bnez	s3, _cz_bse_check
_cz_bse_ok:
	add	t0, s8, s9
	lbu	t0, 0(t0)
	sll	t0, t0, s11
	or	s10, s10, t0
	addi	s9, s9, 1
	addi	s11, s11, 8
	j	_cz_bs_ensure
_cz_bse_check:
	blt	s9, s3, _cz_bse_ok
	# past end — feed zeros
	addi	s11, s11, 8
	j	_cz_bs_ensure
_cz_bse_done:
	ret


# ══════════════════════════════════════════════════════════════════════════════
# calculate_codes: assign canonical Huffman codes from code lengths
# a0 = code_lengths ptr (array of CZ_CL_SIZE-byte structs)
# a1 = count
# Modifies the .code field of each entry. Clobbers s-regs via SETUP.
# ══════════════════════════════════════════════════════════════════════════════
_cz_calculate_codes:
	SETUP	s0, s1, s2, s3, s4, s5

	mv	s0, a0				# code_lengths ptr
	mv	s1, a1				# count

	# allocate length_count[12], length_start[12], length_pos[12] on stack
	# 3 × 12 × 4 = 144 bytes
	addi	sp, sp, -144
	mv	s2, sp				# length_count
	addi	s3, sp, 48			# length_start
	addi	s4, sp, 96			# length_pos

	# zero all three arrays
	li	t0, 36				# 144 / 4
	mv	t1, sp
1:	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, 1b

	# count lengths (skip out-of-range values)
	mv	t0, s0				# ptr
	mv	t1, s1				# count
_cz_cc_count:
	beqz	t1, _cz_cc_count_done
	lhu	t2, CZ_CL_LEN(t0)		# length
	beqz	t2, _cz_cc_count_next
	li	t3, CZ_MAX_CODE_LENGTH
	bgtu	t2, t3, _cz_cc_count_next	# skip invalid lengths
	slli	t3, t2, 2
	add	t3, s2, t3			# &length_count[length]
	lw	t4, 0(t3)
	addi	t4, t4, 1
	sw	t4, 0(t3)
_cz_cc_count_next:
	addi	t0, t0, CZ_CL_SIZE
	addi	t1, t1, -1
	j	_cz_cc_count

_cz_cc_count_done:
	# compute length_start
	li	s5, 0				# code = 0
	li	t0, 1				# i = 1
_cz_cc_start_loop:
	li	t1, CZ_MAX_CODE_LENGTH
	bgt	t0, t1, _cz_cc_start_done
	slli	s5, s5, 1			# code <<= 1
	slli	t2, t0, 2
	add	t2, s3, t2
	sw	s5, 0(t2)			# length_start[i] = code
	slli	t3, t0, 2
	add	t3, s2, t3
	lw	t3, 0(t3)			# length_count[i]
	add	s5, s5, t3			# code += length_count[i]
	addi	t0, t0, 1
	j	_cz_cc_start_loop

_cz_cc_start_done:
	# assign codes and reverse bits
	mv	t0, s0				# ptr
	mv	t1, s1				# count
_cz_cc_assign:
	beqz	t1, _cz_cc_done
	lhu	t2, CZ_CL_LEN(t0)		# length
	beqz	t2, _cz_cc_skip			# skip zero-length
	li	t3, CZ_MAX_CODE_LENGTH
	bgtu	t2, t3, _cz_cc_skip		# skip invalid length

	# code = length_start[len] + length_pos[len]++
	slli	t3, t2, 2
	add	t4, s3, t3			# &length_start[len]
	add	t5, s4, t3			# &length_pos[len]
	lw	t6, 0(t4)			# length_start[len]
	lw	t3, 0(t5)			# length_pos[len]
	add	t6, t6, t3			# code = start + pos
	addi	t3, t3, 1
	sw	t3, 0(t5)			# length_pos[len]++

	# mask code to len bits
	li	t3, 1
	sll	t3, t3, t2			# 1 << len
	addi	t3, t3, -1			# (1 << len) - 1
	and	t6, t6, t3			# code &= mask

	# reverse bits: reversed = 0, for j=0..len-1: reversed = (reversed<<1)|(code&1); code>>=1
	li	t3, 0				# reversed
	mv	t4, t2				# j = len
	mv	t5, t6				# temp code
_cz_cc_rev:
	beqz	t4, _cz_cc_rev_done
	slli	t3, t3, 1
	andi	t6, t5, 1
	or	t3, t3, t6
	srli	t5, t5, 1
	addi	t4, t4, -1
	j	_cz_cc_rev

_cz_cc_rev_done:
	sh	t3, CZ_CL_CODE(t0)		# store reversed code

_cz_cc_skip:
	addi	t0, t0, CZ_CL_SIZE
	addi	t1, t1, -1
	j	_cz_cc_assign

_cz_cc_done:
	addi	sp, sp, 144
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# build_lookup_table: fill Huffman decode table from code lengths
# a0 = code_lengths ptr
# a1 = count
# a2 = lookup_table ptr
# a3 = max_length (7 or 11)
# ══════════════════════════════════════════════════════════════════════════════
_cz_build_lookup_table:
	SETUP	s0, s1, s2, s3

	mv	s0, a0				# code_lengths
	mv	s1, a1				# count
	mv	s2, a2				# lookup_table
	mv	s3, a3				# max_length

	li	t0, 0				# i = 0
11:	bge	t0, s1, 12f
	# compute entry address
	slli	t1, t0, 2			# i * CZ_CL_SIZE (4)
	add	t1, s0, t1
	lhu	t2, CZ_CL_LEN(t1)		# length
	beqz	t2, 13f
	bgt	t2, s3, 13f			# length > max_length: skip (invalid)

	# index = code & ((1 << length) - 1)
	lhu	t3, CZ_CL_CODE(t1)		# code
	li	t4, 1
	sll	t4, t4, t2			# 1 << length
	addi	t4, t4, -1			# mask
	and	t3, t3, t4			# index

	# fill_depth = 1 << (max_length - length)
	sub	t4, s3, t2			# max_length - length
	li	t5, 1
	sll	t5, t5, t4			# fill_depth

	# fill table entries
	li	t4, 0				# j = 0
14:	bge	t4, t5, 13f
	# table_index = index | (j << length)
	sll	t6, t4, t2
	or	t6, t6, t3
	slli	t6, t6, 2			# * CZ_HL_SIZE
	add	t6, s2, t6
	sh	t0, CZ_HL_SYMBOL(t6)		# symbol = i
	sb	t2, CZ_HL_LEN(t6)		# length
	addi	t4, t4, 1
	j	14b

13:	addi	t0, t0, 1
	j	11b

12:	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# compress_block: compress input data
# a0 = input_ptr
# a1 = input_len (must be > 0)
# a2 = output_ptr (must be at least input_len + 3 bytes)
# a3 = match_array_ptr (must be at least input_len * 4 + 4 bytes, u32 entries)
# Returns: a0 = compressed output size in bytes, or -1 on error
# ══════════════════════════════════════════════════════════════════════════════
compress_block:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11

	# Input validation
	beqz	a1, _cz_err			# zero-length input

	mv	s0, a0				# input
	mv	s1, a1				# input_len
	mv	s2, a2				# output
	mv	s3, a3				# match_array

	# ── Phase 1: find_matches ──
	# Allocate hash table on stack: 64K entries × 2 bytes = 128 KB
	li	t0, CZ_HASH_TABLE_SIZE * 2	# 131072 bytes
	sub	sp, sp, t0
	mv	s4, sp				# s4 = hash_table

	# Zero hash table
	li	t0, CZ_HASH_TABLE_SIZE / 2	# 32768 words
	mv	t1, s4
15:	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, 15b

	# Allocate frequencies array: CZ_SYMBOL_COUNT × 4 = 1540 bytes (round to 1544)
	addi	sp, sp, -1544
	mv	s5, sp				# s5 = frequencies

	# Zero frequencies
	li	t0, 386				# ceil(1544/4)
	mv	t1, s5
16:	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, 16b

	# find_matches state
	li	s6, 0				# i = input position
	li	s7, 0				# maitt = match_array write index

	# max = len >= 32 + MAX_MATCH_LEN ? len - (32 + MAX_MATCH_LEN) : 0
	li	t0, 32 + CZ_MAX_MATCH_LEN	# 288
	sub	t0, s1, t0			# len - 288
	bgez	t0, 17f
	li	t0, 0
17:	# t0 = max, save to stack
	addi	sp, sp, -4
	sw	t0, 0(sp)

	# output data starts at output + 4 (first 4 bytes = decompressed_size)
	addi	s2, s2, 4			# skip header

_cz_match_loop:
	lw	t0, 0(sp)			# max
	bgeu	s6, t0, _cz_match_tail

	# key = *(u32*)(in + i)
	add	t0, s0, s6
	lbu	t1, 0(t0)
	lbu	t2, 1(t0)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 2(t0)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 3(t0)
	slli	t2, t2, 24
	or	t1, t1, t2			# t1 = key (unaligned u32 load)

	# hash = ((key >> 16) ^ key) & 0xFFFF
	# Note: with mul (RV32M), (key * 0x9e3779b9) >> 16 gives 2.84:1
	srli	t2, t1, 16
	xor	t2, t2, t1
	srli	t3, t2, 8
	xor	t2, t2, t3
	slli	t2, t2, 16
	srli	t2, t2, 16			# t2 = hash (16-bit)

	# dist = (u16)i - table[hash]
	slli	t3, t2, 1			# hash * 2
	add	t3, s4, t3			# &table[hash]
	lhu	t4, 0(t3)			# table[hash]
	# store current i into table
	sh	s6, 0(t3)
	# dist = (u16)i - old_entry
	slli	t5, s6, 16
	srli	t5, t5, 16			# (u16)i
	sub	t4, t5, t4			# dist (may be negative/wrapped)
	slli	t4, t4, 16
	srli	t4, t4, 16			# (u16)dist

	# if dist == 0, no match possible
	beqz	t4, _cz_no_match

	# compare bytes: len = 0; while (len < MAX_MATCH_LEN && in[i+len] == in[mpos+len]) len++
	sub	t5, s6, t4			# mpos = i - dist
	li	t6, 0				# len = 0
	add	t0, s0, s6			# in + i
	add	t1, s0, t5			# in + mpos
_cz_compare:
	li	t2, CZ_MAX_MATCH_LEN
	bge	t6, t2, _cz_compare_done
	lbu	t2, 0(t0)
	lbu	t3, 0(t1)
	bne	t2, t3, _cz_compare_done
	addi	t6, t6, 1
	addi	t0, t0, 1
	addi	t1, t1, 1
	j	_cz_compare
_cz_compare_done:

	# if len >= MIN_MATCH_LEN → emit match
	li	t0, CZ_MIN_MATCH_LEN
	blt	t6, t0, _cz_no_match

	# ── emit match ──
	# compute match_code = ((floor_log2(len-3)) << 4) | floor_log2(dist)
	# floor_log2(x) = 31 - clz(x) = position of highest set bit
	addi	t0, t6, -3			# len - 3

	# floor_log2(t0) → t1
	li	t1, 0
	mv	t2, t0
18:	srli	t2, t2, 1
	beqz	t2, 19f
	addi	t1, t1, 1
	j	18b
19:	# t1 = floor_log2(len-3) = len_bits
	slli	t1, t1, CZ_LEN_SHIFT		# len_bits << 4

	# floor_log2(t4=dist) → t2
	li	t2, 0
	mv	t3, t4
20:	srli	t3, t3, 1
	beqz	t3, 21f
	addi	t2, t2, 1
	j	20b
21:	# t2 = floor_log2(dist) = dist_bits
	or	t1, t1, t2			# t1 = match_code (mc)
	andi	t1, t1, 0x7F			# clamp to 7 bits

	# compute extra bits
	# leb = mc >> 4, deb = mc & 0xF
	srli	t2, t1, CZ_LEN_SHIFT		# leb
	andi	t3, t1, CZ_DIST_MASK		# deb

	# len_base = (1 << leb) - 1
	li	t5, 1
	sll	t5, t5, t2
	addi	t5, t5, -1			# len_base

	# dist_base = 1 << deb
	li	a0, 1
	sll	a0, a0, t3			# dist_base

	# len_extra_value = len - len_base - 4
	sub	a1, t6, t5
	addi	a1, a1, -4			# len_extra_value

	# dist_extra_value = dist - dist_base
	sub	a2, t4, a0			# dist_extra_value

	# combined_extra = (dist_extra << leb) | len_extra
	sll	a2, a2, t2			# dist_extra << leb
	or	a2, a2, a1			# combined_extra

	# compute match_symbol
	li	t0, CZ_MATCH_OFFSET
	add	t0, t0, t1			# match_symbol

	# increment frequency
	slli	t2, t0, 2
	add	t2, s5, t2
	lw	t3, 0(t2)
	addi	t3, t3, 1
	sw	t3, 0(t2)

	# pack entry: match_symbol | (combined_extra << 10)
	slli	a2, a2, 10
	or	t0, t0, a2

	# store in match_array (u32)
	slli	t2, s7, 2
	add	t2, s3, t2
	sw	t0, 0(t2)
	addi	s7, s7, 1

	# update hash for positions i+1, i+2, i+3 (seeds next match)
	addi	t0, s6, 1
	add	t0, s0, t0
	lbu	t1, 0(t0)
	lbu	t2, 1(t0)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 2(t0)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 3(t0)
	slli	t2, t2, 24
	or	t1, t1, t2
	srli	t2, t1, 16
	xor	t2, t2, t1
	srli	t3, t2, 8
	xor	t2, t2, t3
	slli	t2, t2, 16
	srli	t2, t2, 16
	slli	t3, t2, 1
	add	t3, s4, t3
	addi	t0, s6, 1
	sh	t0, 0(t3)

	addi	t0, s6, 2
	add	t0, s0, t0
	lbu	t1, 0(t0)
	lbu	t2, 1(t0)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 2(t0)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 3(t0)
	slli	t2, t2, 24
	or	t1, t1, t2
	srli	t2, t1, 16
	xor	t2, t2, t1
	srli	t3, t2, 8
	xor	t2, t2, t3
	slli	t2, t2, 16
	srli	t2, t2, 16
	slli	t3, t2, 1
	add	t3, s4, t3
	addi	t0, s6, 2
	sh	t0, 0(t3)

	addi	t0, s6, 3
	add	t0, s0, t0
	lbu	t1, 0(t0)
	lbu	t2, 1(t0)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 2(t0)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 3(t0)
	slli	t2, t2, 24
	or	t1, t1, t2
	srli	t2, t1, 16
	xor	t2, t2, t1
	srli	t3, t2, 8
	xor	t2, t2, t3
	slli	t2, t2, 16
	srli	t2, t2, 16
	slli	t3, t2, 1
	add	t3, s4, t3
	addi	t0, s6, 3
	sh	t0, 0(t3)

	# advance i by len
	add	s6, s6, t6
	j	_cz_match_loop

_cz_no_match:
	# emit literal
	add	t0, s0, s6
	lbu	t0, 0(t0)			# literal byte

	# match_array[maitt] = literal (u32, upper bits 0)
	slli	t1, s7, 2
	add	t1, s3, t1
	sw	t0, 0(t1)
	addi	s7, s7, 1

	# frequencies[literal]++
	slli	t1, t0, 2
	add	t1, s5, t1
	lw	t2, 0(t1)
	addi	t2, t2, 1
	sw	t2, 0(t1)

	addi	s6, s6, 1
	j	_cz_match_loop

_cz_match_tail:
	# emit remaining bytes as literals
	bge	s6, s1, _cz_match_done
	add	t0, s0, s6
	lbu	t0, 0(t0)
	slli	t1, s7, 2
	add	t1, s3, t1
	sw	t0, 0(t1)
	addi	s7, s7, 1
	slli	t1, t0, 2
	add	t1, s5, t1
	lw	t2, 0(t1)
	addi	t2, t2, 1
	sw	t2, 0(t1)
	addi	s6, s6, 1
	j	_cz_match_tail

_cz_match_done:
	# append SYMBOL_TERM
	li	t0, CZ_SYMBOL_TERM
	slli	t1, s7, 2
	add	t1, s3, t1
	sw	t0, 0(t1)
	# frequencies[SYMBOL_TERM]++
	slli	t1, t0, 2
	add	t1, s5, t1
	lw	t2, 0(t1)
	addi	t2, t2, 1
	sw	t2, 0(t1)

	# ── Phase 2: build Huffman codes ──
	# Allocate code_lengths: CZ_SYMBOL_COUNT × CZ_CL_SIZE = 385 × 4 = 1540 bytes
	addi	sp, sp, -1544
	mv	s6, sp				# s6 = code_lengths

	# Zero code_lengths
	li	t0, 386
	mv	t1, s6
22:	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, 22b

	# calculate_lengths(frequencies, code_lengths, SYMBOL_COUNT, MAX_CODE_LENGTH)
	mv	a0, s5				# frequencies
	mv	a1, s6				# code_lengths
	li	a2, CZ_SYMBOL_COUNT
	li	a3, CZ_MAX_CODE_LENGTH
	jal	_cz_calculate_lengths

	# calculate_codes(code_lengths, SYMBOL_COUNT)
	mv	a0, s6
	li	a1, CZ_SYMBOL_COUNT
	jal	_cz_calculate_codes

	# ── Phase 3: write compressed output ──
	# Reassign registers for output phase:
	# s4 = code_lengths, s5 = match_array loop index
	# s8-s11 = bitstream write state
	mv	s4, s6				# code_lengths ptr
	li	s5, 0				# match_array read index

	mv	s8, s2				# output base (past 4-byte header)
	li	s9, 0				# byte offset
	li	s10, 0				# bit accumulator
	li	s11, 0				# bits in accumulator

	# 3a: write codebook to bitstream
	mv	a0, s4				# code_lengths
	jal	_cz_write_codebook

	# 3b: write Huffman-encoded match_array with interleaved extra bits
_cz_write_sym_loop:
	slli	t5, s5, 2
	add	t5, s3, t5
	lw	t5, 0(t5)			# t5 = match_array entry

	# extract symbol
	andi	t6, t5, 0x3FF			# t6 = symbol (low 10 bits)

	# look up Huffman code
	slli	t1, t6, 2			# symbol * CZ_CL_SIZE
	add	t1, s4, t1
	lhu	a0, CZ_CL_CODE(t1)		# code
	lhu	a1, CZ_CL_LEN(t1)		# length
	jal	_cz_bsw				# write Huffman code (clobbers t0)
	# t5, t6 survive

	# check for TERM
	li	t0, CZ_SYMBOL_TERM
	beq	t6, t0, _cz_write_sym_done

	# check for match (symbol >= CZ_MATCH_OFFSET)
	li	t0, CZ_MATCH_OFFSET
	bltu	t6, t0, _cz_write_sym_next	# literal, no extra bits

	# match: write interleaved extra bits
	srli	a0, t5, 10			# combined_extra (upper 22 bits of entry)
	addi	t1, t6, -CZ_MATCH_OFFSET	# match_code
	srli	t2, t1, CZ_LEN_SHIFT		# leb
	andi	t3, t1, CZ_DIST_MASK		# deb
	add	a1, t2, t3			# extra_count = leb + deb
	beqz	a1, _cz_write_sym_next		# no extra bits
	jal	_cz_bsw				# write extra bits

_cz_write_sym_next:
	addi	s5, s5, 1
	j	_cz_write_sym_loop

_cz_write_sym_done:
	# flush remaining bits
	jal	_cz_bsw_flush

	# write decompressed_size into 4-byte header (LE)
	addi	t0, s8, -4			# header ptr = output base - 4
	sb	s1, 0(t0)
	srli	t1, s1, 8
	sb	t1, 1(t0)
	srli	t1, s1, 16
	sb	t1, 2(t0)
	srli	t1, s1, 24
	sb	t1, 3(t0)

	# compressed size = 4 (header) + s9 (data bytes)
	addi	a0, s9, 4

	# cleanup stack (code_lengths + max + frequencies + hash_table)
	addi	sp, sp, 1544			# code_lengths
	addi	sp, sp, 4			# max
	addi	sp, sp, 1544			# frequencies
	li	t0, CZ_HASH_TABLE_SIZE * 2
	add	sp, sp, t0			# hash_table
	j	_cz_ret

_cz_err:
	li	a0, -1
_cz_ret:
	RETURN


# ── heap operations ──

# _cz_heap_insert: insert node into min-heap
# a0 = heap_size_ptr, a1 = heap_ptrs, a2 = node_ptr
_cz_heap_insert:
	lw	t0, 0(a0)			# size
	slli	t1, t0, 2
	add	t1, a1, t1
	sw	a2, 0(t1)			# heap[size] = node
	addi	t0, t0, 1
	sw	t0, 0(a0)			# size++

	# bubble up
	addi	t0, t0, -1			# i = size - 1
30:	beqz	t0, 31f
	addi	t1, t0, -1
	srli	t1, t1, 1			# parent = (i-1)/2
	slli	t2, t0, 2
	add	t2, a1, t2
	lw	t3, 0(t2)			# heap[i]
	slli	t4, t1, 2
	add	t4, a1, t4
	lw	t5, 0(t4)			# heap[parent]
	lw	t3, 4(t3)			# heap[i].freq
	lw	t5, 4(t5)			# heap[parent].freq
	bgeu	t3, t5, 31f			# if heap[i].freq >= heap[parent].freq, done

	# swap
	slli	t2, t0, 2
	add	t2, a1, t2
	slli	t4, t1, 2
	add	t4, a1, t4
	lw	t3, 0(t2)
	lw	t5, 0(t4)
	sw	t5, 0(t2)
	sw	t3, 0(t4)
	mv	t0, t1				# i = parent
	j	30b
31:	ret


# _cz_heap_extract_min: remove and return minimum node
# a0 = heap_size_ptr, a1 = heap_ptrs
# Returns: a0 = node_ptr
_cz_heap_extract_min:
	lw	t0, 0(a0)			# size
	lw	t1, 0(a1)			# min = heap[0]
	addi	sp, sp, -4
	sw	t1, 0(sp)			# save min on stack (t6 gets clobbered)
	addi	t0, t0, -1			# new size
	sw	t0, 0(a0)			# store new size

	beqz	t0, _cz_sift_done		# empty heap, nothing to sift

	# move last element to root
	slli	t1, t0, 2
	add	t1, a1, t1
	lw	t2, 0(t1)
	sw	t2, 0(a1)			# heap[0] = last

	# sift down from index 0
	li	t1, 0				# idx
_cz_sift_down:
	slli	t2, t1, 1
	addi	t2, t2, 1			# left = 2*idx + 1
	addi	t3, t2, 1			# right = 2*idx + 2
	mv	t4, t1				# smallest = idx

	# if left < size && heap[left].freq < heap[smallest].freq
	bge	t2, t0, _cz_sift_check_right
	slli	t5, t2, 2
	add	t5, a1, t5
	lw	t5, 0(t5)			# heap[left]
	lw	t5, 4(t5)			# heap[left].freq
	slli	t6, t4, 2
	add	t6, a1, t6
	lw	t6, 0(t6)			# heap[smallest]
	lw	t6, 4(t6)			# heap[smallest].freq
	bgeu	t5, t6, _cz_sift_check_right
	mv	t4, t2				# smallest = left

_cz_sift_check_right:
	bge	t3, t0, _cz_sift_maybe_swap
	slli	t5, t3, 2
	add	t5, a1, t5
	lw	t5, 0(t5)			# heap[right]
	lw	t5, 4(t5)			# heap[right].freq
	slli	t6, t4, 2
	add	t6, a1, t6
	lw	t6, 0(t6)			# heap[smallest]
	lw	t6, 4(t6)			# heap[smallest].freq
	bgeu	t5, t6, _cz_sift_maybe_swap
	mv	t4, t3				# smallest = right

_cz_sift_maybe_swap:
	beq	t4, t1, _cz_sift_done		# if smallest == idx, done

	# swap heap[idx] and heap[smallest]
	slli	t5, t1, 2
	add	t5, a1, t5
	slli	t6, t4, 2
	add	t6, a1, t6
	lw	t2, 0(t5)
	lw	t3, 0(t6)
	sw	t3, 0(t5)
	sw	t2, 0(t6)

	mv	t1, t4				# idx = smallest
	j	_cz_sift_down

_cz_sift_done:
	lw	a0, 0(sp)			# return saved min from stack
	addi	sp, sp, 4
	ret


# _cz_compute_lengths: DFS to assign code lengths
# a0 = node_ptr, a1 = code_lengths, a2 = depth
_cz_compute_lengths:
	beqz	a0, 32f				# null check

	lw	t0, 8(a0)			# left
	lw	t1, 12(a0)			# right

	# leaf if both children are null
	or	t2, t0, t1
	bnez	t2, 33f

	# leaf: code_lengths[symbol].length = depth
	lhu	t0, 0(a0)			# symbol
	slli	t0, t0, 2			# * CZ_CL_SIZE
	add	t0, a1, t0
	sh	a2, CZ_CL_LEN(t0)
	j	32f

33:	# internal node: recurse left and right
	addi	sp, sp, -16
	sw	ra, 0(sp)
	sw	a0, 4(sp)
	sw	a1, 8(sp)
	sw	a2, 12(sp)

	lw	a0, 8(a0)			# left child
	addi	a2, a2, 1
	jal	_cz_compute_lengths

	lw	a0, 4(sp)			# restore node
	lw	a1, 8(sp)
	lw	a2, 12(sp)
	lw	a0, 12(a0)			# right child
	addi	a2, a2, 1
	jal	_cz_compute_lengths

	lw	ra, 0(sp)
	addi	sp, sp, 16

32:	ret


# ══════════════════════════════════════════════════════════════════════════════
# calculate_lengths: build Huffman tree and compute code lengths
# a0 = frequencies (u32[SYMBOL_COUNT])
# a1 = code_lengths (CodeLength[SYMBOL_COUNT])
# a2 = count
# a3 = max_length
#
# Uses a min-heap to build the Huffman tree, then traverses to get lengths,
# then limits lengths to max_length.
# ══════════════════════════════════════════════════════════════════════════════
_cz_calculate_lengths:
	SETUP	s0, s1, s2, s3, s4, s5, s6

	mv	s0, a0				# frequencies
	mv	s1, a1				# code_lengths
	mv	s2, a2				# count
	mv	s3, a3				# max_length

	# Huffman node: symbol(2) + pad(2) + freq(4) + left(4) + right(4) = 16 bytes
	# Max nodes: count * 2 + 1 = 771
	# Heap: array of pointers, max 771 entries = 3084 bytes
	# Nodes: 771 * 16 = 12336 bytes
	# Total: ~16 KB on stack

	li	t0, 771 * 16			# nodes
	li	t1, 771 * 4			# heap pointers
	add	t0, t0, t1
	addi	t0, t0, 4			# heap size counter
	sub	sp, sp, t0
	mv	s4, sp				# s4 = heap_size (1 word)
	addi	s5, sp, 4			# s5 = heap_ptrs (771 words)
	li	t1, 771 * 4
	add	s6, s5, t1			# s6 = nodes base

	sw	zero, 0(s4)			# heap.size = 0

	# Build tree: insert all symbols with freq > 0
	li	t0, 0				# i
	mv	t1, s6				# next_node
23:	bge	t0, s2, 24f
	slli	t2, t0, 2
	add	t2, s0, t2
	lw	t3, 0(t2)			# freq
	beqz	t3, 25f

	# init node: symbol=i, freq=t3, left=0, right=0
	sh	t0, 0(t1)			# symbol
	sw	t3, 4(t1)			# freq
	sw	zero, 8(t1)			# left
	sw	zero, 12(t1)			# right

	# insert into heap
	mv	a0, s4				# heap
	mv	a1, s5				# heap_ptrs
	mv	a2, t1				# node
	# save t0, t1 across call
	addi	sp, sp, -8
	sw	t0, 0(sp)
	sw	t1, 4(sp)
	jal	_cz_heap_insert
	lw	t0, 0(sp)
	lw	t1, 4(sp)
	addi	sp, sp, 8

	addi	t1, t1, 16			# next node

25:	addi	t0, t0, 1
	j	23b

24:	# save next_node pointer
	addi	sp, sp, -4
	sw	t1, 0(sp)

	# Handle single-symbol case
	lw	t0, 0(s4)			# heap.size
	li	t1, 1
	bne	t0, t1, 26f
	# single symbol: extract and assign length 1
	mv	a0, s4
	mv	a1, s5
	jal	_cz_heap_extract_min
	# a0 = node ptr
	lhu	t0, 0(a0)			# symbol
	slli	t0, t0, 2			# * CZ_CL_SIZE
	add	t0, s1, t0
	li	t1, 1
	sh	t1, CZ_CL_LEN(t0)		# length = 1
	j	27f

26:	# Build tree: while heap.size > 1, merge two smallest
	# Use a fixed stack frame for the merge loop: [next_node, left, right]
	# 0(sp) is already next_node from the save above
28:	lw	t0, 0(s4)			# heap.size
	li	t1, 1
	ble	t0, t1, 29f

	# extract left
	mv	a0, s4
	mv	a1, s5
	jal	_cz_heap_extract_min
	# save left on stack
	addi	sp, sp, -4
	sw	a0, 0(sp)

	# extract right
	mv	a0, s4
	mv	a1, s5
	jal	_cz_heap_extract_min
	mv	t5, a0				# right

	lw	t4, 0(sp)			# left
	addi	sp, sp, 4
	lw	t1, 0(sp)			# next_node

	# create parent node at next_node
	li	t0, 0xFFFF
	sh	t0, 0(t1)			# symbol = 0xFFFF (internal)
	lw	t2, 4(t4)			# left.freq
	lw	t3, 4(t5)			# right.freq
	add	t2, t2, t3
	sw	t2, 4(t1)			# freq
	sw	t4, 8(t1)			# left
	sw	t5, 12(t1)			# right

	# advance next_node and save
	addi	t0, t1, 16
	sw	t0, 0(sp)			# update next_node on stack

	# insert parent into heap
	mv	a0, s4
	mv	a1, s5
	mv	a2, t1
	jal	_cz_heap_insert

	j	28b

29:	# extract root and compute lengths via DFS
	mv	a0, s4
	mv	a1, s5
	jal	_cz_heap_extract_min
	# a0 = root node
	mv	a1, s1				# code_lengths
	li	a2, 0				# depth = 0
	jal	_cz_compute_lengths

	# limit lengths
	mv	a0, s0				# frequencies
	mv	a1, s1				# code_lengths
	mv	a2, s2				# count
	mv	a3, s3				# max_length
	jal	_cz_limit_lengths

27:	# cleanup
	lw	t0, 0(sp)			# next_node (or junk if single)
	addi	sp, sp, 4			# pop next_node save
	li	t0, 771 * 16 + 771 * 4 + 4
	add	sp, sp, t0
	RETURN


# _cz_limit_lengths: limit code lengths to max_length with Kraft fixup
# a0 = frequencies, a1 = code_lengths, a2 = count, a3 = max_length
#
# Pass 1: clamp lengths > max, track frequency-weighted excess
# Pass 2: redistribute excess by incrementing shorter codes (quality)
# Pass 3: enforce Kraft inequality (correctness)
_cz_limit_lengths:
	SETUP	s0, s1, s2, s3, s4, s5

	mv	s0, a0				# frequencies
	mv	s1, a1				# code_lengths
	mv	s2, a2				# count
	mv	s3, a3				# max_length

	# ── Pass 1: clamp and compute excess ──
	# excess = sum((len - max) * freq) for clamped symbols
	# needed = sum(freq) for clamped symbols
	li	s4, 0				# excess
	li	s5, 0				# needed
	li	t0, 0
_cl_p1:
	bge	t0, s2, _cl_p2
	slli	t1, t0, 2
	add	t2, s1, t1
	lhu	t3, CZ_CL_LEN(t2)		# length
	ble	t3, s3, _cl_p1_next		# <= max, skip

	# excess += (length - max) * freq (multiply by repeated add)
	add	t4, s0, t1
	lw	t4, 0(t4)			# freq
	sub	t5, t3, s3			# diff = length - max
_cl_p1_mul:
	beqz	t5, _cl_p1_mulok
	add	s4, s4, t4			# excess += freq
	addi	t5, t5, -1
	j	_cl_p1_mul
_cl_p1_mulok:
	add	s5, s5, t4			# needed += freq

	# clamp
	sh	s3, CZ_CL_LEN(t2)
_cl_p1_next:
	addi	t0, t0, 1
	j	_cl_p1

	# ── Pass 2: redistribute excess ──
	# Increment shorter codes of low-freq symbols to compensate
_cl_p2:
	beqz	s4, _cl_kraft			# no excess, skip
	beqz	s5, _cl_kraft
_cl_p2_outer:
	beqz	s4, _cl_kraft
	beqz	s5, _cl_kraft
	li	t0, 0
_cl_p2_scan:
	bge	t0, s2, _cl_kraft		# one full pass done
	beqz	s4, _cl_kraft			# excess consumed
	slli	t1, t0, 2
	add	t2, s1, t1
	lhu	t3, CZ_CL_LEN(t2)		# length
	beqz	t3, _cl_p2_next			# skip unused
	bge	t3, s3, _cl_p2_next		# skip length >= max
	add	t4, s0, t1
	lw	t4, 0(t4)			# freq
	beqz	t4, _cl_p2_next			# skip zero freq

	# delta = min(excess, freq)
	mv	t5, t4
	bleu	s4, t4, _cl_p2_use_exc
	j	_cl_p2_apply
_cl_p2_use_exc:
	mv	t5, s4				# delta = excess
_cl_p2_apply:
	addi	t3, t3, 1
	sh	t3, CZ_CL_LEN(t2)		# length++
	sub	s4, s4, t5			# excess -= delta
	sub	s5, s5, t5			# needed -= delta

_cl_p2_next:
	addi	t0, t0, 1
	j	_cl_p2_scan

	# ── Pass 3: enforce Kraft inequality ──
_cl_kraft:
	# Compute Kraft sum = sum(2^(max - len)) for all symbols with len > 0
	li	s4, 0				# sum
	li	t0, 0
_cl_sum:
	bge	t0, s2, _cl_fix
	slli	t1, t0, 2
	add	t1, s1, t1
	lhu	t2, CZ_CL_LEN(t1)
	beqz	t2, _cl_sum_next
	sub	t3, s3, t2			# max - len
	li	t4, 1
	sll	t4, t4, t3			# 2^(max - len)
	add	s4, s4, t4
_cl_sum_next:
	addi	t0, t0, 1
	j	_cl_sum

_cl_fix:
	# target = 2^max_length
	li	s5, 1
	sll	s5, s5, s3			# s5 = 2^max

	# While sum > target: find min-freq symbol with 0 < len < max, increment it
_cl_fix_loop:
	ble	s4, s5, _cl_done

	# Find symbol with minimum frequency, length in (1, max)
	li	t6, -1				# best_idx = none
	li	t5, -1				# min_freq = 0xFFFFFFFF
	li	t0, 0
_cl_find:
	bge	t0, s2, _cl_apply
	slli	t1, t0, 2
	add	t2, s1, t1
	lhu	t3, CZ_CL_LEN(t2)		# length
	beqz	t3, _cl_fnext			# skip length 0
	bge	t3, s3, _cl_fnext		# skip length >= max
	add	t2, s0, t1
	lw	t4, 0(t2)			# frequency
	bgeu	t4, t5, _cl_fnext		# freq >= min, skip
	mv	t5, t4				# new min_freq
	mv	t6, t0				# new best_idx
_cl_fnext:
	addi	t0, t0, 1
	j	_cl_find

_cl_apply:
	bltz	t6, _cl_done			# no candidate, bail

	# Increment best symbol's length
	slli	t0, t6, 2
	add	t0, s1, t0
	lhu	t1, CZ_CL_LEN(t0)		# old_len
	addi	t2, t1, 1			# new_len
	sh	t2, CZ_CL_LEN(t0)

	# Update sum: subtract old contribution, add new
	sub	t3, s3, t1			# max - old_len
	li	t4, 1
	sll	t4, t4, t3
	sub	s4, s4, t4			# sum -= 2^(max - old_len)

	sub	t3, s3, t2			# max - new_len
	li	t4, 1
	sll	t4, t4, t3
	add	s4, s4, t4			# sum += 2^(max - new_len)

	j	_cl_fix_loop

_cl_done:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# _cz_rle_encode: RLE-encode code lengths into book symbol sequence
# a0 = code_lengths (CodeLength[count])
# a1 = count
# a2 = output buffer (u32 pairs: low u16 = symbol, high u16 = extra value)
# Returns: a0 = number of RLE entries
# ══════════════════════════════════════════════════════════════════════════════
_cz_rle_encode:
	SETUP	s0, s1, s2, s3, s4, s5, s6

	mv	s0, a0				# code_lengths
	mv	s1, a1				# count
	mv	s2, a2				# output
	li	s3, 0				# input index (i)
	li	s4, 0				# output index (j)
	li	s5, 0				# prev non-zero value

_rle_loop:
	bge	s3, s1, _rle_done

	# get current length
	slli	t0, s3, 2
	add	t0, s0, t0
	lhu	t1, CZ_CL_LEN(t0)		# t1 = current length

	beqz	t1, _rle_zeros

	# ── non-zero value ──
	# emit the literal value
	slli	t0, s4, 2
	add	t0, s2, t0
	sh	t1, 0(t0)			# symbol = length value
	sh	zero, 2(t0)			# extra = 0
	addi	s4, s4, 1
	mv	s5, t1				# prev = current
	addi	s3, s3, 1

	# count consecutive same values after this one
	li	s6, 0				# run = 0
_rle_count_same:
	add	t0, s3, s6
	bge	t0, s1, _rle_emit_same
	slli	t0, t0, 2
	add	t0, s0, t0
	lhu	t2, CZ_CL_LEN(t0)
	bne	t2, s5, _rle_emit_same
	addi	s6, s6, 1
	j	_rle_count_same

_rle_emit_same:
	# s6 = run of same values to encode
_rle_emit_same_loop:
	li	t0, 3
	blt	s6, t0, _rle_emit_same_singles

	# REPEAT_VALUE: 3-6 repeats
	li	t0, 6
	ble	s6, t0, _rle_esm_use_run
	li	t1, 6				# cap at 6
	j	_rle_esm_emit
_rle_esm_use_run:
	mv	t1, s6
_rle_esm_emit:
	slli	t0, s4, 2
	add	t0, s2, t0
	li	t2, CZ_REPEAT_VALUE_INDEX
	sh	t2, 0(t0)			# symbol = REPEAT_VALUE
	addi	t3, t1, -3
	sh	t3, 2(t0)			# extra = count - 3
	addi	s4, s4, 1
	sub	s6, s6, t1
	add	s3, s3, t1
	j	_rle_emit_same_loop

_rle_emit_same_singles:
	beqz	s6, _rle_loop
	slli	t0, s4, 2
	add	t0, s2, t0
	sh	s5, 0(t0)			# symbol = prev value
	sh	zero, 2(t0)			# extra = 0
	addi	s4, s4, 1
	addi	s6, s6, -1
	addi	s3, s3, 1
	j	_rle_emit_same_singles

_rle_zeros:
	# count consecutive zeros
	li	s6, 0
_rle_count_zeros:
	add	t0, s3, s6
	bge	t0, s1, _rle_emit_zeros
	slli	t0, t0, 2
	add	t0, s0, t0
	lhu	t2, CZ_CL_LEN(t0)
	bnez	t2, _rle_emit_zeros
	addi	s6, s6, 1
	j	_rle_count_zeros

_rle_emit_zeros:
	# s6 = run of zeros to encode
_rle_emit_zeros_loop:
	beqz	s6, _rle_loop

	li	t0, 11
	bge	s6, t0, _rle_ez_long

	li	t0, 3
	bge	s6, t0, _rle_ez_short

	# individual zero literals
	slli	t0, s4, 2
	add	t0, s2, t0
	sh	zero, 0(t0)			# symbol = 0
	sh	zero, 2(t0)			# extra = 0
	addi	s4, s4, 1
	addi	s6, s6, -1
	addi	s3, s3, 1
	j	_rle_emit_zeros_loop

_rle_ez_long:
	# REPEAT_ZERO_LONG: 11-138 zeros
	li	t0, 138
	ble	s6, t0, _rle_ezl_use_run
	li	t1, 138
	j	_rle_ezl_emit
_rle_ezl_use_run:
	mv	t1, s6
_rle_ezl_emit:
	slli	t0, s4, 2
	add	t0, s2, t0
	li	t2, CZ_REPEAT_ZERO_LONG
	sh	t2, 0(t0)			# symbol = REPEAT_ZERO_LONG
	addi	t3, t1, -11
	sh	t3, 2(t0)			# extra = count - 11
	addi	s4, s4, 1
	sub	s6, s6, t1
	add	s3, s3, t1
	j	_rle_emit_zeros_loop

_rle_ez_short:
	# REPEAT_ZERO_SHORT: 3-10 zeros
	li	t0, 10
	ble	s6, t0, _rle_ezs_use_run
	li	t1, 10
	j	_rle_ezs_emit
_rle_ezs_use_run:
	mv	t1, s6
_rle_ezs_emit:
	slli	t0, s4, 2
	add	t0, s2, t0
	li	t2, CZ_REPEAT_ZERO_SHORT
	sh	t2, 0(t0)			# symbol = REPEAT_ZERO_SHORT
	addi	t3, t1, -3
	sh	t3, 2(t0)			# extra = count - 3
	addi	s4, s4, 1
	sub	s6, s6, t1
	add	s3, s3, t1
	j	_rle_emit_zeros_loop

_rle_done:
	mv	a0, s4				# return entry count
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# _cz_write_codebook: serialize codebook to bitstream
# a0 = code_lengths (CodeLength[CZ_SYMBOL_COUNT])
# Bitstream state in s8-s11 (NOT saved — modifications persist to caller)
# ══════════════════════════════════════════════════════════════════════════════
_cz_write_codebook:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7

	mv	s0, a0				# main code_lengths

	# Allocate RLE buffer: CZ_SYMBOL_COUNT * 4 = 1540 bytes
	addi	sp, sp, -1540
	mv	s1, sp				# s1 = rle_buf

	# RLE encode the code lengths
	mv	a0, s0				# code_lengths
	li	a1, CZ_SYMBOL_COUNT		# 385
	mv	a2, s1				# output buf
	jal	_cz_rle_encode
	mv	s2, a0				# s2 = rle_count

	# Count book symbol frequencies (15 symbols)
	addi	sp, sp, -60			# 15 × 4
	mv	s3, sp				# s3 = book_freqs

	# zero book_freqs
	li	t0, 15
	mv	t1, s3
_wcb_zf:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _wcb_zf

	# count
	li	t0, 0
	mv	t1, s1
_wcb_cf:
	bge	t0, s2, _wcb_cf_done
	lhu	t2, 0(t1)			# rle symbol
	slli	t3, t2, 2
	add	t3, s3, t3
	lw	t4, 0(t3)
	addi	t4, t4, 1
	sw	t4, 0(t3)
	addi	t1, t1, 4
	addi	t0, t0, 1
	j	_wcb_cf
_wcb_cf_done:

	# Allocate book CodeLengths: 15 × CZ_CL_SIZE = 60 bytes
	addi	sp, sp, -60
	mv	s4, sp				# s4 = book_cl

	# zero book_cl
	li	t0, 15
	mv	t1, s4
_wcb_zcl:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _wcb_zcl

	# build book Huffman codes
	mv	a0, s3				# book_freqs
	mv	a1, s4				# book_cl
	li	a2, CZ_MAX_BOOK_CODES		# 15
	li	a3, CZ_MAX_BOOK_CODE_LENGTH	# 7
	jal	_cz_calculate_lengths

	mv	a0, s4
	li	a1, CZ_MAX_BOOK_CODES
	jal	_cz_calculate_codes

	# Write 15 × 3-bit book code lengths to bitstream
	li	s5, 0
_wcb_wbl:
	li	t0, CZ_MAX_BOOK_CODES
	bge	s5, t0, _wcb_wbl_done
	slli	t0, s5, 2
	add	t0, s4, t0
	lhu	a0, CZ_CL_LEN(t0)		# code length value
	li	a1, 3				# 3 bits per entry
	jal	_cz_bsw
	addi	s5, s5, 1
	j	_wcb_wbl
_wcb_wbl_done:

	# Write RLE symbols using book Huffman codes
	li	s5, 0				# rle index
	mv	s6, s1				# rle_buf ptr
_wcb_ws:
	bge	s5, s2, _wcb_ws_done
	lhu	t5, 0(s6)			# rle symbol
	lhu	t6, 2(s6)			# rle extra value

	# look up book Huffman code for this symbol
	slli	t0, t5, 2
	add	t0, s4, t0
	lhu	a0, CZ_CL_CODE(t0)		# book code
	lhu	a1, CZ_CL_LEN(t0)		# book code length
	jal	_cz_bsw				# write book code (clobbers t0; t5,t6 survive)

	# write extra bits if RLE symbol requires them
	li	t0, CZ_REPEAT_VALUE_INDEX	# 12
	beq	t5, t0, _wcb_rep_val
	li	t0, CZ_REPEAT_ZERO_SHORT	# 14
	beq	t5, t0, _wcb_rep_zs
	li	t0, CZ_REPEAT_ZERO_LONG	# 13
	beq	t5, t0, _wcb_rep_zl
	j	_wcb_ws_next			# literal, no extra

_wcb_rep_val:
	mv	a0, t6				# extra value
	li	a1, 2				# 2 bits
	jal	_cz_bsw
	j	_wcb_ws_next

_wcb_rep_zs:
	mv	a0, t6
	li	a1, 3				# 3 bits
	jal	_cz_bsw
	j	_wcb_ws_next

_wcb_rep_zl:
	mv	a0, t6
	li	a1, 7				# 7 bits
	jal	_cz_bsw
	j	_wcb_ws_next

_wcb_ws_next:
	addi	s6, s6, 4
	addi	s5, s5, 1
	j	_wcb_ws
_wcb_ws_done:

	# cleanup
	addi	sp, sp, 60			# book_cl
	addi	sp, sp, 60			# book_freqs
	addi	sp, sp, 1540			# rle_buf

	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# decompress_block: decompress data
# a0 = input_ptr (compressed data)
# a1 = input_len
# a2 = output_ptr
# a3 = output_capacity
# Returns: a0 = decompressed size, or -1 on error
# ══════════════════════════════════════════════════════════════════════════════
decompress_block:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7

	mv	s0, a2				# output_ptr
	mv	s1, a3				# output_capacity
	li	s2, 0				# output_pos

	# Minimum input length check
	li	t0, 5				# at least header + 1 byte of data
	blt	a1, t0, _dcz_error_imm

	# Read decompressed_size (4 bytes LE)
	lbu	t0, 0(a0)
	lbu	t1, 1(a0)
	slli	t1, t1, 8
	or	t0, t0, t1
	lbu	t1, 2(a0)
	slli	t1, t1, 16
	or	t0, t0, t1
	lbu	t1, 3(a0)
	slli	t1, t1, 24
	# s3 = input byte limit for bitstream bounds checking
	# (input_len minus the 4-byte header, since bitstream starts at input+4)
	addi	s3, a1, -4			# bitstream byte limit

	# Init bitstream at input + 4
	addi	s8, a0, 4
	li	s9, 0
	li	s10, 0
	li	s11, 0

	# ── Read book code lengths (15 × 3 bits) ──
	addi	sp, sp, -60			# book_cl: 15 × CZ_CL_SIZE
	mv	s4, sp

	# zero book_cl
	li	t0, 15
	mv	t1, s4
_dcz_zbcl:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _dcz_zbcl

	li	s5, 0				# i = 0
_dcz_rbl:
	li	t0, CZ_MAX_BOOK_CODES
	bge	s5, t0, _dcz_rbl_done
	li	a0, 3
	jal	_cz_bsr				# read 3 bits → a0
	slli	t0, s5, 2
	add	t0, s4, t0
	sh	a0, CZ_CL_LEN(t0)
	addi	s5, s5, 1
	j	_dcz_rbl
_dcz_rbl_done:

	# Validate: at least one book code length must be non-zero
	li	t0, 0
	mv	t1, s4
	li	t2, CZ_MAX_BOOK_CODES
_dcz_vbook:
	beqz	t2, _dcz_vbook_done
	lhu	t3, CZ_CL_LEN(t1)
	add	t0, t0, t3			# accumulate lengths
	addi	t1, t1, CZ_CL_SIZE
	addi	t2, t2, -1
	j	_dcz_vbook
_dcz_vbook_done:
	beqz	t0, _dcz_error_bcl		# all zero = no valid book codes

	# calculate book codes
	mv	a0, s4
	li	a1, CZ_MAX_BOOK_CODES
	jal	_cz_calculate_codes

	# Build book lookup table: 2^7 = 128 entries × 4 bytes = 512 bytes
	addi	sp, sp, -512
	mv	s5, sp				# s5 = book_lookup

	li	t0, 128
	mv	t1, s5
_dcz_zblt:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _dcz_zblt

	mv	a0, s4
	li	a1, CZ_MAX_BOOK_CODES
	mv	a2, s5
	li	a3, CZ_MAX_BOOK_CODE_LENGTH
	jal	_cz_build_lookup_table

	# ── Read main code lengths using book codes + RLE ──
	addi	sp, sp, -1540			# main_cl: CZ_SYMBOL_COUNT × CZ_CL_SIZE
	mv	s4, sp				# s4 = main_cl (reuse)

	li	t0, 385
	mv	t1, s4
_dcz_zmcl:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _dcz_zmcl

	li	s6, 0				# code_length index
	li	s7, 0				# prev non-zero value

_dcz_rcl_loop:
	li	t0, CZ_SYMBOL_COUNT
	bge	s6, t0, _dcz_rcl_done

	# ensure 7 bits and peek
	li	a0, CZ_MAX_BOOK_CODE_LENGTH
	jal	_cz_bs_ensure
	andi	t0, s10, 0x7F			# peek 7 bits

	# look up in book table
	slli	t0, t0, 2
	add	t0, s5, t0
	lhu	t5, CZ_HL_SYMBOL(t0)		# book symbol
	lbu	t6, CZ_HL_LEN(t0)		# book code length
	beqz	t6, _dcz_error_book		# invalid code (garbled table)

	# consume bits
	srl	s10, s10, t6
	sub	s11, s11, t6

	# dispatch on book symbol type
	li	t0, CZ_REPEAT_VALUE_INDEX	# 12
	beq	t5, t0, _dcz_rep_val
	li	t0, CZ_REPEAT_ZERO_SHORT	# 14
	beq	t5, t0, _dcz_rep_zs
	li	t0, CZ_REPEAT_ZERO_LONG	# 13
	beq	t5, t0, _dcz_rep_zl

	# literal code length (0-11)
	slli	t0, s6, 2
	add	t0, s4, t0
	sh	t5, CZ_CL_LEN(t0)
	beqz	t5, _dcz_cl_next
	mv	s7, t5				# update prev if non-zero
_dcz_cl_next:
	addi	s6, s6, 1
	j	_dcz_rcl_loop

_dcz_rep_val:
	# repeat previous value, 2 extra bits → count = extra + 3
	li	a0, 2
	jal	_cz_bsr
	addi	t3, a0, 3			# count
_dcz_rv_loop:
	beqz	t3, _dcz_rcl_loop
	li	t0, CZ_SYMBOL_COUNT
	bge	s6, t0, _dcz_error_book		# bounds check
	slli	t0, s6, 2
	add	t0, s4, t0
	sh	s7, CZ_CL_LEN(t0)
	addi	s6, s6, 1
	addi	t3, t3, -1
	j	_dcz_rv_loop

_dcz_rep_zs:
	# repeat zero short, 3 extra bits → count = extra + 3
	li	a0, 3
	jal	_cz_bsr
	addi	t3, a0, 3
_dcz_rzs_loop:
	beqz	t3, _dcz_rcl_loop
	li	t0, CZ_SYMBOL_COUNT
	bge	s6, t0, _dcz_error_book		# bounds check
	slli	t0, s6, 2
	add	t0, s4, t0
	sh	zero, CZ_CL_LEN(t0)
	addi	s6, s6, 1
	addi	t3, t3, -1
	j	_dcz_rzs_loop

_dcz_rep_zl:
	# repeat zero long, 7 extra bits → count = extra + 11
	li	a0, 7
	jal	_cz_bsr
	addi	t3, a0, 11
_dcz_rzl_loop:
	beqz	t3, _dcz_rcl_loop
	li	t0, CZ_SYMBOL_COUNT
	bge	s6, t0, _dcz_error_book		# bounds check
	slli	t0, s6, 2
	add	t0, s4, t0
	sh	zero, CZ_CL_LEN(t0)
	addi	s6, s6, 1
	addi	t3, t3, -1
	j	_dcz_rzl_loop

_dcz_rcl_done:
	# Validate: at least one main code length must be non-zero
	li	t0, 0
	mv	t1, s4
	li	t2, CZ_SYMBOL_COUNT
_dcz_vmain:
	beqz	t2, _dcz_vmain_done
	lhu	t3, CZ_CL_LEN(t1)
	add	t0, t0, t3
	addi	t1, t1, CZ_CL_SIZE
	addi	t2, t2, -1
	j	_dcz_vmain
_dcz_vmain_done:
	beqz	t0, _dcz_error_book		# all zero = no valid main codes

	# calculate main codes
	mv	a0, s4
	li	a1, CZ_SYMBOL_COUNT
	jal	_cz_calculate_codes

	# Build main lookup table: 2^11 = 2048 entries × 4 bytes = 8192 bytes
	li	t0, 8192
	sub	sp, sp, t0
	mv	s5, sp				# s5 = main_lookup (reuse)

	li	t0, 2048
	mv	t1, s5
_dcz_zmlt:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _dcz_zmlt

	mv	a0, s4
	li	a1, CZ_SYMBOL_COUNT
	mv	a2, s5
	li	a3, CZ_MAX_CODE_LENGTH
	jal	_cz_build_lookup_table

	# ── Main decode loop ──
	# s3 = decompressed_size from header (used as iteration limit for safety)
	li	s6, 0				# iteration counter
_dcz_decode_loop:
	bge	s6, s1, _dcz_error		# more iterations than capacity = invalid
	addi	s6, s6, 1
	# ensure enough bits for lookup
	li	a0, CZ_MAX_CODE_LENGTH		# 11
	jal	_cz_bs_ensure

	# peek 11 bits
	li	t0, (1 << CZ_MAX_CODE_LENGTH) - 1	# 0x7FF
	and	t0, s10, t0

	# look up in main table
	slli	t0, t0, 2
	add	t0, s5, t0
	lhu	t5, CZ_HL_SYMBOL(t0)		# symbol
	lbu	t6, CZ_HL_LEN(t0)		# code length
	beqz	t6, _dcz_error			# invalid code (garbled table)

	# consume bits
	srl	s10, s10, t6
	sub	s11, s11, t6

	# check for TERM
	li	t0, CZ_SYMBOL_TERM
	beq	t5, t0, _dcz_done

	# check for match
	li	t0, CZ_MATCH_OFFSET
	bgeu	t5, t0, _dcz_match

	# ── literal ──
	bge	s2, s1, _dcz_error		# capacity check
	add	t0, s0, s2
	sb	t5, 0(t0)
	addi	s2, s2, 1
	j	_dcz_decode_loop

_dcz_match:
	# decode match
	addi	t5, t5, -CZ_MATCH_OFFSET	# match_code
	srli	t1, t5, CZ_LEN_SHIFT		# leb
	andi	t2, t5, CZ_DIST_MASK		# deb
	add	t3, t1, t2			# extra_count = leb + deb

	# read extra bits (t1, t2 survive _cz_bsr which only clobbers t0, t4)
	li	a0, 0				# combined_extra default
	beqz	t3, _dcz_match_decode
	mv	a0, t3
	jal	_cz_bsr				# a0 = combined_extra

_dcz_match_decode:
	# a0 = combined_extra, t1 = leb, t2 = deb

	# len_extra = combined_extra & ((1 << leb) - 1)
	li	t3, 1
	sll	t3, t3, t1
	addi	t3, t3, -1			# mask = (1 << leb) - 1
	and	t4, a0, t3			# len_extra

	# dist_extra = combined_extra >> leb
	srl	t5, a0, t1			# dist_extra

	# len = len_extra + len_base + 4 = len_extra + ((1<<leb)-1) + 4 = len_extra + t3 + 4
	add	t3, t4, t3			# len_extra + len_base
	addi	t3, t3, 4			# match_len

	# dist = dist_extra + dist_base = dist_extra + (1 << deb)
	li	t6, 1
	sll	t6, t6, t2			# dist_base
	add	t6, t5, t6			# match_dist

	# copy match_len bytes from (output_pos - match_dist)
	beqz	t6, _dcz_error			# dist == 0 = invalid
	bgtu	t6, s2, _dcz_error		# dist > output_pos = invalid
	sub	t4, s2, t6			# src_offset

_dcz_copy:
	beqz	t3, _dcz_decode_loop
	bge	s2, s1, _dcz_error		# capacity check
	add	t0, s0, t4			# src ptr
	lbu	t0, 0(t0)
	add	t1, s0, s2			# dst ptr
	sb	t0, 0(t1)
	addi	t4, t4, 1
	addi	s2, s2, 1
	addi	t3, t3, -1
	j	_dcz_copy

_dcz_done:
	mv	a0, s2				# return decompressed size
	j	_dcz_cleanup

_dcz_error_bcl:
	# Error after only book_cl allocated
	li	a0, -1
	addi	sp, sp, 60			# book_cl
	j	_dcz_cleanup_ret

_dcz_error_blt:
	# Error after book_cl + book_lookup allocated
	li	a0, -1
	addi	sp, sp, 512			# book_lookup
	addi	sp, sp, 60			# book_cl
	j	_dcz_cleanup_ret

_dcz_error_book:
	# Error after book_cl + book_lookup + main_cl allocated
	li	a0, -1
	addi	sp, sp, 1540			# main_cl
	addi	sp, sp, 512			# book_lookup
	addi	sp, sp, 60			# book_cl
	j	_dcz_cleanup_ret

_dcz_error:
	li	a0, -1

_dcz_cleanup:
	li	t0, 8192
	add	sp, sp, t0			# main_lookup
	addi	sp, sp, 1540			# main_cl
	addi	sp, sp, 512			# book_lookup
	addi	sp, sp, 60			# book_cl
	j	_dcz_cleanup_ret

_dcz_error_imm:
	# Error before any stack allocation — just return -1
	li	a0, -1

_dcz_cleanup_ret:
	RETURN

.endm	# DEFINE_COMPRESS
