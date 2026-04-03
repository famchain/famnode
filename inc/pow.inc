# pow.inc — Bible-based memory-hard Proof of Work for RISC-V 32-bit
#
# Usage:
#   .include "macros.inc"
#   .include "blake2s.inc"
#   .include "compress.inc"
#   .include "pow.inc"
#   ...
#   DEFINE_POW
#
# Public labels emitted by DEFINE_POW:
#   bible_expand(a0=compressed, a1=compressed_len, a2=table_out, a3=table_size)
#       Builds the PoW lookup table. Copies compressed data, then extends
#       via blake2s chain (16 iterations per 32-byte entry).
#       Returns: a0 = 0 on success, -1 on error
#
#   pow_hash(a0=table_ptr, a1=table_mask, a2=state_ptr, a3=out_ptr)
#       Compute PoW hash from pre-initialized state. 32 lookup rounds → output.
#       state_ptr is 32 bytes (e.g. from blake2s + ARX nonce fold).
#       table_mask = (table_size >> 5) - 1.
#       Returns: nothing (result written to out_ptr)
#
#   pow_hash_full(a0=table_ptr, a1=table_mask, a2=header_ptr, a3=out_ptr)
#       Convenience: blake2s(header) → pow_hash. For single-shot use.
#       header is 128 bytes.
#
#   mine_block(a0=table_ptr, a1=table_mask, a2=header_ptr, a3=target_ptr)
#       Mine: blake2s(header[0:124]) once, then iterate nonces with ARX fold.
#       Additional args on stack: out_ptr at 0(sp), max_iter at 4(sp).
#       Returns: a0 = nonce on success, -1 if max_iter reached
#
# Requires: blake2s, decompress_block from blake2s.inc / compress.inc

.equ	POW_BLAKE2S_ITERS,	16		# blake2s iterations per generated entry
.equ	POW_LOOKUP_ROUNDS,	32		# random lookup rounds per hash
.equ	POW_HEADER_LEN,		128		# header length for hashing
.equ	POW_NONCE_OFFSET,	124		# nonce position in header (last 4 bytes)

.macro DEFINE_POW

# ══════════════════════════════════════════════════════════════════════════════
# bible_expand: build PoW lookup table from compressed bible data
# a0 = compressed_ptr (raw compressed bible data)
# a1 = compressed_len
# a2 = table_out (must be table_size bytes)
# a3 = table_size (must be multiple of 32, e.g. 16*1024*1024)
# Returns: a0 = 0 success, -1 error
# ══════════════════════════════════════════════════════════════════════════════
bible_expand:
	SETUP	s0, s1, s2, s3, s4, s5, s6

	mv	s0, a0				# compressed_ptr
	mv	s1, a1				# compressed_len
	mv	s2, a2				# table_out
	mv	s3, a3				# table_size

	# Validate: table_size must be >= 64
	li	t0, 64
	bltu	s3, t0, _be_err

	# Phase 1: copy compressed data to start of table
	# copy_len = min(compressed_len, table_size)
	mv	t2, s1
	bleu	t2, s3, _be_copy_start
	mv	t2, s3				# truncate to table_size
_be_copy_start:
	mv	t0, s0				# src
	mv	t1, s2				# dst
_be_copy:
	beqz	t2, _be_copy_done
	lbu	t3, 0(t0)
	sb	t3, 0(t1)
	addi	t0, t0, 1
	addi	t1, t1, 1
	addi	t2, t2, -1
	j	_be_copy
_be_copy_done:

	# Pad remaining bytes of the first partial 32-byte block with zeros
	# (align compressed_len up to next 32-byte boundary)
	andi	t0, s1, 31			# compressed_len & 31
	beqz	t0, _be_aligned
	li	t1, 32
	sub	t0, t1, t0			# bytes to pad
	add	t1, s2, s1			# dst = table + compressed_len
_be_pad:
	beqz	t0, _be_aligned
	sb	zero, 0(t1)
	addi	t1, t1, 1
	addi	t0, t0, -1
	j	_be_pad
_be_aligned:

	# s4 = offset of first generated entry (compressed_len rounded up to 32)
	addi	s4, s1, 31
	li	t0, -32
	and	s4, s4, t0			# s4 = (compressed_len + 31) & ~31

	# Phase 2: blake2s chain to fill remaining entries
	# Each entry: hash previous 32-byte block POW_BLAKE2S_ITERS times
	# Seed: last 32 bytes of the compressed data region
	addi	sp, sp, -32			# temp buffer for blake2s output
	mv	s5, sp

_be_gen_loop:
	bgeu	s4, s3, _be_done		# offset >= table_size → done

	# Input for chain: the previous 32-byte block in the table
	addi	a0, s4, -32
	add	a0, s2, a0			# table + offset - 32

	# Run POW_BLAKE2S_ITERS rounds of blake2s
	li	s6, POW_BLAKE2S_ITERS
_be_iter:
	beqz	s6, _be_iter_done
	# blake2s(input=a0, len=32, output=s5)
	li	a1, 32
	mv	a2, s5
	jal	blake2s
	# Next iteration: input = output
	mv	a0, s5
	addi	s6, s6, -1
	j	_be_iter
_be_iter_done:

	# Copy result to table
	add	t0, s2, s4			# dst = table + offset
	mv	t1, s5				# src = temp buffer
	li	t2, 8				# 32 bytes = 8 words
_be_store:
	lw	t3, 0(t1)
	sw	t3, 0(t0)
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	bnez	t2, _be_store

	addi	s4, s4, 32			# next entry
	j	_be_gen_loop

_be_done:
	addi	sp, sp, 32			# free temp buffer
	li	a0, 0
	j	_be_ret

_be_err:
	li	a0, -1
_be_ret:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# pow_hash: compute memory-hard PoW hash from pre-initialized state
# a0 = table_ptr
# a1 = table_mask ((table_size >> 5) - 1)
# a2 = state_ptr (32 bytes, will be modified in-place as working state)
# a3 = out_ptr (32-byte output, may equal state_ptr)
#
# Performs 32 random lookup rounds: idx = XOR(state) & mask, state ^= table[idx]
# ══════════════════════════════════════════════════════════════════════════════
pow_hash:
	SETUP	s0, s1, s2, s3, s4

	mv	s0, a0				# table_ptr
	mv	s1, a1				# table_mask
	mv	s2, a2				# state_ptr
	mv	s3, a3				# out_ptr

	li	s4, POW_LOOKUP_ROUNDS
_ph_round:
	beqz	s4, _ph_done

	# idx = (state[0] ^ state[1] ^ ... ^ state[7]) & table_mask
	lw	t0, 0(s2)
	lw	t1, 4(s2)
	xor	t0, t0, t1
	lw	t1, 8(s2)
	xor	t0, t0, t1
	lw	t1, 12(s2)
	xor	t0, t0, t1
	lw	t1, 16(s2)
	xor	t0, t0, t1
	lw	t1, 20(s2)
	xor	t0, t0, t1
	lw	t1, 24(s2)
	xor	t0, t0, t1
	lw	t1, 28(s2)
	xor	t0, t0, t1
	and	t0, t0, s1			# & table_mask
	slli	t0, t0, 5			# * 32 (byte offset)
	add	t0, s0, t0			# table_ptr + offset

	# state ^= table[idx]
	lw	t1, 0(t0)
	lw	t2, 0(s2)
	xor	t2, t2, t1
	sw	t2, 0(s2)

	lw	t1, 4(t0)
	lw	t2, 4(s2)
	xor	t2, t2, t1
	sw	t2, 4(s2)

	lw	t1, 8(t0)
	lw	t2, 8(s2)
	xor	t2, t2, t1
	sw	t2, 8(s2)

	lw	t1, 12(t0)
	lw	t2, 12(s2)
	xor	t2, t2, t1
	sw	t2, 12(s2)

	lw	t1, 16(t0)
	lw	t2, 16(s2)
	xor	t2, t2, t1
	sw	t2, 16(s2)

	lw	t1, 20(t0)
	lw	t2, 20(s2)
	xor	t2, t2, t1
	sw	t2, 20(s2)

	lw	t1, 24(t0)
	lw	t2, 24(s2)
	xor	t2, t2, t1
	sw	t2, 24(s2)

	lw	t1, 28(t0)
	lw	t2, 28(s2)
	xor	t2, t2, t1
	sw	t2, 28(s2)

	addi	s4, s4, -1
	j	_ph_round

_ph_done:
	# Copy state to output (skip if out_ptr == state_ptr)
	beq	s3, s2, _ph_ret
	mv	t0, s3
	mv	t1, s2
	li	t2, 8
_ph_copy:
	lw	t3, 0(t1)
	sw	t3, 0(t0)
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	bnez	t2, _ph_copy
_ph_ret:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# pow_hash_full: canonical PoW hash for a single header
# a0 = table_ptr, a1 = table_mask, a2 = header_ptr (128 bytes), a3 = out_ptr
#
# Computes: blake2s(header[0:124]) → ARX fold nonce from header[124:128] → 32 rounds
# This matches what mine_block computes, so verifiers and miners agree.
# ══════════════════════════════════════════════════════════════════════════════
pow_hash_full:
	SETUP	s0, s1, s2, s3

	mv	s0, a0				# table_ptr
	mv	s1, a1				# table_mask
	mv	s2, a2				# header_ptr
	mv	s3, a3				# out_ptr

	# blake2s(header[0:124]) → out_ptr
	mv	a0, s2				# header_ptr
	li	a1, POW_NONCE_OFFSET		# 124 bytes (exclude nonce)
	mv	a2, s3				# output = out_ptr
	jal	blake2s

	# Load nonce from header[124]
	li	t0, POW_NONCE_OFFSET
	add	t0, s2, t0
	lw	s2, 0(t0)			# s2 = nonce (reuse reg)

	# ARX nonce fold into state at out_ptr
	# word 0: add rot(nonce,0), xor rot(nonce,16)
	lw	t0, 0(s3)
	add	t0, t0, s2
	srli	t1, s2, 16
	slli	t2, s2, 16
	or	t1, t1, t2
	xor	t0, t0, t1
	sw	t0, 0(s3)

	# word 1: add rot(nonce,4), xor rot(nonce,20)
	lw	t0, 4(s3)
	srli	t1, s2, 4
	slli	t2, s2, 28
	or	t1, t1, t2
	add	t0, t0, t1
	srli	t1, s2, 20
	slli	t2, s2, 12
	or	t1, t1, t2
	xor	t0, t0, t1
	sw	t0, 4(s3)

	# word 2: add rot(nonce,8), xor rot(nonce,24)
	lw	t0, 8(s3)
	srli	t1, s2, 8
	slli	t2, s2, 24
	or	t1, t1, t2
	add	t0, t0, t1
	srli	t1, s2, 24
	slli	t2, s2, 8
	or	t1, t1, t2
	xor	t0, t0, t1
	sw	t0, 8(s3)

	# word 3: add rot(nonce,12), xor rot(nonce,28)
	lw	t0, 12(s3)
	srli	t1, s2, 12
	slli	t2, s2, 20
	or	t1, t1, t2
	add	t0, t0, t1
	srli	t1, s2, 28
	slli	t2, s2, 4
	or	t1, t1, t2
	xor	t0, t0, t1
	sw	t0, 12(s3)

	# word 4: add rot(nonce,16), xor rot(nonce,0)
	lw	t0, 16(s3)
	srli	t1, s2, 16
	slli	t2, s2, 16
	or	t1, t1, t2
	add	t0, t0, t1
	xor	t0, t0, s2
	sw	t0, 16(s3)

	# word 5: add rot(nonce,20), xor rot(nonce,4)
	lw	t0, 20(s3)
	srli	t1, s2, 20
	slli	t2, s2, 12
	or	t1, t1, t2
	add	t0, t0, t1
	srli	t1, s2, 4
	slli	t2, s2, 28
	or	t1, t1, t2
	xor	t0, t0, t1
	sw	t0, 20(s3)

	# word 6: add rot(nonce,24), xor rot(nonce,8)
	lw	t0, 24(s3)
	srli	t1, s2, 24
	slli	t2, s2, 8
	or	t1, t1, t2
	add	t0, t0, t1
	srli	t1, s2, 8
	slli	t2, s2, 24
	or	t1, t1, t2
	xor	t0, t0, t1
	sw	t0, 24(s3)

	# word 7: add rot(nonce,28), xor rot(nonce,12)
	lw	t0, 28(s3)
	srli	t1, s2, 28
	slli	t2, s2, 4
	or	t1, t1, t2
	add	t0, t0, t1
	srli	t1, s2, 12
	slli	t2, s2, 20
	or	t1, t1, t2
	xor	t0, t0, t1
	sw	t0, 28(s3)

	# pow_hash(table, mask, state=out_ptr, out=out_ptr)
	mv	a0, s0
	mv	a1, s1
	mv	a2, s3
	mv	a3, s3
	jal	pow_hash

	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# mine_block: iterate nonces until hash < target
# a0 = table_ptr
# a1 = table_mask
# a2 = header_ptr (128 bytes, nonce at offset 124)
# a3 = target_ptr (32 bytes, LE u256 comparison)
# Stack args: 0(sp) = out_ptr, 4(sp) = max_iter
# Returns: a0 = nonce on success, -1 if max_iter reached
#
# Optimization: blake2s(header[0:124]) is computed once. For each nonce,
# the base state is copied and the nonce is folded in via ARX (add-rotate-xor)
# across all 8 state words. Then 32 lookup rounds are performed.
# ══════════════════════════════════════════════════════════════════════════════
mine_block:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7

	mv	s0, a0				# table_ptr
	mv	s1, a1				# table_mask
	mv	s2, a2				# header_ptr
	mv	s3, a3				# target_ptr

	# Load stack args (SETUP saved 9 words, rounded to 48 bytes)
	lw	s4, 48(sp)			# out_ptr
	lw	s5, 52(sp)			# max_iter

	# Compute base_state = blake2s(header[0:124]) — once
	addi	sp, sp, -32			# base_state on stack
	mv	a0, s2				# header_ptr
	li	a1, POW_NONCE_OFFSET		# 124 bytes (exclude nonce)
	mv	a2, sp
	jal	blake2s
	mv	s7, sp				# s7 = base_state ptr

	li	s6, 0				# nonce = 0

_mb_loop:
	bgeu	s6, s5, _mb_fail

	# Copy base_state → out_ptr (working state)
	mv	t0, s4				# dst = out_ptr
	mv	t1, s7				# src = base_state
	lw	t2, 0(t1)
	sw	t2, 0(t0)
	lw	t2, 4(t1)
	sw	t2, 4(t0)
	lw	t2, 8(t1)
	sw	t2, 8(t0)
	lw	t2, 12(t1)
	sw	t2, 12(t0)
	lw	t2, 16(t1)
	sw	t2, 16(t0)
	lw	t2, 20(t1)
	sw	t2, 20(t0)
	lw	t2, 24(t1)
	sw	t2, 24(t0)
	lw	t2, 28(t1)
	sw	t2, 28(t0)

	# ARX nonce fold: for each word i, state[i] += rot(nonce, i*4); state[i] ^= rot(nonce, i*4+16)
	# Rotations: 0,4,8,12,16,20,24,28 for add; 16,20,24,28,0,4,8,12 for xor

	# word 0: add rot(nonce,0), xor rot(nonce,16)
	lw	t0, 0(s4)
	add	t0, t0, s6			# + nonce (rot 0)
	srli	t1, s6, 16
	slli	t2, s6, 16
	or	t1, t1, t2			# rot(nonce, 16)
	xor	t0, t0, t1
	sw	t0, 0(s4)

	# word 1: add rot(nonce,4), xor rot(nonce,20)
	lw	t0, 4(s4)
	srli	t1, s6, 4
	slli	t2, s6, 28
	or	t1, t1, t2			# rot(nonce, 4)
	add	t0, t0, t1
	srli	t1, s6, 20
	slli	t2, s6, 12
	or	t1, t1, t2			# rot(nonce, 20)
	xor	t0, t0, t1
	sw	t0, 4(s4)

	# word 2: add rot(nonce,8), xor rot(nonce,24)
	lw	t0, 8(s4)
	srli	t1, s6, 8
	slli	t2, s6, 24
	or	t1, t1, t2			# rot(nonce, 8)
	add	t0, t0, t1
	srli	t1, s6, 24
	slli	t2, s6, 8
	or	t1, t1, t2			# rot(nonce, 24)
	xor	t0, t0, t1
	sw	t0, 8(s4)

	# word 3: add rot(nonce,12), xor rot(nonce,28)
	lw	t0, 12(s4)
	srli	t1, s6, 12
	slli	t2, s6, 20
	or	t1, t1, t2			# rot(nonce, 12)
	add	t0, t0, t1
	srli	t1, s6, 28
	slli	t2, s6, 4
	or	t1, t1, t2			# rot(nonce, 28)
	xor	t0, t0, t1
	sw	t0, 12(s4)

	# word 4: add rot(nonce,16), xor rot(nonce,0)
	lw	t0, 16(s4)
	srli	t1, s6, 16
	slli	t2, s6, 16
	or	t1, t1, t2			# rot(nonce, 16)
	add	t0, t0, t1
	xor	t0, t0, s6			# xor nonce (rot 0)
	sw	t0, 16(s4)

	# word 5: add rot(nonce,20), xor rot(nonce,4)
	lw	t0, 20(s4)
	srli	t1, s6, 20
	slli	t2, s6, 12
	or	t1, t1, t2			# rot(nonce, 20)
	add	t0, t0, t1
	srli	t1, s6, 4
	slli	t2, s6, 28
	or	t1, t1, t2			# rot(nonce, 4)
	xor	t0, t0, t1
	sw	t0, 20(s4)

	# word 6: add rot(nonce,24), xor rot(nonce,8)
	lw	t0, 24(s4)
	srli	t1, s6, 24
	slli	t2, s6, 8
	or	t1, t1, t2			# rot(nonce, 24)
	add	t0, t0, t1
	srli	t1, s6, 8
	slli	t2, s6, 24
	or	t1, t1, t2			# rot(nonce, 8)
	xor	t0, t0, t1
	sw	t0, 24(s4)

	# word 7: add rot(nonce,28), xor rot(nonce,12)
	lw	t0, 28(s4)
	srli	t1, s6, 28
	slli	t2, s6, 4
	or	t1, t1, t2			# rot(nonce, 28)
	add	t0, t0, t1
	srli	t1, s6, 12
	slli	t2, s6, 20
	or	t1, t1, t2			# rot(nonce, 12)
	xor	t0, t0, t1
	sw	t0, 28(s4)

	# pow_hash(table, mask, state=out_ptr, out=out_ptr)
	mv	a0, s0
	mv	a1, s1
	mv	a2, s4				# state = out_ptr (in-place)
	mv	a3, s4				# out = out_ptr
	jal	pow_hash

	# Compare hash < target (LE u256: most significant byte at offset 31)
	li	t5, 31
_mb_cmp:
	bltz	t5, _mb_found			# all equal → hash <= target, accept
	add	t0, s4, t5
	add	t1, s3, t5
	lbu	t2, 0(t0)
	lbu	t3, 0(t1)
	bltu	t2, t3, _mb_found
	bgtu	t2, t3, _mb_next
	addi	t5, t5, -1
	j	_mb_cmp

_mb_next:
	addi	s6, s6, 1
	j	_mb_loop

_mb_found:
	mv	a0, s6
	j	_mb_cleanup

_mb_fail:
	li	a0, -1
_mb_cleanup:
	addi	sp, sp, 32			# free base_state
	RETURN

.endm	# DEFINE_POW
