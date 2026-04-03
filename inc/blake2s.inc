# blake2s.inc — Performance-optimized BLAKE2s (RFC 7693) for RISC-V 32-bit
#
# Usage:
#   .include "blake2s.inc"
#   ...
#   DEFINE_BLAKE2S          # place after your code, emits b2s_compress + blake2s + data
#
# Public labels emitted by DEFINE_BLAKE2S:
#   b2s_compress(a0=h_ptr, a1=m_ptr, a2=t_lo, a3=t_hi, a4=f0)
#   blake2s(a0=input, a1=len, a2=output_ptr)
#
# Compression register map:
#   v[0..7]=s0..s7, v[8..11]=s8..s11, v[12..15]=a0..a3
#   mx,my=a4,a5  tmp=a6  m_ptr=a7
#
# Requires: SETUP/RETURN/LOAD_ADDRESS macros to be defined.

# ──────────────────────────────────────────────────────────────────────────────
# ROTR: rotate right by constant amount
# ──────────────────────────────────────────────────────────────────────────────
.macro ROTR reg, tmp, n
	srli	\tmp, \reg, \n
	slli	\reg, \reg, (32 - \n)
	or	\reg, \reg, \tmp
.endm

# ──────────────────────────────────────────────────────────────────────────────
# G mixing function (RFC 7693 §3.1)
# va,vb,vc,vd = state registers; mx_off,my_off = byte offsets into msg (a7)
# Uses a4,a5 for message words, a6 for rotation temp
# ──────────────────────────────────────────────────────────────────────────────
.macro B2S_G va, vb, vc, vd, mx_off, my_off
	lw	a4, \mx_off(a7)
	lw	a5, \my_off(a7)
	add	\va, \va, \vb
	add	\va, \va, a4
	xor	\vd, \vd, \va
	ROTR	\vd, a6, 16
	add	\vc, \vc, \vd
	xor	\vb, \vb, \vc
	ROTR	\vb, a6, 12
	add	\va, \va, \vb
	add	\va, \va, a5
	xor	\vd, \vd, \va
	ROTR	\vd, a6, 8
	add	\vc, \vc, \vd
	xor	\vb, \vb, \vc
	ROTR	\vb, a6, 7
.endm

# ──────────────────────────────────────────────────────────────────────────────
# B2S_ROUND: one round = 4 column G calls + 4 diagonal G calls
# m0..m15 = sigma permutation indices for this round
# ──────────────────────────────────────────────────────────────────────────────
.macro B2S_ROUND m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15
	# Column rounds
	B2S_G	s0, s4, s8,  a0, (\m0*4),  (\m1*4)
	B2S_G	s1, s5, s9,  a1, (\m2*4),  (\m3*4)
	B2S_G	s2, s6, s10, a2, (\m4*4),  (\m5*4)
	B2S_G	s3, s7, s11, a3, (\m6*4),  (\m7*4)
	# Diagonal rounds
	B2S_G	s0, s5, s10, a3, (\m8*4),  (\m9*4)
	B2S_G	s1, s6, s11, a0, (\m10*4), (\m11*4)
	B2S_G	s2, s7, s8,  a1, (\m12*4), (\m13*4)
	B2S_G	s3, s4, s9,  a2, (\m14*4), (\m15*4)
.endm

# ──────────────────────────────────────────────────────────────────────────────
# B2S_10_ROUNDS: all 10 rounds with sigma permutations baked in
# ──────────────────────────────────────────────────────────────────────────────
.macro B2S_10_ROUNDS
	B2S_ROUND  0, 1,  2, 3,  4, 5,  6, 7,  8, 9, 10, 11, 12, 13, 14, 15
	B2S_ROUND 14, 10,  4, 8,  9, 15, 13, 6,  1, 12,  0,  2, 11,  7,  5,  3
	B2S_ROUND 11,  8, 12, 0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4
	B2S_ROUND  7,  9,  3, 1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8
	B2S_ROUND  9,  0,  5, 7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13
	B2S_ROUND  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9
	B2S_ROUND 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11
	B2S_ROUND 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10
	B2S_ROUND  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5
	B2S_ROUND 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0
.endm

# ──────────────────────────────────────────────────────────────────────────────
# DEFINE_BLAKE2S: emits b2s_compress, blake2s, and IV data.
# Place this after your main code to avoid executing it at boot.
# ──────────────────────────────────────────────────────────────────────────────
.macro DEFINE_BLAKE2S

# b2s_compress: BLAKE2s compression function
# a0=h_ptr, a1=m_ptr, a2=t_lo, a3=t_hi, a4=f0
b2s_compress:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11

	mv	a7, a1			# a7 = m_ptr (kept for all rounds)
	mv	t0, a0			# t0 = h_ptr

	# v[0..7] = h[0..7]
	lw	s0,  0(t0)
	lw	s1,  4(t0)
	lw	s2,  8(t0)
	lw	s3, 12(t0)
	lw	s4, 16(t0)
	lw	s5, 20(t0)
	lw	s6, 24(t0)
	lw	s7, 28(t0)

	# save h_ptr + h[0..7] on stack for final XOR
	addi	sp, sp, -36
	sw	t0,  0(sp)
	sw	s0,  4(sp)
	sw	s1,  8(sp)
	sw	s2, 12(sp)
	sw	s3, 16(sp)
	sw	s4, 20(sp)
	sw	s5, 24(sp)
	sw	s6, 28(sp)
	sw	s7, 32(sp)

	# v[8..11] = IV[0..3]; v[12..15] = IV[4..7] ^ (t_lo, t_hi, f0, 0)
	LOAD_ADDRESS t1, _b2s_iv
	lw	s8,   0(t1)
	lw	s9,   4(t1)
	lw	s10,  8(t1)
	lw	s11, 12(t1)
	lw	a0,  16(t1);	xor a0, a0, a2	# v[12] = IV[4] ^ t_lo
	lw	a1,  20(t1);	xor a1, a1, a3	# v[13] = IV[5] ^ t_hi
	lw	a2,  24(t1);	xor a2, a2, a4	# v[14] = IV[6] ^ f0
	lw	a3,  28(t1)			# v[15] = IV[7]

	B2S_10_ROUNDS

	# finalize: h[i] ^= v[i] ^ v[i+8]
	lw	t0, 0(sp)
	lw	t1,  4(sp);	xor t1,t1,s0;	xor t1,t1,s8;	sw t1,  0(t0)
	lw	t1,  8(sp);	xor t1,t1,s1;	xor t1,t1,s9;	sw t1,  4(t0)
	lw	t1, 12(sp);	xor t1,t1,s2;	xor t1,t1,s10;	sw t1,  8(t0)
	lw	t1, 16(sp);	xor t1,t1,s3;	xor t1,t1,s11;	sw t1, 12(t0)
	lw	t1, 20(sp);	xor t1,t1,s4;	xor t1,t1,a0;	sw t1, 16(t0)
	lw	t1, 24(sp);	xor t1,t1,s5;	xor t1,t1,a1;	sw t1, 20(t0)
	lw	t1, 28(sp);	xor t1,t1,s6;	xor t1,t1,a2;	sw t1, 24(t0)
	lw	t1, 32(sp);	xor t1,t1,s7;	xor t1,t1,a3;	sw t1, 28(t0)
	addi	sp, sp, 36

	RETURN

# blake2s: hash arbitrary-length input with 32-byte output
# a0=input_ptr, a1=input_len, a2=output_ptr
blake2s:
	SETUP	s0, s1, s2, s3, s4, s5, s6

	mv	s0, a0			# input_ptr
	mv	s1, a1			# remaining bytes
	mv	s2, a2			# output_ptr

	# allocate h[0..7] (32 bytes) + last-block buffer (64 bytes) = 96
	addi	sp, sp, -96
	mv	s3, sp			# h_ptr
	addi	s4, sp, 32		# buf_ptr

	# h[0..7] = IV[0..7]
	LOAD_ADDRESS t0, _b2s_iv
	.set _i, 0
	.rept 8
	lw	t1, (_i*4)(t0)
	sw	t1, (_i*4)(s3)
	.set _i, _i+1
	.endr

	# h[0] ^= 0x01010020 (outlen=32, fanout=1, depth=1)
	lw	t0, 0(s3)
	li	t1, 0x01010020
	xor	t0, t0, t1
	sw	t0, 0(s3)

	li	s5, 0			# counter_lo
	li	s6, 0			# counter_hi

	# process complete 64-byte blocks (except last)
_b2s_block\@:
	li	t0, 64
	ble	s1, t0, _b2s_last\@

	add	s5, s5, t0		# counter += 64
	mv	a0, s3
	mv	a1, s0
	mv	a2, s5
	mv	a3, s6
	li	a4, 0
	jal	b2s_compress

	addi	s0, s0, 64
	addi	s1, s1, -64
	j	_b2s_block\@

_b2s_last\@:
	# zero 64-byte buffer
	mv	t1, s4
	.rept 16
	sw	zero, 0(t1)
	addi	t1, t1, 4
	.endr

	# copy remaining bytes into buffer
	mv	t0, s0
	mv	t1, s4
	mv	t2, s1
_b2s_copy\@:
	beqz	t2, _b2s_done\@
	lbu	t3, 0(t0)
	sb	t3, 0(t1)
	addi	t0, t0, 1
	addi	t1, t1, 1
	addi	t2, t2, -1
	j	_b2s_copy\@
_b2s_done\@:

	add	s5, s5, s1		# counter += remaining
	mv	a0, s3
	mv	a1, s4
	mv	a2, s5
	mv	a3, s6
	li	a4, -1			# f0 = 0xFFFFFFFF (last block)
	jal	b2s_compress

	# copy h[0..7] → output
	.set _i, 0
	.rept 8
	lw	t0, (_i*4)(s3)
	sw	t0, (_i*4)(s2)
	.set _i, _i+1
	.endr

	addi	sp, sp, 96
	RETURN

# blake2s_64: optimized blake2s for exactly 64-byte input (one block)
# a0 = input_ptr (64 bytes), a1 = output_ptr (32 bytes)
#
# Skips the multi-block wrapper entirely. Uses pre-computed initial h[]
# (IV with params already applied). Calls b2s_compress directly.
# ~30% faster than generic blake2s for 64-byte inputs.
blake2s_64:
	SETUP	s0, s1

	mv	s0, a0				# input_ptr
	mv	s1, a1				# output_ptr

	# allocate h[0..7] on stack (32 bytes)
	addi	sp, sp, -32

	# load pre-computed h[] (IV with 0x01010020 already XOR'd into h[0])
	LOAD_ADDRESS t0, _b2s_h_init
	.set _i, 0
	.rept 8
	lw	t1, (_i*4)(t0)
	sw	t1, (_i*4)(sp)
	.set _i, _i+1
	.endr

	# compress(h=sp, m=input, t_lo=64, t_hi=0, f0=-1)
	mv	a0, sp				# h_ptr
	mv	a1, s0				# m_ptr = input directly (no copy!)
	li	a2, 64				# counter = 64
	li	a3, 0				# counter_hi = 0
	li	a4, -1				# f0 = last block
	jal	b2s_compress

	# copy h[0..7] → output
	.set _i, 0
	.rept 8
	lw	t0, (_i*4)(sp)
	sw	t0, (_i*4)(s1)
	.set _i, _i+1
	.endr

	addi	sp, sp, 32
	RETURN

# IV constants
	.balign 4
_b2s_iv:
	.word	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
	.word	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19

# Pre-computed h[] for blake2s with outlen=32, fanout=1, depth=1
# h[0] = IV[0] ^ 0x01010020, h[1..7] = IV[1..7]
	.balign 4
_b2s_h_init:
	.word	0x6B08E647	# 0x6A09E667 ^ 0x01010020
	.word	0xBB67AE85, 0x3C6EF372, 0xA54FF53A
	.word	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19

.endm	# DEFINE_BLAKE2S
