# poseidon2.inc — Poseidon2 hash over BabyBear field for RISC-V 32-bit
#
# Parameters: width=16, rate=8, capacity=8, S-box=x^7
# Rounds: 4 full (external) + 13 partial (internal) + 4 full (external)
# Field: BabyBear p = 2^31 - 2^27 + 1 = 0x78000001
#
# Usage:
#   .include "macros.inc"
#   .include "field.inc"
#   .include "poseidon2.inc"
#   ...
#   DEFINE_POSEIDON2
#
# Public labels:
#   poseidon2_hash(a0=input_ptr, a1=num_elements, a2=output_ptr)
#       Hash a sequence of field elements. Output is 8 field elements (32 bytes).
#       Uses sponge construction: absorb rate=8 elements at a time.
#
#   poseidon2_perm(a0=state_ptr)
#       Apply the Poseidon2 permutation in-place to 16 field elements.
#
# Requires: fp_add, fp_sub, fp_mul from field.inc

.macro DEFINE_POSEIDON2

# ══════════════════════════════════════════════════════════════════════════════
# poseidon2_perm: apply Poseidon2 permutation to state[0..15]
# a0 = state_ptr (16 × u32 field elements, modified in-place)
# Clobbers: s-regs via SETUP, t-regs, a0-a1
# ══════════════════════════════════════════════════════════════════════════════
poseidon2_perm:
	SETUP	s0, s1, s2, s3

	mv	s0, a0				# state_ptr

	# ── Initial external linear layer ──
	mv	a0, s0
	jal	_p2_mds_external

	# ── 4 initial full (external) rounds ──
	LOAD_ADDRESS	s1, _p2_rc_ext_init
	li	s2, 4
_p2_ext_init:
	beqz	s2, _p2_partial
	mv	a0, s0				# state
	mv	a1, s1				# round constants (16 words)
	jal	_p2_external_round
	addi	s1, s1, 64			# next 16 constants
	addi	s2, s2, -1
	j	_p2_ext_init

	# ── 13 partial (internal) rounds ──
_p2_partial:
	LOAD_ADDRESS	s1, _p2_rc_int
	li	s2, 13
_p2_int_loop:
	beqz	s2, _p2_ext_final
	mv	a0, s0				# state
	lw	a1, 0(s1)			# single round constant
	jal	_p2_internal_round
	addi	s1, s1, 4			# next constant
	addi	s2, s2, -1
	j	_p2_int_loop

	# ── 4 final full (external) rounds ──
_p2_ext_final:
	LOAD_ADDRESS	s1, _p2_rc_ext_final
	li	s2, 4
_p2_ext_final_loop:
	beqz	s2, _p2_perm_done
	mv	a0, s0
	mv	a1, s1
	jal	_p2_external_round
	addi	s1, s1, 64
	addi	s2, s2, -1
	j	_p2_ext_final_loop

_p2_perm_done:
	RETURN


# ── External (full) round: add constants + S-box all + MDS ──
# a0 = state_ptr, a1 = round_constants_ptr (16 words)
_p2_external_round:
	SETUP	s0, s1, s2

	mv	s0, a0				# state
	mv	s1, a1				# constants

	# Add round constants and apply S-box to all 16 elements
	li	s2, 0
_p2_ext_sbox:
	li	t0, 16
	bge	s2, t0, _p2_ext_mds
	slli	t0, s2, 2
	add	t1, s0, t0
	add	t2, s1, t0
	lw	a0, 0(t1)			# state[i]
	lw	a1, 0(t2)			# rc[i]
	jal	fp_add				# x = state[i] + rc[i]
	jal	_p2_sbox7			# x^7
	slli	t0, s2, 2
	add	t1, s0, t0
	sw	a0, 0(t1)			# state[i] = x^7
	addi	s2, s2, 1
	j	_p2_ext_sbox

_p2_ext_mds:
	mv	a0, s0
	jal	_p2_mds_external

	RETURN


# ── Internal (partial) round: add constant to state[0] + S-box state[0] + internal MDS ──
# a0 = state_ptr, a1 = round_constant (single field element)
_p2_internal_round:
	SETUP	s0, s1

	mv	s0, a0				# state
	mv	s1, a1				# constant

	# Add round constant to state[0] only
	lw	a0, 0(s0)
	mv	a1, s1
	jal	fp_add
	# S-box on state[0]: x^7
	jal	_p2_sbox7
	sw	a0, 0(s0)

	# Internal MDS
	mv	a0, s0
	jal	_p2_mds_internal

	RETURN


# ── S-box: a0 = a0^7 mod p ──
# Computes x^7 = ((x^2)^2 * x^2) * x using 3 multiplications
# Clobbers: a1, t0-t6 (via fp_mul)
_p2_sbox7:
	addi	sp, sp, -8
	sw	ra, 0(sp)
	sw	a0, 4(sp)			# save x
	mv	a1, a0
	jal	fp_mul				# x^2
	mv	a1, a0
	addi	sp, sp, -4
	sw	a0, 0(sp)			# save x^2
	jal	fp_mul				# x^4
	lw	a1, 0(sp)			# x^2
	addi	sp, sp, 4
	jal	fp_mul				# x^6
	lw	a1, 4(sp)			# x
	jal	fp_mul				# x^7
	lw	ra, 0(sp)
	addi	sp, sp, 8
	ret


# ── External MDS: circulant of MDSMat4 blocks ──
# MDSMat4([a,b,c,d]) = [s+a+2b, s+b+2c, s+c+2d, s+d+2a] where s=a+b+c+d
# For width 16: apply MDSMat4 to each 4-element chunk, then add sum of all
# 4 chunks (element-wise by position) to each chunk.
# a0 = state_ptr (16 words, modified in-place)
_p2_mds_external:
	SETUP	s0, s1, s2, s3, s4, s5

	mv	s0, a0

	# Pass 1: apply MDSMat4 to each 4-element chunk
	# Use a temp buffer to avoid overwriting issues
	addi	sp, sp, -16			# temp for 4 outputs
	mv	s1, sp

	li	s2, 0				# chunk byte offset
_p2_mds_chunk:
	li	t0, 64
	bge	s2, t0, _p2_mds_pass2

	add	s3, s0, s2			# chunk ptr

	# Load originals a, b, c, d → save on stack
	lw	s4, 0(s3)			# a
	lw	s5, 4(s3)			# b
	addi	sp, sp, -16
	lw	t0, 8(s3)			# c
	sw	t0, 0(sp)
	lw	t0, 12(s3)			# d
	sw	t0, 4(sp)

	# s = a + b + c + d
	mv	a0, s4
	mv	a1, s5
	jal	fp_add
	lw	a1, 0(sp)			# c
	jal	fp_add
	lw	a1, 4(sp)			# d
	jal	fp_add
	sw	a0, 8(sp)			# save s

	# out[0] = s + a + 2b
	lw	a0, 8(sp)			# s
	mv	a1, s4				# a
	jal	fp_add
	mv	a1, s5				# b
	jal	fp_add
	mv	a1, s5				# b (add twice = +2b)
	jal	fp_add
	sw	a0, 0(s1)			# temp[0]

	# out[1] = s + b + 2c
	lw	a0, 8(sp)			# s
	mv	a1, s5				# b
	jal	fp_add
	lw	a1, 0(sp)			# c
	jal	fp_add
	lw	a1, 0(sp)			# c
	jal	fp_add
	sw	a0, 4(s1)

	# out[2] = s + c + 2d
	lw	a0, 8(sp)			# s
	lw	a1, 0(sp)			# c
	jal	fp_add
	lw	a1, 4(sp)			# d
	jal	fp_add
	lw	a1, 4(sp)			# d
	jal	fp_add
	sw	a0, 8(s1)

	# out[3] = s + d + 2a
	lw	a0, 8(sp)			# s
	lw	a1, 4(sp)			# d
	jal	fp_add
	mv	a1, s4				# a
	jal	fp_add
	mv	a1, s4				# a
	jal	fp_add
	sw	a0, 12(s1)

	addi	sp, sp, 16			# pop c, d, s

	# Copy temp → chunk
	lw	t0, 0(s1)
	sw	t0, 0(s3)
	lw	t0, 4(s1)
	sw	t0, 4(s3)
	lw	t0, 8(s1)
	sw	t0, 8(s3)
	lw	t0, 12(s1)
	sw	t0, 12(s3)

	addi	s2, s2, 16
	j	_p2_mds_chunk

_p2_mds_pass2:
	addi	sp, sp, 16			# free temp buffer

	# Pass 2: compute sum of all 4 chunks (by position), add to each chunk
	# sum[j] = state[j] + state[j+16] + state[j+32] + state[j+48] for j=0..3
	# Then for each chunk i: state[i*4+j] += sum[j]
	addi	sp, sp, -16			# sum[0..3]

	li	t5, 0				# position j = 0..3
_p2_mds_sum_pos:
	li	t0, 4
	bge	t5, t0, _p2_mds_add_back

	slli	t1, t5, 2
	add	t1, s0, t1			# &state[j] (use t1, not t0)
	lw	a0, 0(t1)
	lw	a1, 16(t1)
	jal	fp_add
	slli	t1, t5, 2			# recompute after fp_add
	add	t1, s0, t1
	lw	a1, 32(t1)
	jal	fp_add
	slli	t1, t5, 2
	add	t1, s0, t1
	lw	a1, 48(t1)
	jal	fp_add
	slli	t1, t5, 2
	add	t1, sp, t1
	sw	a0, 0(t1)			# sum[j]

	addi	t5, t5, 1
	j	_p2_mds_sum_pos

_p2_mds_add_back:
	# For each chunk i (0..3), for each position j (0..3): state[i*16+j*4] += sum[j]
	li	t5, 0				# flat index 0..15
_p2_mds_add_elem:
	li	t0, 16
	bge	t5, t0, _p2_mds_done

	slli	t0, t5, 2
	add	t1, s0, t0			# &state[i]
	lw	a0, 0(t1)
	# sum index = i % 4
	andi	t2, t5, 3
	slli	t2, t2, 2
	add	t2, sp, t2
	lw	a1, 0(t2)			# sum[i%4]
	jal	fp_add
	slli	t0, t5, 2
	add	t1, s0, t0
	sw	a0, 0(t1)

	addi	t5, t5, 1
	j	_p2_mds_add_elem

_p2_mds_done:
	addi	sp, sp, 16			# free sum
	RETURN


# ── Internal MDS: output[i] = sum(state) + diag[i] * state[i] ──
# a0 = state_ptr
_p2_mds_internal:
	SETUP	s0, s1, s2

	mv	s0, a0

	# Compute sum of all 16 elements
	li	s1, 0				# sum
	li	s2, 0				# index
_p2_int_sum:
	li	t0, 16
	bge	s2, t0, _p2_int_apply
	slli	t0, s2, 2
	add	t0, s0, t0
	lw	a0, 0(t0)
	mv	a1, s1
	jal	fp_add
	mv	s1, a0
	addi	s2, s2, 1
	j	_p2_int_sum

_p2_int_apply:
	# For each i: state[i] = sum + diag[i] * state[i]
	LOAD_ADDRESS	s2, _p2_diag_int
	li	t5, 0				# index
_p2_int_elem:
	li	t0, 16
	bge	t5, t0, _p2_int_done
	slli	t0, t5, 2
	add	t1, s0, t0			# &state[i]
	add	t2, s2, t0			# &diag[i]
	lw	a0, 0(t1)			# state[i]
	lw	a1, 0(t2)			# diag[i]
	# Save t5 across fp_mul (t-regs clobbered)
	addi	sp, sp, -8
	sw	t5, 0(sp)
	sw	ra, 4(sp)			# fp_mul is leaf but we jal to it
	jal	fp_mul				# diag[i] * state[i]
	mv	a1, s1				# + sum
	jal	fp_add
	lw	t5, 0(sp)
	lw	ra, 4(sp)
	addi	sp, sp, 8
	slli	t0, t5, 2
	add	t1, s0, t0
	sw	a0, 0(t1)			# state[i] = result
	addi	t5, t5, 1
	j	_p2_int_elem

_p2_int_done:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# poseidon2_hash: sponge hash over field elements
# a0 = input_ptr (array of u32 field elements)
# a1 = num_elements
# a2 = output_ptr (8 u32 field elements = 32 bytes)
# ══════════════════════════════════════════════════════════════════════════════
poseidon2_hash:
	SETUP	s0, s1, s2, s3, s4

	mv	s0, a0				# input
	mv	s1, a1				# num_elements
	mv	s2, a2				# output

	# Allocate state on stack (16 × 4 = 64 bytes), initialize to 0
	addi	sp, sp, -64
	mv	s3, sp				# state ptr
	li	t0, 16
	mv	t1, s3
_p2h_zero:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _p2h_zero

	li	s4, 0				# input position

_p2h_absorb:
	# Absorb rate=8 elements at a time
	bgeu	s4, s1, _p2h_finalize

	# XOR up to 8 input elements into state[0..7]
	li	t2, 0				# rate index
_p2h_xor:
	li	t0, 8
	bge	t2, t0, _p2h_perm
	bgeu	s4, s1, _p2h_perm		# ran out of input
	slli	t0, s4, 2
	add	t0, s0, t0
	lw	a0, 0(t0)			# input[pos]
	slli	t1, t2, 2
	add	t1, s3, t1
	lw	a1, 0(t1)			# state[rate_idx]
	jal	fp_add				# XOR → add in field
	slli	t1, t2, 2
	add	t1, s3, t1
	sw	a0, 0(t1)			# state[rate_idx] = result
	addi	s4, s4, 1
	addi	t2, t2, 1
	j	_p2h_xor

_p2h_perm:
	# Apply permutation
	mv	a0, s3
	jal	poseidon2_perm
	j	_p2h_absorb

_p2h_finalize:
	# Output = state[0..7] (capacity portion stays internal)
	mv	t0, s2				# output ptr
	mv	t1, s3				# state
	li	t2, 8
_p2h_out:
	lw	t3, 0(t1)
	sw	t3, 0(t0)
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	bnez	t2, _p2h_out

	addi	sp, sp, 64			# free state
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# Constants (from Plonky3 BabyBear Poseidon2, width=16)
# ══════════════════════════════════════════════════════════════════════════════
	.balign 4

# Internal round diagonal vector (16 elements)
_p2_diag_int:
	.word	0x77ffffff	# -2 mod p
	.word	0x00000001	# 1
	.word	0x00000002	# 2
	.word	0x3c000001	# 1/2
	.word	0x00000003	# 3
	.word	0x00000004	# 4
	.word	0x3c000000	# -1/2
	.word	0x77fffffe	# -3
	.word	0x77fffffd	# -4
	.word	0x77880001	# 1/256
	.word	0x5a000001	# 1/4
	.word	0x69000001	# 1/8
	.word	0x77fffff2	# 1/2^27
	.word	0x00780000	# -1/256
	.word	0x07800000	# -1/16
	.word	0x0000000f	# -1/2^27

# External initial round constants (4 rounds × 16 elements)
_p2_rc_ext_init:
	# Round 0
	.word	0x69cbb6af, 0x46ad93f9, 0x60a00f4e, 0x6b1297cd
	.word	0x23189afe, 0x732e7bef, 0x72c246de, 0x2c941900
	.word	0x0557eede, 0x1580496f, 0x3a3ea77b, 0x54f3f271
	.word	0x0f49b029, 0x47872fe1, 0x221e2e36, 0x1ab7202e
	# Round 1
	.word	0x487779a6, 0x3851c9d8, 0x38dc17c0, 0x209f8849
	.word	0x268dcee8, 0x350c48da, 0x5b9ad32e, 0x0523272b
	.word	0x3f89055b, 0x01e894b2, 0x13ddedde, 0x1b2ef334
	.word	0x7507d8b4, 0x6ceeb94e, 0x52eb6ba2, 0x50642905
	# Round 2
	.word	0x05453f3f, 0x06349efc, 0x6922787c, 0x04bfff9c
	.word	0x768c714a, 0x3e9ff21a, 0x15737c9c, 0x2229c807
	.word	0x0d47f88c, 0x097e0ecc, 0x27eadba0, 0x2d7d29e4
	.word	0x3502aaa0, 0x0f475fd7, 0x29fbda49, 0x018afffd
	# Round 3
	.word	0x0315b618, 0x6d4497d1, 0x1b171d9e, 0x52861abd
	.word	0x2e5d0501, 0x3ec8646c, 0x6e5f250a, 0x148ae8e6
	.word	0x17f5fa4a, 0x3e66d284, 0x0051aa3b, 0x483f7913
	.word	0x2cfe5f15, 0x023427ca, 0x2cc78315, 0x1e36ea47

# Internal round constants (13 scalar values)
_p2_rc_int:
	.word	0x5a8053c0, 0x693be639, 0x3858867d, 0x19334f6b
	.word	0x128f0fd8, 0x4e2b1ccb, 0x61210ce0, 0x3c318939
	.word	0x0b5b2f22, 0x2edb11d5, 0x213effdf, 0x0cac4606
	.word	0x241af16d

# External final round constants (4 rounds × 16 elements)
_p2_rc_ext_final:
	# Round 0
	.word	0x7290a80d, 0x6f7e5329, 0x598ec8a8, 0x76a859a0
	.word	0x6559e868, 0x657b83af, 0x13271d3f, 0x1f876063
	.word	0x0aeeae37, 0x706e9ca6, 0x46400cee, 0x72a05c26
	.word	0x2c589c9e, 0x20bd37a7, 0x6a2d3d10, 0x20523767
	# Round 1
	.word	0x5b8fe9c4, 0x2aa501d6, 0x1e01ac3e, 0x1448bc54
	.word	0x5ce5ad1c, 0x4918a14d, 0x2c46a83f, 0x4fcf6876
	.word	0x61d8d5c8, 0x6ddf4ff9, 0x11fda4d3, 0x02933a8f
	.word	0x170eaf81, 0x5a9c314f, 0x49a12590, 0x35ec52a1
	# Round 2
	.word	0x58eb1611, 0x5e481e65, 0x367125c9, 0x0eba33ba
	.word	0x1fc28ded, 0x066399ad, 0x0cbec0ea, 0x75fd1af0
	.word	0x50f5bf4e, 0x643d5f41, 0x6f4fe718, 0x5b3cbbde
	.word	0x1e3afb3e, 0x296fb027, 0x45e1547b, 0x4a8db2ab
	# Round 3
	.word	0x59986d19, 0x30bcdfa3, 0x1db63932, 0x1d7c2824
	.word	0x53b33681, 0x0673b747, 0x038a98a3, 0x2c5bce60
	.word	0x351979cd, 0x5008fb73, 0x547bca78, 0x711af481
	.word	0x3f93bf64, 0x644d987b, 0x3c8bcd87, 0x608758b8

.endm	# DEFINE_POSEIDON2
