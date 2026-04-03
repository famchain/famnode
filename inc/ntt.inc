# ntt.inc — Number Theoretic Transform over BabyBear field (RISC-V 32-bit)
#
# Forward and inverse NTT for polynomial operations in the STARK prover.
# Operates in-place on arrays of BabyBear field elements.
#
# Usage:
#   .include "macros.inc"
#   .include "field.inc"
#   .include "ntt.inc"
#   ...
#   DEFINE_NTT
#
# Public labels:
#   ntt_forward(a0=data, a1=len, a2=omega)
#       In-place forward NTT. len must be power of 2.
#       omega = generator of order len.
#       Transforms coefficients → evaluations.
#
#   ntt_inverse(a0=data, a1=len, a2=omega)
#       In-place inverse NTT. omega = generator of order len.
#       Transforms evaluations → coefficients.
#       Includes the 1/N scaling.
#
# Requires: fp_add, fp_sub, fp_mul, fp_inv from field.inc
#
# Algorithm: iterative Cooley-Tukey butterfly with bit-reversal permutation.

.macro DEFINE_NTT

# ══════════════════════════════════════════════════════════════════════════════
# ntt_forward: in-place forward NTT
# a0 = data (array of field elements, modified in-place)
# a1 = len (power of 2)
# a2 = omega (primitive len-th root of unity)
# ══════════════════════════════════════════════════════════════════════════════
ntt_forward:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7

	mv	s0, a0				# data
	mv	s1, a1				# len
	mv	s2, a2				# omega

	# ── Bit-reversal permutation ──
	jal	_ntt_bit_reverse

	# ── Butterfly passes ──
	# For each stage s = 1, 2, 4, ..., len/2:
	#   m = 2 * s (butterfly group size)
	#   wm = omega^(len/m) (twiddle factor step)
	#   For each group starting at k = 0, m, 2m, ...:
	#     w = 1
	#     For j = 0..s-1:
	#       butterfly(data[k+j], data[k+j+s], w)
	#       w *= wm

	li	s3, 1				# s = half_group = 1
_ntt_stage:
	bge	s3, s1, _ntt_done		# s >= len → done

	# m = 2 * s
	slli	s4, s3, 1			# m

	# wm = omega^(len/m) = omega^(len/(2*s))
	# exponent = len / m
	mv	a0, s1
	# Division by power of 2: len >> log2(m)
	# Since m = 2*s and s is power of 2, m is power of 2
	# len/m = len >> (1 + log2(s))
	# Simpler: just compute omega^(len/m) via fp_pow
	addi	sp, sp, -4
	sw	s3, 0(sp)			# save s
	mv	a0, s2				# omega
	# exp = len / m
	mv	a1, s1
	srli	a1, a1, 1			# len/2
	# Now divide by s: for s=1 → len/2, s=2 → len/4, etc.
	mv	t0, s3
_ntt_div_s:
	li	t1, 1
	beq	t0, t1, _ntt_div_done
	srli	a1, a1, 1
	srli	t0, t0, 1
	j	_ntt_div_s
_ntt_div_done:
	# a0 = omega, a1 = len/(2*s) = exponent
	jal	fp_pow				# a0 = wm = omega^(len/m)
	mv	s5, a0				# s5 = wm
	lw	s3, 0(sp)
	addi	sp, sp, 4

	# For each group: k = 0, m, 2m, ...
	li	s6, 0				# k = group start
_ntt_group:
	bge	s6, s1, _ntt_next_stage

	# w = 1
	li	s7, 1				# twiddle = 1

	# For j = 0..s-1: butterfly
	addi	sp, sp, -4
	sw	zero, 0(sp)			# j = 0
_ntt_butterfly:
	lw	t0, 0(sp)			# j
	bge	t0, s3, _ntt_bf_done

	# Compute addresses
	add	t1, s6, t0			# k + j
	slli	t1, t1, 2
	add	t1, s0, t1			# &data[k+j]
	add	t2, t0, s3			# j + s
	add	t2, s6, t2			# k + j + s
	slli	t2, t2, 2
	add	t2, s0, t2			# &data[k+j+s]

	# Load u = data[k+j], v = data[k+j+s]
	lw	a0, 0(t2)			# v = data[k+j+s]
	mv	a1, s7				# w (twiddle)
	# Save t1, t2 across fp_mul
	addi	sp, sp, -8
	sw	t1, 0(sp)
	sw	t2, 4(sp)
	jal	fp_mul				# a0 = w * v = t
	lw	t1, 0(sp)
	lw	t2, 4(sp)
	addi	sp, sp, 8

	mv	t3, a0				# t3 = t = w * v
	lw	a0, 0(t1)			# u = data[k+j]

	# butterfly: data[k+j] = u + t, data[k+j+s] = u - t
	addi	sp, sp, -12
	sw	a0, 0(sp)			# save u
	sw	t1, 4(sp)			# save &data[k+j]
	sw	t2, 8(sp)			# save &data[k+j+s]

	mv	a1, t3				# t
	jal	fp_add				# u + t
	lw	t1, 4(sp)
	sw	a0, 0(t1)			# data[k+j] = u + t

	lw	a0, 0(sp)			# u
	mv	a1, t3				# t
	jal	fp_sub				# u - t
	lw	t2, 8(sp)
	sw	a0, 0(t2)			# data[k+j+s] = u - t
	addi	sp, sp, 12

	# w *= wm
	mv	a0, s7
	mv	a1, s5
	jal	fp_mul
	mv	s7, a0				# w = w * wm

	# j++
	lw	t0, 0(sp)
	addi	t0, t0, 1
	sw	t0, 0(sp)
	j	_ntt_butterfly

_ntt_bf_done:
	addi	sp, sp, 4			# pop j

	# k += m
	add	s6, s6, s4
	j	_ntt_group

_ntt_next_stage:
	slli	s3, s3, 1			# s *= 2
	j	_ntt_stage

_ntt_done:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# ntt_inverse: in-place inverse NTT
# a0 = data, a1 = len, a2 = omega
# ══════════════════════════════════════════════════════════════════════════════
ntt_inverse:
	SETUP	s0, s1, s2

	mv	s0, a0				# data
	mv	s1, a1				# len
	mv	s2, a2				# omega

	# Inverse NTT = forward NTT with omega^(-1), then scale by 1/N
	mv	a0, s2
	jal	fp_inv				# omega_inv
	mv	a2, a0
	mv	a0, s0
	mv	a1, s1
	jal	ntt_forward			# forward NTT with omega^(-1)

	# Scale by 1/N
	mv	a0, s1
	jal	fp_inv				# n_inv = 1/N

	mv	s2, a0				# n_inv
	li	t5, 0
_ntt_scale:
	bge	t5, s1, _ntt_inv_done
	slli	t0, t5, 2
	add	t0, s0, t0
	lw	a0, 0(t0)
	mv	a1, s2
	addi	sp, sp, -8
	sw	t5, 0(sp)
	sw	t0, 4(sp)
	jal	fp_mul
	lw	t5, 0(sp)
	lw	t0, 4(sp)
	addi	sp, sp, 8
	sw	a0, 0(t0)
	addi	t5, t5, 1
	j	_ntt_scale

_ntt_inv_done:
	RETURN


# ── Bit-reversal permutation ──
# Operates on data at s0, length s1. Swaps elements i and bit_reverse(i).
_ntt_bit_reverse:
	SETUP	s3, s4, s5

	# Compute log2(len)
	mv	s3, s1				# len
	li	s4, 0				# log_n
	mv	t0, s3
_nbr_log:
	srli	t0, t0, 1
	beqz	t0, _nbr_start
	addi	s4, s4, 1
	j	_nbr_log

_nbr_start:
	li	s5, 0				# i = 0
_nbr_loop:
	bge	s5, s3, _nbr_done

	# Compute bit_reverse(i, log_n)
	mv	t0, s5				# i
	li	t1, 0				# reversed = 0
	mv	t2, s4				# bits remaining
_nbr_rev:
	beqz	t2, _nbr_swap
	slli	t1, t1, 1
	andi	t3, t0, 1
	or	t1, t1, t3
	srli	t0, t0, 1
	addi	t2, t2, -1
	j	_nbr_rev

_nbr_swap:
	# Only swap if i < reversed (to avoid double-swapping)
	bleu	t1, s5, _nbr_next
	# Swap data[i] and data[reversed]
	slli	t0, s5, 2
	add	t0, s0, t0			# &data[i]
	slli	t2, t1, 2
	add	t2, s0, t2			# &data[reversed]
	lw	t3, 0(t0)
	lw	t4, 0(t2)
	sw	t4, 0(t0)
	sw	t3, 0(t2)

_nbr_next:
	addi	s5, s5, 1
	j	_nbr_loop

_nbr_done:
	RETURN

.endm	# DEFINE_NTT
