# air.inc — AIR (Algebraic Intermediate Representation) for STARK proofs
#
# Defines constraint evaluation for the STARK verifier.
# Simple addition constraint (a + b = c) for initial testing.
# Will be extended to Poseidon constraints for block validation.
#
# Usage:
#   .include "macros.inc"
#   .include "field.inc"
#   .include "air.inc"
#   ...
#   DEFINE_AIR
#
# Public labels:
#   air_eval_add(a0=col_a, a1=col_b, a2=col_c) → a0 = c - a - b
#   air_eval_vanishing(a0=x, a1=log_n, a2=offset) → a0 = x^N - offset^N
#   air_check_quotient(a0=constraint, a1=vanishing, a2=quotient) → a0 = 0/-1
#   air_combine(a0=values_ptr, a1=count, a2=alpha) → a0 = sum(v[i]*alpha^i)
#
# Requires: fp_add, fp_sub, fp_mul from field.inc

.macro DEFINE_AIR

# ══════════════════════════════════════════════════════════════════════════════
# air_eval_add: evaluate addition constraint c - a - b
# a0 = a, a1 = b, a2 = c
# Returns: a0 = c - a - b (0 if satisfied)
# ══════════════════════════════════════════════════════════════════════════════
air_eval_add:
	SETUP	s0
	mv	s0, a2				# save c
	jal	fp_add				# a0 = a + b
	mv	a1, a0				# a1 = a + b
	mv	a0, s0				# a0 = c
	jal	fp_sub				# a0 = c - (a + b)
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# air_eval_vanishing: Z(x) = x^N - offset^N where N = 2^log_n
# a0 = x, a1 = log_n, a2 = offset
# Returns: a0 = x^N - offset^N
# ══════════════════════════════════════════════════════════════════════════════
air_eval_vanishing:
	SETUP	s0, s1, s2, s3

	mv	s0, a0				# x
	mv	s1, a1				# log_n
	mv	s2, a2				# offset

	# Compute x^(2^log_n) by squaring log_n times
	mv	a0, s0
	mv	s3, s1				# loop counter (s-reg survives fp_mul)
_av_xn:
	beqz	s3, _av_xn_done
	mv	a1, a0
	jal	fp_mul
	addi	s3, s3, -1
	j	_av_xn
_av_xn_done:
	mv	s0, a0				# s0 = x^N

	# Compute offset^(2^log_n)
	mv	a0, s2
	mv	s3, s1
_av_on:
	beqz	s3, _av_on_done
	mv	a1, a0
	jal	fp_mul
	addi	s3, s3, -1
	j	_av_on
_av_on_done:
	# a0 = offset^N, s0 = x^N
	mv	a1, a0				# a1 = offset^N
	mv	a0, s0				# a0 = x^N
	jal	fp_sub				# x^N - offset^N

	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# air_check_quotient: verify constraint = quotient × vanishing
# a0 = constraint_value
# a1 = vanishing_value
# a2 = quotient_value
# Returns: a0 = 0 if consistent, -1 if not
# ══════════════════════════════════════════════════════════════════════════════
air_check_quotient:
	SETUP	s0

	mv	s0, a0				# save constraint

	# quotient * vanishing
	mv	a0, a2				# quotient
	jal	fp_mul				# a0 = quotient * vanishing

	# Compare with constraint
	beq	a0, s0, _aq_valid
	li	a0, -1
	j	_aq_ret
_aq_valid:
	li	a0, 0
_aq_ret:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# air_combine: random linear combination of constraint values
# a0 = values_ptr (array of field elements)
# a1 = count
# a2 = alpha (random challenge)
# Returns: a0 = values[0] + alpha*values[1] + alpha^2*values[2] + ...
#
# Uses Horner's method: ((values[n-1]*alpha + values[n-2])*alpha + ...)
# ══════════════════════════════════════════════════════════════════════════════
air_combine:
	SETUP	s0, s1, s2, s3

	mv	s0, a0				# values
	mv	s1, a1				# count
	mv	s2, a2				# alpha

	# Start from last element, work backwards (Horner)
	beqz	s1, _ac_zero
	addi	s3, s1, -1			# i = count - 1
	slli	t0, s3, 2
	add	t0, s0, t0
	lw	s3, 0(t0)			# result = values[count-1]
	addi	s1, s1, -2			# remaining = count - 2

_ac_loop:
	bltz	s1, _ac_done
	# result = result * alpha + values[i]
	mv	a0, s3
	mv	a1, s2
	jal	fp_mul				# result * alpha
	slli	t0, s1, 2
	add	t0, s0, t0
	lw	a1, 0(t0)			# values[i]
	jal	fp_add				# + values[i]
	mv	s3, a0
	addi	s1, s1, -1
	j	_ac_loop

_ac_done:
	mv	a0, s3
	j	_ac_ret

_ac_zero:
	li	a0, 0
_ac_ret:
	RETURN

.endm	# DEFINE_AIR
