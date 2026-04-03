# transcript.inc — Fiat-Shamir transcript for STARK proofs (RISC-V 32-bit)
#
# Absorbs proof elements, squeezes verifier challenges.
# Uses Poseidon2 sponge internally (width=16, rate=8, capacity=8).
#
# Usage:
#   .include "macros.inc"
#   .include "field.inc"
#   .include "poseidon2.inc"
#   .include "transcript.inc"
#   ...
#   DEFINE_TRANSCRIPT
#
# Public labels:
#   transcript_init(a0=state_ptr)
#       Initialize a transcript. state_ptr must be 68 bytes (16 words state + 1 word counter).
#
#   transcript_absorb(a0=state_ptr, a1=value)
#       Absorb one field element into the transcript.
#
#   transcript_absorb_n(a0=state_ptr, a1=values_ptr, a2=count)
#       Absorb multiple field elements.
#
#   transcript_squeeze(a0=state_ptr) → a0 = challenge
#       Squeeze one field element challenge from the transcript.
#
# State layout (68 bytes):
#   [0..63]  : Poseidon2 state (16 × u32)
#   [64]     : absorb counter (0..7, tracks position within rate)
#
# Requires: poseidon2_perm from poseidon2.inc, fp_add from field.inc

.equ	TS_STATE_OFF,	0
.equ	TS_CTR_OFF,	64
.equ	TS_SIZE,	68
.equ	TS_RATE,	8

.macro DEFINE_TRANSCRIPT

# ══════════════════════════════════════════════════════════════════════════════
# transcript_init: initialize transcript state to zeros
# a0 = state_ptr (68 bytes)
# ══════════════════════════════════════════════════════════════════════════════
transcript_init:
	# Zero all 17 words (16 state + 1 counter)
	li	t0, 17
	mv	t1, a0
_ti_zero:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _ti_zero
	ret


# ══════════════════════════════════════════════════════════════════════════════
# transcript_absorb: absorb one field element
# a0 = state_ptr, a1 = value
# ══════════════════════════════════════════════════════════════════════════════
transcript_absorb:
	SETUP	s0, s1

	mv	s0, a0				# state_ptr
	mv	s1, a1				# value

	# state[counter] += value (XOR in field = add)
	lw	t0, TS_CTR_OFF(s0)		# counter
	slli	t1, t0, 2
	add	t1, s0, t1			# &state[counter]
	lw	a0, 0(t1)
	mv	a1, s1
	jal	fp_add
	lw	t0, TS_CTR_OFF(s0)		# reload counter (t0 clobbered)
	slli	t1, t0, 2
	add	t1, s0, t1
	sw	a0, 0(t1)			# state[counter] = old + value

	# Increment counter
	addi	t0, t0, 1
	li	t1, TS_RATE
	blt	t0, t1, _ta_no_perm

	# Counter reached rate → permute and reset
	mv	a0, s0				# state_ptr (permutation is in-place)
	jal	poseidon2_perm
	sw	zero, TS_CTR_OFF(s0)		# reset counter
	j	_ta_done

_ta_no_perm:
	sw	t0, TS_CTR_OFF(s0)		# store updated counter
_ta_done:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# transcript_absorb_n: absorb multiple field elements
# a0 = state_ptr, a1 = values_ptr, a2 = count
# ══════════════════════════════════════════════════════════════════════════════
transcript_absorb_n:
	SETUP	s0, s1, s2

	mv	s0, a0				# state_ptr
	mv	s1, a1				# values_ptr
	mv	s2, a2				# count

_tan_loop:
	beqz	s2, _tan_done
	mv	a0, s0
	lw	a1, 0(s1)
	jal	transcript_absorb
	addi	s1, s1, 4
	addi	s2, s2, -1
	j	_tan_loop

_tan_done:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# transcript_squeeze: squeeze one challenge field element
# a0 = state_ptr
# Returns: a0 = challenge (field element)
#
# If there are absorbed elements not yet permuted, permutes first.
# Then reads from the capacity portion and permutes to advance.
# ══════════════════════════════════════════════════════════════════════════════
transcript_squeeze:
	SETUP	s0, s1

	mv	s0, a0				# state_ptr

	# If counter > 0, un-permuted absorptions → permute first
	lw	t0, TS_CTR_OFF(s0)
	beqz	t0, _ts_read

	mv	a0, s0
	jal	poseidon2_perm
	sw	zero, TS_CTR_OFF(s0)

_ts_read:
	# Read challenge from state[0]
	lw	s1, 0(s0)

	# Permute to advance state (next squeeze gives different value)
	mv	a0, s0
	jal	poseidon2_perm

	mv	a0, s1				# return challenge
	RETURN

.endm	# DEFINE_TRANSCRIPT
