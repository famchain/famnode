# stark.inc — STARK verifier for RISC-V 32-bit
#
# Verifies a STARK proof: Fiat-Shamir replay, FRI Merkle proofs,
# folding consistency between layers.
#
# Requires: field, poseidon2, merkle, transcript, fri, air

.macro DEFINE_STARK

# ══════════════════════════════════════════════════════════════════════════════
# stark_verify: verify a STARK proof
# a0 = proof_ptr
# Returns: a0 = 0 if valid, -1 if invalid
# ══════════════════════════════════════════════════════════════════════════════
stark_verify:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7

	mv	s0, a0				# proof base

	# ── Parse header ──
	lw	s1, 0(s0)			# num_layers
	lw	s2, 4(s0)			# domain_log
	lw	s3, 8(s0)			# num_queries
	lw	s4, 12(s0)			# final_poly_len
	lw	s5, 16(s0)			# coset_offset
	addi	s6, s0, 20			# cursor

	# ── Init transcript ──
	addi	sp, sp, -TS_SIZE
	mv	s7, sp
	mv	a0, s7
	jal	transcript_init

	# Save roots_base
	addi	sp, sp, -4
	sw	s6, 0(sp)

	# ── Absorb roots + squeeze alphas (interleaved, matching prover) ──
	slli	t0, s1, 2
	sub	sp, sp, t0			# allocate alphas[num_layers]
	addi	sp, sp, -4
	addi	t0, sp, 4
	sw	t0, 0(sp)			# alphas_base

	mv	s4, s1				# counter
	lw	s5, 0(sp)			# write_ptr for alphas
_stv_interleave:
	beqz	s4, _stv_interleave_done
	# Absorb this layer's root
	mv	a0, s7
	mv	a1, s6
	li	a2, 8
	jal	transcript_absorb_n
	addi	s6, s6, 32
	# Squeeze alpha for this layer
	mv	a0, s7
	jal	transcript_squeeze
	sw	a0, 0(s5)
	addi	s5, s5, 4
	addi	s4, s4, -1
	j	_stv_interleave
_stv_interleave_done:
	lw	s4, 12(s0)			# reload final_poly_len
	lw	s5, 16(s0)			# reload coset_offset

	# ── Skip final polynomial ──
	slli	t0, s4, 2
	add	s6, s6, t0

	# ── Verify each query ──

	li	s4, 0				# query counter
_stv_query:
	bge	s4, s3, _stv_accept

	# Squeeze query index
	mv	a0, s7
	jal	transcript_squeeze
	li	t0, 1
	addi	t1, s2, -1
	sll	t0, t0, t1
	addi	t0, t0, -1
	and	a0, a0, t0			# qi

	# Per-query state on stack:
	# [0] qi, [4] layer_ctr, [8] prev_folded, [12] has_prev, [16] alphas_base, [20] roots_base
	lw	t0, 0(sp)			# alphas_base
	# roots_base is above alphas: sp + 4 + num_layers*4
	slli	t1, s1, 2
	addi	t1, t1, 4			# offset from sp to roots_base
	add	t1, sp, t1
	lw	t1, 0(t1)			# roots_base value
	addi	sp, sp, -24
	sw	a0, 0(sp)			# query_index
	sw	zero, 4(sp)			# layer_counter = 0
	sw	zero, 8(sp)			# prev_folded = 0
	sw	zero, 12(sp)			# has_prev = 0
	sw	t0, 16(sp)			# alphas_base
	sw	t1, 20(sp)			# roots_base

_stv_layer:

	lw	t0, 4(sp)			# layer_counter
	bge	t0, s1, _stv_query_ok

	# Read f_pos, f_neg, depth from proof
	lw	a0, 0(s6)			# f_pos
	lw	a1, 4(s6)			# f_neg
	lw	t0, 8(s6)			# depth
	addi	s6, s6, 12

	# Per-layer state: [0]f_pos [4]f_neg [8]depth [12]cursor_at_siblings
	addi	sp, sp, -16
	sw	a0, 0(sp)
	sw	a1, 4(sp)
	sw	t0, 8(sp)
	sw	s6, 12(sp)			# cursor now points to Merkle siblings

	# ── Check folding consistency with previous layer ──

	lw	t0, 16 + 12(sp)		# has_prev
	beqz	t0, _stv_skip_fold_chk
	lw	t0, 16 + 8(sp)			# prev_folded
	lw	t1, 0(sp)			# f_pos
	bne	t0, t1, _stv_fold_fail
_stv_skip_fold_chk:

	# ── Verify Merkle proof ──
	# Compute leaf hash: poseidon2_perm([f_pos, f_neg, 0...0])
	addi	sp, sp, -64
	lw	t0, 64(sp)			# f_pos
	sw	t0, 0(sp)
	lw	t0, 64 + 4(sp)			# f_neg
	sw	t0, 4(sp)
	li	t0, 14
	addi	t1, sp, 8
_stv_leaf_zpad:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _stv_leaf_zpad

	mv	a0, sp
	jal	poseidon2_perm			# sp[0..7] = leaf digest

	# Get root: roots_base + layer * 32
	lw	t0, 64 + 16 + 4(sp)		# layer_counter
	slli	t0, t0, 5
	lw	t1, 64 + 16 + 20(sp)		# roots_base
	add	a0, t1, t0			# root ptr

	mv	a1, sp				# leaf digest
	lw	a2, 64 + 16(sp)			# query_index
	lw	a3, 64 + 12(sp)			# proof siblings ptr

	# Push depth as stack arg for merkle_verify
	lw	t0, 64 + 8(sp)			# depth
	addi	sp, sp, -4
	sw	t0, 0(sp)
	jal	merkle_verify
	addi	sp, sp, 4			# pop depth

	addi	sp, sp, 64			# pop temp state

	bnez	a0, _stv_merkle_fail

	# ── Compute evaluation point x ──
	# gen = generator of order 2^(domain_log - layer)
	lw	t0, 16 + 4(sp)			# layer_counter
	sub	a0, s2, t0			# domain_log - layer
	jal	fri_domain_gen			# a0 = gen

	lw	a1, 16(sp)			# query_index
	mv	a2, s5				# coset_offset
	jal	fri_eval_point			# a0 = x

	# ── FRI fold ──
	mv	a3, a0				# x
	lw	a0, 0(sp)			# f_pos
	lw	a1, 4(sp)			# f_neg
	# Get alpha[layer]
	lw	t0, 16 + 4(sp)			# layer_counter
	slli	t0, t0, 2
	lw	t1, 16 + 16(sp)		# alphas_base
	add	t0, t1, t0
	lw	a2, 0(t0)			# alpha

	jal	fri_fold			# a0 = folded value

	# Store folded for next layer check
	sw	a0, 16 + 8(sp)			# prev_folded
	li	t0, 1
	sw	t0, 16 + 12(sp)		# has_prev = 1

	# Update query_index for next layer: idx = idx % (next_half)
	# next_half = 2^(current_domain_log - 2)
	# Since domain_log decreases each layer, use current value before decrement
	lw	t0, 16(sp)			# query_index
	lw	t1, 16 + 4(sp)			# layer_counter (current, before increment)
	sub	t1, s2, t1			# domain_log - layer = current_log
	addi	t1, t1, -2			# current_log - 2
	li	t2, 1
	sll	t2, t2, t1			# 2^(current_log - 2) = next_half
	addi	t2, t2, -1			# mask
	and	t0, t0, t2			# idx & mask
	sw	t0, 16(sp)

	# Advance cursor past Merkle siblings
	lw	t0, 8(sp)			# depth
	slli	t0, t0, 5			# × 32
	lw	s6, 12(sp)			# cursor at siblings start
	add	s6, s6, t0			# past siblings

	# Next layer
	lw	t0, 16 + 4(sp)			# layer_counter
	addi	t0, t0, 1
	sw	t0, 16 + 4(sp)

	addi	sp, sp, 16			# pop layer state
	j	_stv_layer

_stv_merkle_fail:
_stv_fold_fail:
	addi	sp, sp, 16			# pop layer state
	addi	sp, sp, 24			# pop query state
	j	_stv_invalid

_stv_query_ok:
	addi	sp, sp, 24			# pop query state
	addi	s4, s4, 1
	j	_stv_query

_stv_accept:
	li	a0, 0
	j	_stv_cleanup

_stv_invalid:
	li	a0, -1

_stv_cleanup:
	addi	sp, sp, 4			# alphas_base
	slli	t0, s1, 2
	add	sp, sp, t0			# alphas
	addi	sp, sp, 4			# roots_base
	addi	sp, sp, TS_SIZE			# transcript
	RETURN

.endm	# DEFINE_STARK
