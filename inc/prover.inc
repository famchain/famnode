# prover.inc — STARK prover for RISC-V 32-bit
#
# Generates a STARK proof for the addition constraint (a + b = c).
# Uses NTT for polynomial operations, Poseidon2 Merkle trees, FRI.
#
# Public labels:
#   stark_prove(a0=trace, a1=trace_len, a2=work, a3=proof)
#       trace: 3 arrays of trace_len words [a|b|c]
#       trace_len: power of 2 (≥ 4)
#       work: scratch buffer (needs ~20 × domain_size words)
#       proof: output buffer
#       Returns: a0 = proof size in bytes
#
# Requires: field, ntt, poseidon2, merkle, transcript, fri

.equ	BLOWUP,		4
.equ	LOG_BLOWUP,	2
.equ	NUM_QUERIES,	8
.equ	PRIM_ROOT,	31

# Prover frame layout (allocated on stack, s0 = frame base)
.equ	PF_TRACE,	0
.equ	PF_TLEN,	4
.equ	PF_WORK,	8
.equ	PF_PROOF,	12
.equ	PF_CURSOR,	16
.equ	PF_DSIZE,	20
.equ	PF_LOGT,	24
.equ	PF_LOGD,	28
.equ	PF_OFFSET,	32
.equ	PF_NLAYERS,	36
.equ	PF_FPLEN,	40
.equ	PF_TS,		44		# transcript inline (68 bytes)
.equ	PF_SIZE,	112		# 44 + 68

.macro DEFINE_PROVER

# ══════════════════════════════════════════════════════════════════════════════
# stark_prove
# ══════════════════════════════════════════════════════════════════════════════
stark_prove:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7
	# SETUP frame = 48 bytes (9 words padded to 16-byte align)

	# Allocate prover frame
	addi	sp, sp, -PF_SIZE
	mv	s0, sp				# s0 = frame pointer (constant)

	sw	a0, PF_TRACE(s0)
	sw	a1, PF_TLEN(s0)
	sw	a2, PF_WORK(s0)
	sw	a3, PF_PROOF(s0)
	sw	a3, PF_CURSOR(s0)
	li	t0, PRIM_ROOT
	sw	t0, PF_OFFSET(s0)
	sw	zero, PF_NLAYERS(s0)

	# domain_size = trace_len << LOG_BLOWUP
	slli	t0, a1, LOG_BLOWUP
	sw	t0, PF_DSIZE(s0)

	# log2(trace_len)
	mv	t0, a1
	li	t1, 0
1:	srli	t0, t0, 1
	beqz	t0, 2f
	addi	t1, t1, 1
	j	1b
2:	sw	t1, PF_LOGT(s0)
	addi	t1, t1, LOG_BLOWUP
	sw	t1, PF_LOGD(s0)

	# Init transcript
	addi	a0, s0, PF_TS
	jal	transcript_init

	# Skip 5-word header in proof (fill at end)
	lw	t0, PF_CURSOR(s0)
	addi	t0, t0, 20
	sw	t0, PF_CURSOR(s0)

	# ── Step 1: INTT trace columns → coefficients ──
	jal	_pv_step1_intt

	# ── Step 2: Coset evaluation on extended domain ──
	jal	_pv_step2_coset

	# ── Step 3: Compute quotient polynomial ──
	jal	_pv_step3_quotient

	# ── Step 4: FRI commitment layers ──
	jal	_pv_step4_fri

	# ── Step 5: Query phase ──
	jal	_pv_step5_queries

	# ── Step 6: Fill header ──
	lw	t0, PF_PROOF(s0)
	lw	t1, PF_NLAYERS(s0)
	sw	t1, 0(t0)
	lw	t1, PF_LOGD(s0)
	sw	t1, 4(t0)
	li	t1, NUM_QUERIES
	sw	t1, 8(t0)
	lw	t1, PF_FPLEN(s0)
	sw	t1, 12(t0)
	lw	t1, PF_OFFSET(s0)
	sw	t1, 16(t0)

	# Return proof size
	lw	a0, PF_CURSOR(s0)
	lw	t0, PF_PROOF(s0)
	sub	a0, a0, t0

	addi	sp, sp, PF_SIZE
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# Step 1: INTT trace columns → polynomial coefficients
# Reads trace from PF_TRACE, writes coefficients to PF_WORK
# ══════════════════════════════════════════════════════════════════════════════
_pv_step1_intt:
	SETUP	s1, s2, s3, s4, s5
	# s0 = frame ptr (not in our SETUP list, so it's preserved across our calls)

	lw	a0, PF_LOGT(s0)
	jal	fri_domain_gen
	mv	s1, a0				# trace_omega

	lw	s2, PF_TLEN(s0)		# trace_len
	lw	s3, PF_TRACE(s0)
	lw	s4, PF_WORK(s0)
	slli	s5, s2, 2			# trace_bytes

	# Column A: copy trace_a → work[0], then INTT
	mv	a0, s3				# src
	mv	a1, s4				# dst
	mv	a2, s2				# count
	jal	_pv_copy
	mv	a0, s4
	mv	a1, s2
	mv	a2, s1
	jal	ntt_inverse

	# Column B
	add	a0, s3, s5
	add	a1, s4, s5
	mv	a2, s2
	jal	_pv_copy
	add	a0, s4, s5
	mv	a1, s2
	mv	a2, s1
	jal	ntt_inverse

	# Column C
	slli	t0, s5, 1			# 2 * trace_bytes
	add	a0, s3, t0
	add	a1, s4, t0
	mv	a2, s2
	jal	_pv_copy
	slli	t0, s5, 1
	add	a0, s4, t0
	mv	a1, s2
	mv	a2, s1
	jal	ntt_inverse

	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# Step 2: Evaluate polynomials on coset domain
# coeffs at work[0..3TL-1], output to work[3TL..3TL+3D-1]
# ══════════════════════════════════════════════════════════════════════════════
_pv_step2_coset:
	SETUP	s1, s2, s3, s4, s5, s6

	lw	a0, PF_LOGD(s0)
	jal	fri_domain_gen
	mv	s1, a0				# domain_omega

	lw	s2, PF_TLEN(s0)
	lw	s3, PF_DSIZE(s0)
	lw	s4, PF_WORK(s0)
	lw	s5, PF_OFFSET(s0)

	# ext_base = work + 3*TL*4
	slli	t0, s2, 2
	slli	t1, t0, 1
	add	t1, t1, t0
	add	s6, s4, t1			# ext_base

	# ext_a = eval_coset(coeffs_a, trace_len, domain_size, ext_a, omega, offset)
	mv	a0, s4
	mv	a1, s2
	mv	a2, s3
	mv	a3, s6
	mv	a4, s1
	mv	a5, s5
	jal	_pv_eval_coset

	# ext_b
	slli	t0, s2, 2
	add	a0, s4, t0
	mv	a1, s2
	mv	a2, s3
	slli	t0, s3, 2
	add	a3, s6, t0
	mv	a4, s1
	mv	a5, s5
	jal	_pv_eval_coset

	# ext_c
	slli	t0, s2, 2
	slli	t0, t0, 1
	add	a0, s4, t0
	mv	a1, s2
	mv	a2, s3
	slli	t0, s3, 2
	slli	t0, t0, 1
	add	a3, s6, t0
	mv	a4, s1
	mv	a5, s5
	jal	_pv_eval_coset

	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# Step 3: Quotient = (C(x) - A(x) - B(x)) / (x^N - 1) pointwise
# Reads ext evals, writes quotient after them
# ══════════════════════════════════════════════════════════════════════════════
_pv_step3_quotient:
	SETUP	s1, s2, s3, s4, s5, s6, s7

	lw	s2, PF_TLEN(s0)
	lw	s3, PF_DSIZE(s0)
	lw	s4, PF_WORK(s0)
	lw	s5, PF_OFFSET(s0)
	lw	a0, PF_LOGD(s0)
	jal	fri_domain_gen
	mv	s1, a0				# domain_omega

	# Compute ext_base and quotient_ptr
	slli	t0, s2, 2
	slli	t1, t0, 1
	add	t1, t1, t0			# 3*TL*4
	add	s6, s4, t1			# ext_base

	slli	t0, s3, 2
	slli	t1, t0, 1
	add	t1, t1, t0			# 3*D*4
	add	s7, s6, t1			# quotient_ptr = ext_base + 3*D*4

	# x = offset (x_cur tracks offset * omega^i)
	li	s4, 0				# i
	addi	sp, sp, -4
	sw	s5, 0(sp)			# x_cur = offset

_pv3_loop:
	bge	s4, s3, _pv3_done

	# constraint = c[i] - (a[i] + b[i])
	slli	t0, s4, 2
	add	t1, s6, t0			# &ext_a[i]
	lw	a0, 0(t1)
	slli	t2, s3, 2
	add	t1, t1, t2			# &ext_b[i]
	lw	a1, 0(t1)
	jal	fp_add				# a + b
	mv	s5, a0				# save a+b
	slli	t0, s4, 2
	slli	t1, s3, 2
	slli	t1, t1, 1
	add	t0, t0, t1
	add	t0, s6, t0			# &ext_c[i]
	lw	a0, 0(t0)
	mv	a1, s5
	jal	fp_sub				# c - (a+b)
	mv	s5, a0				# constraint

	# vanishing = x_cur^trace_len - 1
	lw	a0, 0(sp)			# x_cur
	mv	a1, s2				# trace_len
	jal	fp_pow
	li	a1, 1
	jal	fp_sub				# x^N - 1
	jal	fp_inv				# 1/(x^N - 1)
	mv	a1, a0
	mv	a0, s5				# constraint
	jal	fp_mul				# constraint / vanishing

	# Store quotient[i]
	slli	t0, s4, 2
	add	t0, s7, t0
	sw	a0, 0(t0)

	# x_cur *= omega
	lw	a0, 0(sp)
	mv	a1, s1				# omega
	jal	fp_mul
	sw	a0, 0(sp)

	addi	s4, s4, 1
	j	_pv3_loop

_pv3_done:
	addi	sp, sp, 4
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# Step 4: FRI commitment layers
#
# Layer evaluations stored consecutively:
#   layer0 = quotient_ptr (D words)
#   layer1 = layer0 + D*4  (D/2 words)
#   layer2 = layer1 + D/2*4 (D/4 words)
#   ...
# After all layers: leaves_scratch, then tree_scratch
# ══════════════════════════════════════════════════════════════════════════════
_pv_step4_fri:
	SETUP	s1, s2, s3, s4, s5, s6, s7

	lw	s3, PF_DSIZE(s0)		# current_size
	lw	a0, PF_LOGD(s0)
	jal	fri_domain_gen
	mv	s2, a0				# current_omega

	# Compute layer0_base (quotient_ptr)
	jal	_pv_layer0_base
	mv	s1, a0				# s1 = current_evals

	# scratch_base = layer0 + 2*D*4 (total layer space ≈ 2D)
	slli	t0, s3, 3			# 2*D*4
	add	s5, s1, t0			# leaves_scratch
	slli	t0, s3, 4			# D*16 bytes for leaves
	add	s6, s5, t0			# tree_scratch

	li	s4, 0				# layer_count

_pv4_loop:
	li	t0, 2
	ble	s3, t0, _pv4_done

	srli	s7, s3, 1			# half

	# Build Merkle leaves
	mv	a0, s1				# evals
	mv	a1, s3				# current_size
	mv	a2, s5				# leaves_buf
	jal	_pv_build_leaves

	# Build Merkle tree
	mv	a0, s5				# leaves
	mv	a1, s7				# num_leaves
	mv	a2, s6				# tree buf
	jal	merkle_build			# a0 = root_ptr

	# Write root to proof and absorb into transcript
	mv	a1, a0				# root_ptr
	addi	a0, s0, PF_CURSOR		# ptr to cursor
	addi	a2, s0, PF_TS			# transcript
	jal	_pv_write_root

	# Squeeze alpha
	addi	a0, s0, PF_TS
	jal	transcript_squeeze		# a0 = alpha

	# FRI fold: from s1 (current) to s1+current_size*4 (next layer)
	slli	t0, s3, 2
	add	a4, s1, t0			# dst = next layer base
	mv	a3, a0				# alpha
	mv	a0, s1				# src
	mv	a1, s3				# size
	mv	a2, a3				# alpha
	mv	a3, s2				# omega
	# a4 already set (dst)
	jal	_pv_fri_fold

	# Advance
	slli	t0, s3, 2
	add	s1, s1, t0			# next layer
	mv	s3, s7				# size /= 2
	mv	a0, s2
	mv	a1, s2
	jal	fp_mul
	mv	s2, a0				# omega^2
	addi	s4, s4, 1

	j	_pv4_loop

_pv4_done:
	sw	s4, PF_NLAYERS(s0)
	sw	s3, PF_FPLEN(s0)

	# Write final polynomial
	lw	t0, PF_CURSOR(s0)
	li	t1, 0
1:	bge	t1, s3, 2f
	slli	t2, t1, 2
	add	t2, s1, t2
	lw	t3, 0(t2)
	sw	t3, 0(t0)
	addi	t0, t0, 4
	addi	t1, t1, 1
	j	1b
2:	sw	t0, PF_CURSOR(s0)

	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# Step 5: Query phase
# For each query: squeeze index, walk layers, write openings + Merkle proofs
# ══════════════════════════════════════════════════════════════════════════════
_pv_step5_queries:
	SETUP	s1, s2, s3, s4, s5, s6, s7

	lw	s3, PF_DSIZE(s0)		# domain_size (for scratch recompute)

	# Compute scratch bases (same as step 4)
	jal	_pv_layer0_base
	mv	s6, a0				# layer0_base
	slli	t0, s3, 3
	add	s5, s6, t0			# leaves_scratch
	slli	t0, s3, 4
	add	s7, s5, t0			# tree_scratch

	li	s4, 0				# query counter

_pv5_query:
	li	t0, NUM_QUERIES
	bge	s4, t0, _pv5_done

	# Squeeze query index
	addi	a0, s0, PF_TS
	jal	transcript_squeeze

	# Mask to half of initial domain
	lw	t0, PF_LOGD(s0)
	li	t1, 1
	sll	t1, t1, t0
	addi	t1, t1, -1
	and	a0, a0, t1
	lw	t0, PF_DSIZE(s0)
	srli	t0, t0, 1
	addi	t0, t0, -1
	and	s1, a0, t0			# s1 = leaf_idx for first layer

	# Walk FRI layers
	mv	s2, s6				# current_layer_base
	lw	s3, PF_DSIZE(s0)		# current_layer_size
	lw	t0, PF_NLAYERS(s0)

	addi	sp, sp, -4
	sw	t0, 0(sp)			# layers remaining

_pv5_layer:
	lw	t0, 0(sp)
	beqz	t0, _pv5_layer_done

	srli	t1, s3, 1			# half

	# Write f_pos, f_neg, depth
	lw	t0, PF_CURSOR(s0)
	slli	t2, s1, 2
	add	t3, s2, t2			# &evals[idx]
	lw	t4, 0(t3)			# f_pos
	sw	t4, 0(t0)
	slli	t5, t1, 2
	add	t3, t3, t5
	lw	t4, 0(t3)			# f_neg
	sw	t4, 4(t0)

	# depth = log2(half)
	mv	t4, t1
	li	t5, 0
1:	srli	t4, t4, 1
	beqz	t4, 2f
	addi	t5, t5, 1
	j	1b
2:	sw	t5, 8(t0)
	addi	t0, t0, 12
	sw	t0, PF_CURSOR(s0)

	# Save volatile state
	addi	sp, sp, -16
	sw	s1, 0(sp)			# leaf_idx
	sw	s2, 4(sp)			# layer_base
	sw	s3, 8(sp)			# layer_size
	sw	t5, 12(sp)			# depth

	# Build leaves + tree for this layer to extract Merkle proof
	mv	a0, s2				# evals
	mv	a1, s3				# size
	mv	a2, s5				# leaves_scratch
	jal	_pv_build_leaves

	lw	t1, 8(sp)
	srli	a1, t1, 1			# half = num_leaves
	mv	a0, s5
	mv	a2, s7				# tree
	jal	merkle_build

	# merkle_prove(tree, num_leaves, leaf_idx, proof_out)
	lw	t1, 8(sp)
	mv	a0, s7				# tree
	srli	a1, t1, 1			# num_leaves
	lw	a2, 0(sp)			# leaf_idx
	lw	a3, PF_CURSOR(s0)		# output directly to proof
	jal	merkle_prove

	# Advance cursor by depth * 32
	lw	t5, 12(sp)
	slli	t0, t5, 5
	lw	t1, PF_CURSOR(s0)
	add	t1, t1, t0
	sw	t1, PF_CURSOR(s0)

	# Restore + advance layer
	lw	s1, 0(sp)
	lw	s2, 4(sp)
	lw	s3, 8(sp)
	addi	sp, sp, 16

	# Next layer base
	slli	t0, s3, 2
	add	s2, s2, t0
	# Next size
	srli	s3, s3, 1
	# Next leaf_idx
	srli	t0, s3, 1
	addi	t0, t0, -1
	and	s1, s1, t0

	# Decrement layers
	lw	t0, 0(sp)
	addi	t0, t0, -1
	sw	t0, 0(sp)
	j	_pv5_layer

_pv5_layer_done:
	addi	sp, sp, 4
	addi	s4, s4, 1
	j	_pv5_query

_pv5_done:
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# Helpers (all preserve s0 = frame pointer)
# ══════════════════════════════════════════════════════════════════════════════

# _pv_copy: copy a2 words from a0 to a1
_pv_copy:
	beqz	a2, 1f
	lw	t0, 0(a0)
	sw	t0, 0(a1)
	addi	a0, a0, 4
	addi	a1, a1, 4
	addi	a2, a2, -1
	j	_pv_copy
1:	ret


# _pv_layer0_base: compute address of quotient/layer0 in work buffer
# Returns a0 = layer0_base
_pv_layer0_base:
	lw	t0, PF_WORK(s0)
	lw	t1, PF_TLEN(s0)
	slli	t1, t1, 2			# TL*4
	slli	t2, t1, 1
	add	t2, t2, t1			# 3*TL*4
	add	a0, t0, t2			# ext_base
	lw	t1, PF_DSIZE(s0)
	slli	t1, t1, 2			# D*4
	slli	t2, t1, 1
	add	t2, t2, t1			# 3*D*4
	add	a0, a0, t2			# layer0 = ext_base + 3*D*4
	ret


# _pv_eval_coset: evaluate polynomial on coset domain
# a0=coeffs, a1=trace_len, a2=domain_size, a3=out, a4=omega, a5=offset
_pv_eval_coset:
	SETUP	s1, s2, s3, s4, s5, s6

	mv	s1, a0				# coeffs
	mv	s2, a1				# trace_len
	mv	s3, a2				# domain_size
	mv	s4, a3				# out
	mv	s5, a4				# omega
	mv	s6, a5				# offset

	# Shift coefficients by offset: out[i] = coeffs[i] * offset^i
	li	a3, 0				# i
	li	a4, 1				# o_pow = 1
	addi	sp, sp, -8
	sw	zero, 0(sp)			# i
	li	t0, 1
	sw	t0, 4(sp)			# o_pow
_pec_shift:
	lw	a3, 0(sp)
	bge	a3, s2, _pec_pad
	slli	t0, a3, 2
	add	t0, s1, t0
	lw	a0, 0(t0)			# coeffs[i]
	lw	a1, 4(sp)			# o_pow
	jal	fp_mul
	lw	a3, 0(sp)
	slli	t0, a3, 2
	add	t0, s4, t0
	sw	a0, 0(t0)			# out[i]
	lw	a0, 4(sp)			# o_pow
	mv	a1, s6				# offset
	jal	fp_mul
	sw	a0, 4(sp)			# o_pow updated
	lw	a3, 0(sp)
	addi	a3, a3, 1
	sw	a3, 0(sp)
	j	_pec_shift

_pec_pad:
	lw	a3, 0(sp)
	bge	a3, s3, _pec_ntt
	slli	t0, a3, 2
	add	t0, s4, t0
	sw	zero, 0(t0)
	addi	a3, a3, 1
	sw	a3, 0(sp)
	j	_pec_pad

_pec_ntt:
	addi	sp, sp, 8
	mv	a0, s4
	mv	a1, s3
	mv	a2, s5
	jal	ntt_forward
	RETURN


# _pv_build_leaves: hash evaluation pairs into Merkle leaves
# a0=evals, a1=size, a2=leaves_buf
_pv_build_leaves:
	SETUP	s1, s2, s3, s4, s5

	mv	s1, a0				# evals
	mv	s2, a1				# size
	mv	s3, a2				# leaves
	srli	s4, s2, 1			# half
	li	s5, 0				# i

_pvbl_loop:
	bge	s5, s4, _pvbl_done

	# state = [evals[i], evals[i+half], 0×14]
	addi	sp, sp, -64
	slli	t0, s5, 2
	add	t1, s1, t0
	lw	t0, 0(t1)			# f_pos
	sw	t0, 0(sp)
	slli	t0, s4, 2
	add	t1, t1, t0
	lw	t0, 0(t1)			# f_neg
	sw	t0, 4(sp)
	li	t0, 14
	addi	t1, sp, 8
1:	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, 1b

	mv	a0, sp
	jal	poseidon2_perm

	# Copy first 8 words → leaves[i]
	slli	t0, s5, 5
	add	t0, s3, t0
	li	t1, 8
	mv	t2, sp
1:	lw	t3, 0(t2)
	sw	t3, 0(t0)
	addi	t2, t2, 4
	addi	t0, t0, 4
	addi	t1, t1, -1
	bnez	t1, 1b

	addi	sp, sp, 64
	addi	s5, s5, 1
	j	_pvbl_loop

_pvbl_done:
	RETURN


# _pv_write_root: write 8-word root to proof cursor, absorb into transcript
# a0 = ptr to PF_CURSOR field (writes cursor), a1 = root_ptr, a2 = transcript_ptr
_pv_write_root:
	SETUP	s1, s2, s3

	mv	s1, a0				# cursor_field_ptr
	mv	s2, a1				# root
	mv	s3, a2				# transcript

	lw	t0, 0(s1)			# cursor value
	li	t1, 8
1:	lw	t2, 0(s2)
	sw	t2, 0(t0)
	addi	s2, s2, 4
	addi	t0, t0, 4
	addi	t1, t1, -1
	bnez	t1, 1b
	sw	t0, 0(s1)			# update cursor

	# Absorb (root starts 32 bytes before current cursor)
	mv	a0, s3
	addi	a1, t0, -32
	li	a2, 8
	jal	transcript_absorb_n

	RETURN


# _pv_fri_fold: fold evaluation pairs into destination
# a0=src, a1=size, a2=alpha, a3=omega, a4=dst
_pv_fri_fold:
	SETUP	s1, s2, s3, s4, s5, s6

	mv	s1, a0				# src
	mv	s2, a1				# size
	mv	s3, a2				# alpha
	mv	s4, a3				# omega
	mv	s5, a4				# dst
	srli	s6, s2, 1			# half

	li	t5, 0
	addi	sp, sp, -4
	sw	zero, 0(sp)			# i

_pvff_loop:
	lw	t5, 0(sp)
	bge	t5, s6, _pvff_done

	# x = omega^i
	mv	a0, s4
	mv	a1, t5
	jal	fp_pow				# a0 = x

	# fri_fold(f_pos, f_neg, alpha, x)
	mv	a3, a0				# x
	lw	t5, 0(sp)
	slli	t0, t5, 2
	add	t1, s1, t0
	lw	a0, 0(t1)			# f_pos
	slli	t0, s6, 2
	add	t1, t1, t0
	lw	a1, 0(t1)			# f_neg
	mv	a2, s3				# alpha
	jal	fri_fold

	lw	t5, 0(sp)
	slli	t0, t5, 2
	add	t0, s5, t0
	sw	a0, 0(t0)			# dst[i] = folded

	addi	t5, t5, 1
	sw	t5, 0(sp)
	j	_pvff_loop

_pvff_done:
	addi	sp, sp, 4
	RETURN

.endm	# DEFINE_PROVER
