# merkle.inc — Poseidon2-based Merkle tree for RISC-V 32-bit
#
# Digests are 8 BabyBear field elements (32 bytes).
# Internal nodes: poseidon2_perm([left || right]) → first 8 elements.
#
# Usage:
#   .include "macros.inc"
#   .include "field.inc"
#   .include "poseidon2.inc"
#   .include "merkle.inc"
#   ...
#   DEFINE_MERKLE
#
# Public labels:
#   merkle_hash2(a0=left_ptr, a1=right_ptr, a2=out_ptr)
#       Hash two 32-byte digests into one via Poseidon2 compression.
#
#   merkle_build(a0=leaves_ptr, a1=num_leaves, a2=tree_ptr)
#       Build a complete binary Merkle tree. num_leaves must be power of 2.
#       tree_ptr must hold 2*num_leaves nodes of 32 bytes each.
#       Tree layout: tree[1]=root, tree[2i]/tree[2i+1]=children of tree[i].
#       Leaves stored at tree[num_leaves..2*num_leaves-1].
#       Returns: a0 = ptr to root (tree_ptr + 32)
#
#   merkle_prove(a0=tree_ptr, a1=num_leaves, a2=leaf_index, a3=proof_ptr)
#       Generate Merkle proof (array of sibling digests from leaf to root).
#       Proof length = log2(num_leaves) digests.
#       Returns: a0 = proof length (number of 32-byte siblings)
#
#   merkle_verify(a0=root_ptr, a1=leaf_ptr, a2=leaf_index, a3=proof_ptr)
#       Verify a Merkle proof. Additional arg: depth at 0(sp).
#       Returns: a0 = 0 if valid, -1 if invalid
#
# Requires: poseidon2_perm from poseidon2.inc

.macro DEFINE_MERKLE

# ══════════════════════════════════════════════════════════════════════════════
# merkle_hash2: compress two 32-byte digests into one
# a0 = left_ptr (8 field elements)
# a1 = right_ptr (8 field elements)
# a2 = out_ptr (8 field elements)
# ══════════════════════════════════════════════════════════════════════════════
merkle_hash2:
	SETUP	s0, s1

	mv	s0, a2				# save out_ptr
	# Build state on stack: [left[0..7], right[0..7]]
	addi	sp, sp, -64
	mv	s1, sp

	# Copy left → state[0..7]
	lw	t0, 0(a0)
	sw	t0, 0(s1)
	lw	t0, 4(a0)
	sw	t0, 4(s1)
	lw	t0, 8(a0)
	sw	t0, 8(s1)
	lw	t0, 12(a0)
	sw	t0, 12(s1)
	lw	t0, 16(a0)
	sw	t0, 16(s1)
	lw	t0, 20(a0)
	sw	t0, 20(s1)
	lw	t0, 24(a0)
	sw	t0, 24(s1)
	lw	t0, 28(a0)
	sw	t0, 28(s1)

	# Copy right → state[8..15]
	lw	t0, 0(a1)
	sw	t0, 32(s1)
	lw	t0, 4(a1)
	sw	t0, 36(s1)
	lw	t0, 8(a1)
	sw	t0, 40(s1)
	lw	t0, 12(a1)
	sw	t0, 44(s1)
	lw	t0, 16(a1)
	sw	t0, 48(s1)
	lw	t0, 20(a1)
	sw	t0, 52(s1)
	lw	t0, 24(a1)
	sw	t0, 56(s1)
	lw	t0, 28(a1)
	sw	t0, 60(s1)

	# Permute
	mv	a0, s1
	jal	poseidon2_perm

	# Copy state[0..7] → output
	lw	t0, 0(s1)
	sw	t0, 0(s0)
	lw	t0, 4(s1)
	sw	t0, 4(s0)
	lw	t0, 8(s1)
	sw	t0, 8(s0)
	lw	t0, 12(s1)
	sw	t0, 12(s0)
	lw	t0, 16(s1)
	sw	t0, 16(s0)
	lw	t0, 20(s1)
	sw	t0, 20(s0)
	lw	t0, 24(s1)
	sw	t0, 24(s0)
	lw	t0, 28(s1)
	sw	t0, 28(s0)

	addi	sp, sp, 64
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# merkle_build: build complete binary Merkle tree
# a0 = leaves_ptr (array of 32-byte digests)
# a1 = num_leaves (must be power of 2)
# a2 = tree_ptr (must hold 2 * num_leaves * 32 bytes)
# Returns: a0 = ptr to root (tree_ptr + 32)
# ══════════════════════════════════════════════════════════════════════════════
merkle_build:
	SETUP	s0, s1, s2

	mv	s0, a0				# leaves
	mv	s1, a1				# num_leaves
	mv	s2, a2				# tree

	# Copy leaves into tree[num_leaves..2*num_leaves-1]
	slli	t0, s1, 5			# num_leaves * 32 = byte offset to leaf region
	add	t1, s2, t0			# &tree[num_leaves]
	mv	t2, s0				# source
	slli	t3, s1, 5			# total leaf bytes
	add	t3, t2, t3			# end of source
_mk_copy_leaves:
	bgeu	t2, t3, _mk_build
	lw	t4, 0(t2)
	sw	t4, 0(t1)
	addi	t2, t2, 4
	addi	t1, t1, 4
	j	_mk_copy_leaves

_mk_build:
	# Build internal nodes: for i = num_leaves-1 down to 1
	# tree[i] = merkle_hash2(tree[2i], tree[2i+1])
	addi	s1, s1, -1			# i = num_leaves - 1
_mk_loop:
	beqz	s1, _mk_done
	# &tree[2i] = tree + 2*i*32 = tree + i*64
	slli	t0, s1, 6			# i * 64
	add	a0, s2, t0			# &tree[2i] (left child)
	addi	a1, a0, 32			# &tree[2i+1] (right child)
	slli	t0, s1, 5			# i * 32
	add	a2, s2, t0			# &tree[i] (output)
	jal	merkle_hash2
	addi	s1, s1, -1
	j	_mk_loop

_mk_done:
	addi	a0, s2, 32			# return ptr to tree[1] = root
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# merkle_prove: generate proof for a leaf
# a0 = tree_ptr
# a1 = num_leaves (power of 2)
# a2 = leaf_index (0-based)
# a3 = proof_ptr (output: array of 32-byte sibling digests)
# Returns: a0 = proof length (log2(num_leaves))
# ══════════════════════════════════════════════════════════════════════════════
merkle_prove:
	SETUP	s0, s1, s2, s3

	mv	s0, a0				# tree
	mv	s2, a3				# proof output
	add	s1, a1, a2			# node = num_leaves + leaf_index
	li	s3, 0				# proof length

_mp_loop:
	li	t0, 1
	ble	s1, t0, _mp_done		# reached root

	# Sibling = node ^ 1
	xori	t0, s1, 1
	slli	t0, t0, 5			# sibling * 32
	add	t0, s0, t0			# &tree[sibling]

	# Copy sibling to proof
	mv	t1, s2
	lw	t2, 0(t0)
	sw	t2, 0(t1)
	lw	t2, 4(t0)
	sw	t2, 4(t1)
	lw	t2, 8(t0)
	sw	t2, 8(t1)
	lw	t2, 12(t0)
	sw	t2, 12(t1)
	lw	t2, 16(t0)
	sw	t2, 16(t1)
	lw	t2, 20(t0)
	sw	t2, 20(t1)
	lw	t2, 24(t0)
	sw	t2, 24(t1)
	lw	t2, 28(t0)
	sw	t2, 28(t1)

	addi	s2, s2, 32			# next proof slot
	addi	s3, s3, 1
	srli	s1, s1, 1			# parent = node / 2
	j	_mp_loop

_mp_done:
	mv	a0, s3				# return proof length
	RETURN


# ══════════════════════════════════════════════════════════════════════════════
# merkle_verify: verify a Merkle proof
# a0 = root_ptr (32 bytes)
# a1 = leaf_ptr (32 bytes)
# a2 = leaf_index (0-based)
# a3 = proof_ptr (array of 32-byte siblings)
# Stack arg: 0(sp) = depth (number of proof elements)
# Returns: a0 = 0 if valid, -1 if invalid
# ══════════════════════════════════════════════════════════════════════════════
merkle_verify:
	SETUP	s0, s1, s2, s3, s4

	mv	s0, a0				# root
	mv	s1, a1				# leaf (current hash)
	mv	s2, a2				# index
	mv	s3, a3				# proof
	lw	s4, 32(sp)			# depth (SETUP: ra+s0..s4 = 6 words → 32 bytes)

	# Allocate working buffer for current hash (32 bytes)
	addi	sp, sp, -32
	# Copy leaf into working buffer
	mv	t0, sp
	lw	t1, 0(s1)
	sw	t1, 0(t0)
	lw	t1, 4(s1)
	sw	t1, 4(t0)
	lw	t1, 8(s1)
	sw	t1, 8(t0)
	lw	t1, 12(s1)
	sw	t1, 12(t0)
	lw	t1, 16(s1)
	sw	t1, 16(t0)
	lw	t1, 20(s1)
	sw	t1, 20(t0)
	lw	t1, 24(s1)
	sw	t1, 24(t0)
	lw	t1, 28(s1)
	sw	t1, 28(t0)
	mv	s1, sp				# s1 = current hash ptr

_mv_loop:
	beqz	s4, _mv_check
	# If index bit 0 is 0: hash(current, sibling)
	# If index bit 0 is 1: hash(sibling, current)
	andi	t0, s2, 1
	bnez	t0, _mv_right
	# current is left, sibling is right
	mv	a0, s1				# left = current
	mv	a1, s3				# right = sibling
	j	_mv_hash
_mv_right:
	# sibling is left, current is right
	mv	a0, s3				# left = sibling
	mv	a1, s1				# right = current
_mv_hash:
	mv	a2, s1				# output = current (in-place)
	jal	merkle_hash2
	addi	s3, s3, 32			# next proof element
	srli	s2, s2, 1			# index >>= 1
	addi	s4, s4, -1
	j	_mv_loop

_mv_check:
	# Compare current hash with root
	li	t2, 8
	mv	t0, s1				# computed root
	mv	t1, s0				# expected root
_mv_cmp:
	beqz	t2, _mv_valid
	lw	t3, 0(t0)
	lw	t4, 0(t1)
	bne	t3, t4, _mv_invalid
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	j	_mv_cmp

_mv_valid:
	li	a0, 0
	j	_mv_ret

_mv_invalid:
	li	a0, -1
_mv_ret:
	addi	sp, sp, 32
	RETURN

.endm	# DEFINE_MERKLE
