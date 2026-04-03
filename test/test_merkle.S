# test_merkle.S — Poseidon2 Merkle tree unit tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_mk_build
	# Build a tree with 4 leaves, verify root is non-zero
	addi	sp, sp, -384		# 128 (leaves) + 256 (tree)
	mv	t0, sp
	li	t1, 96			# zero 384 bytes = 96 words
_mkt_zero:
	sw	zero, 0(t0)
	addi	t0, t0, 4
	addi	t1, t1, -1
	bnez	t1, _mkt_zero
	li	t0, 1
	sw	t0, 0(sp)		# leaf[0][0] = 1
	li	t0, 2
	sw	t0, 32(sp)		# leaf[1][0] = 2
	li	t0, 3
	sw	t0, 64(sp)		# leaf[2][0] = 3
	li	t0, 4
	sw	t0, 96(sp)		# leaf[3][0] = 4
	mv	a0, sp			# leaves
	li	a1, 4			# num_leaves
	addi	a2, sp, 128		# tree (after leaves)
	jal	merkle_build
	lw	t0, 0(a0)
	beqz	t0, test_fail
	PASS_TEST

	RUN_TEST tn_mk_prove
	addi	a0, sp, 128		# tree
	li	a1, 4
	li	a2, 2			# leaf_index
	addi	sp, sp, -64
	mv	a3, sp			# proof
	jal	merkle_prove
	li	t0, 2			# expect depth 2
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_mk_verify
	addi	a0, sp, 64 + 128 + 32	# root = tree_base + 32
	addi	a1, sp, 64 + 64		# leaf[2]
	li	a2, 2
	mv	a3, sp			# proof
	addi	sp, sp, -4
	li	t0, 2
	sw	t0, 0(sp)		# depth = 2
	jal	merkle_verify
	addi	sp, sp, 4
	bnez	a0, test_fail
	PASS_TEST

	RUN_TEST tn_mk_tamper
	addi	t0, sp, 64 + 64	# leaf[2]
	lw	t1, 0(t0)
	xori	t1, t1, 1
	sw	t1, 0(t0)
	addi	a0, sp, 64 + 128 + 32	# root
	addi	a1, sp, 64 + 64		# tampered leaf
	li	a2, 2
	mv	a3, sp			# proof
	addi	sp, sp, -4
	li	t0, 2
	sw	t0, 0(sp)
	jal	merkle_verify
	addi	sp, sp, 4
	beqz	a0, test_fail		# should return -1
	# Restore leaf
	addi	t0, sp, 64 + 64
	lw	t1, 0(t0)
	xori	t1, t1, 1
	sw	t1, 0(t0)
	addi	sp, sp, 64 + 384	# cleanup
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

	.balign 4
tn_mk_build:	.asciz	"merkle build        "
tn_mk_prove:	.asciz	"merkle prove        "
tn_mk_verify:	.asciz	"merkle verify       "
tn_mk_tamper:	.asciz	"merkle tamper reject"

_gp_base:
