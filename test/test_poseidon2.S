# test_poseidon2.S — Poseidon2 hash unit tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_p2_perm
	# Test permutation against Plonky3 test vector
	addi	sp, sp, -64
	LOAD_ADDRESS	t0, _p2_tv_input
	mv	t1, sp
	li	t2, 16
_p2t_load:
	lw	t3, 0(t0)
	sw	t3, 0(t1)
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	bnez	t2, _p2t_load
	mv	a0, sp
	jal	poseidon2_perm
	# Compare against expected output
	LOAD_ADDRESS	t0, _p2_tv_output
	mv	t1, sp
	li	t2, 16
_p2t_check:
	beqz	t2, _p2t_ok
	lw	t3, 0(t0)
	lw	t4, 0(t1)
	bne	t3, t4, test_fail
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	j	_p2t_check
_p2t_ok:
	addi	sp, sp, 64
	PASS_TEST

	RUN_TEST tn_p2_determ
	# Same input → same output (deterministic)
	addi	sp, sp, -128		# two 64-byte states
	# Init both to [1,0,...,0]
	li	t0, 32
	mv	t1, sp
_p2t_init2:
	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, _p2t_init2
	li	t0, 1
	sw	t0, 0(sp)
	sw	t0, 64(sp)
	# Permute both
	mv	a0, sp
	jal	poseidon2_perm
	addi	a0, sp, 64
	jal	poseidon2_perm
	# Compare
	li	t2, 16
	mv	t0, sp
	addi	t1, sp, 64
_p2t_cmp:
	beqz	t2, _p2t_det_ok
	lw	t3, 0(t0)
	lw	t4, 0(t1)
	bne	t3, t4, test_fail
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	j	_p2t_cmp
_p2t_det_ok:
	addi	sp, sp, 128
	PASS_TEST

	RUN_TEST tn_p2_hash
	# Hash [1,2,3,4,5,6,7,8] → non-zero 8-element output
	addi	sp, sp, -64		# 32 bytes input + 32 bytes output
	li	t0, 1
	sw	t0, 0(sp)
	li	t0, 2
	sw	t0, 4(sp)
	li	t0, 3
	sw	t0, 8(sp)
	li	t0, 4
	sw	t0, 12(sp)
	li	t0, 5
	sw	t0, 16(sp)
	li	t0, 6
	sw	t0, 20(sp)
	li	t0, 7
	sw	t0, 24(sp)
	li	t0, 8
	sw	t0, 28(sp)
	mv	a0, sp			# input
	li	a1, 8			# num_elements
	addi	a2, sp, 32		# output
	jal	poseidon2_hash
	# Check output non-zero
	lw	t0, 32(sp)
	beqz	t0, test_fail
	addi	sp, sp, 64
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

# ══════════════════════════════════════════════════════════════════════════════
# Test vectors
# ══════════════════════════════════════════════════════════════════════════════
	.balign 4

tn_p2_perm:	.asciz	"poseidon2 perm      "
tn_p2_determ:	.asciz	"poseidon2 determinism"
tn_p2_hash:	.asciz	"poseidon2 hash      "

_p2_tv_input:
	.word	894848333, 1437655012, 1200606629, 1690012884
	.word	71131202, 1749206695, 1717947831, 120589055
	.word	19776022, 42382981, 1831865506, 724844064
	.word	171220207, 1299207443, 227047920, 1783754913

_p2_tv_output:
	.word	516096821, 90309867, 1101817252, 1660784290
	.word	360715097, 1789519026, 1788910906, 563338433
	.word	319524748, 1741414159, 1650859320, 894311162
	.word	1121347488, 1692793758, 1052633829, 1344246938

_gp_base:
