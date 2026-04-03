# test_field.S — BabyBear field arithmetic unit tests

.include "lib_includes.inc"
.include "test.inc"

.equ	FP_P,	0x78000001

TEST_INIT

	RUN_TEST tn_fp_add
	li	a0, 1
	li	a1, 2
	jal	fp_add
	li	t0, 3
	bne	a0, t0, test_fail
	# wrap: (p-1) + 1 = 0
	li	a0, FP_P - 1
	li	a1, 1
	jal	fp_add
	bnez	a0, test_fail
	PASS_TEST

	RUN_TEST tn_fp_sub
	li	a0, 5
	li	a1, 3
	jal	fp_sub
	li	t0, 2
	bne	a0, t0, test_fail
	# underflow: 0 - 1 = p-1
	li	a0, 0
	li	a1, 1
	jal	fp_sub
	li	t0, FP_P - 1
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_fp_mul
	li	a0, 3
	li	a1, 7
	jal	fp_mul
	li	t0, 21
	bne	a0, t0, test_fail
	# large: (p-1) * 2 = p-2
	li	a0, FP_P - 1
	li	a1, 2
	jal	fp_mul
	li	t0, FP_P - 2
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_fp_inv
	# inv(1) = 1
	li	a0, 1
	jal	fp_inv
	li	t0, 1
	bne	a0, t0, test_fail
	# 42 * inv(42) = 1
	li	a0, 42
	jal	fp_inv
	mv	a1, a0
	li	a0, 42
	jal	fp_mul
	li	t0, 1
	bne	a0, t0, test_fail
	# (p-1) * inv(p-1) = 1
	li	a0, FP_P - 1
	jal	fp_inv
	mv	a1, a0
	li	a0, FP_P - 1
	jal	fp_mul
	li	t0, 1
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_fp_pow
	# 31^10 mod p = 0x5cde7c78
	li	a0, 31
	li	a1, 10
	jal	fp_pow
	li	t0, 0x5cde7c78
	bne	a0, t0, test_fail
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

# ══════════════════════════════════════════════════════════════════════════════
# Test names
# ══════════════════════════════════════════════════════════════════════════════
	.balign 4

tn_fp_add:	.asciz	"fp_add              "
tn_fp_sub:	.asciz	"fp_sub              "
tn_fp_mul:	.asciz	"fp_mul              "
tn_fp_inv:	.asciz	"fp_inv              "
tn_fp_pow:	.asciz	"fp_pow              "

_gp_base:
