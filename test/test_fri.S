# test_fri.S — FRI unit tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_fri_domgen
	li	a0, 10
	jal	fri_domain_gen
	li	t0, 0x145e952d
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_fri_evalpt
	li	a0, 0x145e952d		# gen10
	li	a1, 3			# index
	li	a2, 7			# offset
	jal	fri_eval_point
	li	t0, 0x736c98ee
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_fri_fold1
	# fri_fold(6, 2, 0, 1) = 4 (alpha=0 → just even part)
	li	a0, 6
	li	a1, 2
	li	a2, 0
	li	a3, 1
	jal	fri_fold
	li	t0, 4
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_fri_fold2
	# fri_fold(10, 20, 3, 5) = 12
	li	a0, 10
	li	a1, 20
	li	a2, 3
	li	a3, 5
	jal	fri_fold
	li	t0, 12
	bne	a0, t0, test_fail
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

	.balign 4
tn_fri_domgen:	.asciz	"fri domain gen      "
tn_fri_evalpt:	.asciz	"fri eval point      "
tn_fri_fold1:	.asciz	"fri fold (alpha=0)  "
tn_fri_fold2:	.asciz	"fri fold (alpha=3)  "

_gp_base:
