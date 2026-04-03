# test_air.S — AIR constraint unit tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_air_add_ok
	li	a0, 5
	li	a1, 7
	li	a2, 12
	jal	air_eval_add
	bnez	a0, test_fail
	PASS_TEST

	RUN_TEST tn_air_add_bad
	li	a0, 5
	li	a1, 7
	li	a2, 15
	jal	air_eval_add
	li	t0, 3
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_air_vanish
	# Z(3, log=3, offset=1) = 3^8 - 1 = 6560
	li	a0, 3
	li	a1, 3
	li	a2, 1
	jal	air_eval_vanishing
	li	t0, 6560
	bne	a0, t0, test_fail
	# Z(5, log=2, offset=2) = 5^4 - 2^4 = 609
	li	a0, 5
	li	a1, 2
	li	a2, 2
	jal	air_eval_vanishing
	li	t0, 609
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_air_quot
	# 10 == 2 * 5 → valid
	li	a0, 10
	li	a1, 5
	li	a2, 2
	jal	air_check_quotient
	bnez	a0, test_fail
	# 10 != 3 * 5 → invalid
	li	a0, 10
	li	a1, 5
	li	a2, 3
	jal	air_check_quotient
	li	t0, -1
	bne	a0, t0, test_fail
	PASS_TEST

	RUN_TEST tn_air_combine
	addi	sp, sp, -12
	li	t0, 3
	sw	t0, 0(sp)
	li	t0, 7
	sw	t0, 4(sp)
	li	t0, 11
	sw	t0, 8(sp)
	mv	a0, sp
	li	a1, 3
	li	a2, 2
	jal	air_combine
	addi	sp, sp, 12
	li	t0, 61
	bne	a0, t0, test_fail
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

	.balign 4
tn_air_add_ok:	.asciz	"air add (valid)     "
tn_air_add_bad:	.asciz	"air add (invalid)   "
tn_air_vanish:	.asciz	"air vanishing poly  "
tn_air_quot:	.asciz	"air quotient check  "
tn_air_combine:	.asciz	"air combine (Horner)"

_gp_base:
