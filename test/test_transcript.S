# test_transcript.S — Fiat-Shamir transcript unit tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_ts_basic
	addi	sp, sp, -TS_SIZE
	mv	a0, sp
	jal	transcript_init
	mv	a0, sp
	li	a1, 42
	jal	transcript_absorb
	mv	a0, sp
	jal	transcript_squeeze
	beqz	a0, test_fail
	addi	sp, sp, TS_SIZE
	PASS_TEST

	RUN_TEST tn_ts_determ
	addi	sp, sp, -(TS_SIZE * 2)
	mv	a0, sp
	jal	transcript_init
	mv	a0, sp
	li	a1, 100
	jal	transcript_absorb
	mv	a0, sp
	li	a1, 200
	jal	transcript_absorb
	mv	a0, sp
	jal	transcript_squeeze
	mv	s0, a0
	addi	a0, sp, TS_SIZE
	jal	transcript_init
	addi	a0, sp, TS_SIZE
	li	a1, 100
	jal	transcript_absorb
	addi	a0, sp, TS_SIZE
	li	a1, 200
	jal	transcript_absorb
	addi	a0, sp, TS_SIZE
	jal	transcript_squeeze
	bne	a0, s0, test_fail
	addi	sp, sp, TS_SIZE * 2
	PASS_TEST

	RUN_TEST tn_ts_diff
	addi	sp, sp, -(TS_SIZE * 2)
	mv	a0, sp
	jal	transcript_init
	mv	a0, sp
	li	a1, 1
	jal	transcript_absorb
	mv	a0, sp
	jal	transcript_squeeze
	mv	s0, a0
	addi	a0, sp, TS_SIZE
	jal	transcript_init
	addi	a0, sp, TS_SIZE
	li	a1, 2
	jal	transcript_absorb
	addi	a0, sp, TS_SIZE
	jal	transcript_squeeze
	beq	a0, s0, test_fail
	addi	sp, sp, TS_SIZE * 2
	PASS_TEST

	RUN_TEST tn_ts_multi
	addi	sp, sp, -TS_SIZE
	mv	a0, sp
	jal	transcript_init
	mv	a0, sp
	li	a1, 42
	jal	transcript_absorb
	mv	a0, sp
	jal	transcript_squeeze
	mv	s0, a0
	mv	a0, sp
	jal	transcript_squeeze
	beq	a0, s0, test_fail
	addi	sp, sp, TS_SIZE
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

	.balign 4
tn_ts_basic:	.asciz	"transcript basic    "
tn_ts_determ:	.asciz	"transcript determ   "
tn_ts_diff:	.asciz	"transcript diff     "
tn_ts_multi:	.asciz	"transcript multi sq "

_gp_base:
