# test_stark.S — STARK verifier and prover round-trip tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_stark_verify
	LOAD_ADDRESS	a0, _test_stark_proof
	jal	stark_verify
	bnez	a0, test_fail
	PASS_TEST

	RUN_TEST tn_prover_rt
	# Prove a+b=c with trace_len=4, then verify the proof
	# Trace: a=[1,4,7,10] b=[2,5,8,11] c=[3,9,15,21]
	li	t0, 0x60000
	add	t1, gp, t0
	li	t2, 1
	sw	t2, 0(t1)
	li	t2, 4
	sw	t2, 4(t1)
	li	t2, 7
	sw	t2, 8(t1)
	li	t2, 10
	sw	t2, 12(t1)
	li	t2, 2
	sw	t2, 16(t1)
	li	t2, 5
	sw	t2, 20(t1)
	li	t2, 8
	sw	t2, 24(t1)
	li	t2, 11
	sw	t2, 28(t1)
	li	t2, 3
	sw	t2, 32(t1)
	li	t2, 9
	sw	t2, 36(t1)
	li	t2, 15
	sw	t2, 40(t1)
	li	t2, 21
	sw	t2, 44(t1)
	mv	a0, t1
	li	a1, 4
	li	t0, 0x60100
	add	a2, gp, t0
	li	t0, 0x62100
	add	a3, gp, t0
	jal	stark_prove
	blez	a0, test_fail
	li	t0, 0x62100
	add	a0, gp, t0
	jal	stark_verify
	bnez	a0, test_fail
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

	.balign 4
tn_stark_verify:	.asciz	"stark verify proof  "
tn_prover_rt:		.asciz	"prover round-trip   "

_test_stark_proof:
	.incbin "tmp/test_proof.bin"
	.balign 4

_gp_base:
