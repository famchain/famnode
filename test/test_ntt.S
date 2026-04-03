# test_ntt.S — NTT unit tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_ntt_identity
	addi	sp, sp, -16
	li	t0, 1
	sw	t0, 0(sp)
	sw	zero, 4(sp)
	sw	zero, 8(sp)
	sw	zero, 12(sp)
	mv	a0, sp
	li	a1, 4
	li	a2, 0x67055c21		# omega_4
	jal	ntt_forward
	lw	t0, 0(sp)
	li	t1, 1
	bne	t0, t1, test_fail
	lw	t0, 4(sp)
	bne	t0, t1, test_fail
	lw	t0, 8(sp)
	bne	t0, t1, test_fail
	lw	t0, 12(sp)
	bne	t0, t1, test_fail
	addi	sp, sp, 16
	PASS_TEST

	RUN_TEST tn_ntt_fwd4
	addi	sp, sp, -16
	li	t0, 1
	sw	t0, 0(sp)
	li	t0, 2
	sw	t0, 4(sp)
	li	t0, 3
	sw	t0, 8(sp)
	li	t0, 4
	sw	t0, 12(sp)
	mv	a0, sp
	li	a1, 4
	li	a2, 0x67055c21
	jal	ntt_forward
	lw	t0, 0(sp)
	li	t1, 10
	bne	t0, t1, test_fail
	lw	t0, 4(sp)
	li	t1, 0x21f547be
	bne	t0, t1, test_fail
	lw	t0, 8(sp)
	li	t1, 0x77ffffff
	bne	t0, t1, test_fail
	lw	t0, 12(sp)
	li	t1, 0x560ab83f
	bne	t0, t1, test_fail
	addi	sp, sp, 16
	PASS_TEST

	RUN_TEST tn_ntt_rt4
	addi	sp, sp, -16
	li	t0, 1
	sw	t0, 0(sp)
	li	t0, 2
	sw	t0, 4(sp)
	li	t0, 3
	sw	t0, 8(sp)
	li	t0, 4
	sw	t0, 12(sp)
	mv	a0, sp
	li	a1, 4
	li	a2, 0x67055c21
	jal	ntt_forward
	mv	a0, sp
	li	a1, 4
	li	a2, 0x67055c21
	jal	ntt_inverse
	lw	t0, 0(sp)
	li	t1, 1
	bne	t0, t1, test_fail
	lw	t0, 4(sp)
	li	t1, 2
	bne	t0, t1, test_fail
	lw	t0, 8(sp)
	li	t1, 3
	bne	t0, t1, test_fail
	lw	t0, 12(sp)
	li	t1, 4
	bne	t0, t1, test_fail
	addi	sp, sp, 16
	PASS_TEST

	RUN_TEST tn_ntt_rt8
	addi	sp, sp, -32
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
	mv	a0, sp
	li	a1, 8
	li	a2, 0x5ee99486		# omega_8
	jal	ntt_forward
	mv	a0, sp
	li	a1, 8
	li	a2, 0x5ee99486
	jal	ntt_inverse
	li	t1, 1
	lw	t0, 0(sp)
	bne	t0, t1, test_fail
	li	t1, 2
	lw	t0, 4(sp)
	bne	t0, t1, test_fail
	li	t1, 3
	lw	t0, 8(sp)
	bne	t0, t1, test_fail
	li	t1, 4
	lw	t0, 12(sp)
	bne	t0, t1, test_fail
	li	t1, 5
	lw	t0, 16(sp)
	bne	t0, t1, test_fail
	li	t1, 6
	lw	t0, 20(sp)
	bne	t0, t1, test_fail
	li	t1, 7
	lw	t0, 24(sp)
	bne	t0, t1, test_fail
	li	t1, 8
	lw	t0, 28(sp)
	bne	t0, t1, test_fail
	addi	sp, sp, 32
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

	.balign 4
tn_ntt_identity:	.asciz	"ntt identity        "
tn_ntt_fwd4:		.asciz	"ntt forward len=4   "
tn_ntt_rt4:		.asciz	"ntt round-trip 4    "
tn_ntt_rt8:		.asciz	"ntt round-trip 8    "

_gp_base:
