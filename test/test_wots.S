# test_wots.S — WOTS+ signature unit tests

.include "lib_includes.inc"
.include "test.inc"

.equ	SK_OFF,		0
.equ	PK_OFF,		576
.equ	SIG_OFF,	1152
.equ	MSG_OFF,	1728
.equ	SEED_OFF,	1760

TEST_INIT

	# Setup seed (0xAA * 32)
	li		t0, SEED_OFF
	add		t0, gp, t0
	li		t1, 0xAAAAAAAA
	.set	_i, 0
	.rept	8
	sw		t1, (_i * 4)(t0)
	.set	_i, _i + 1
	.endr

	RUN_TEST tn_wots_hash
	LOAD_ADDRESS	a0, tv_wots_msg_text
	li		a1, 21
	li		t0, MSG_OFF
	add		a2, gp, t0
	jal		blake2s
	li		t0, MSG_OFF
	add		a0, gp, t0
	LOAD_ADDRESS	t0, tv_wots_msg_hash
	jal		check_hash_32
	PASS_TEST

	RUN_TEST tn_wots_keygen
	li		t0, SEED_OFF
	add		a0, gp, t0
	li		t0, PK_OFF
	add		a1, gp, t0
	li		t0, SK_OFF
	add		a2, gp, t0
	jal		wots_keyfrom
	mv		a0, gp
	LOAD_ADDRESS	t0, tv_wots_sk0
	jal		check_hash_32
	PASS_TEST

	RUN_TEST tn_wots_sign
	li		t0, SK_OFF
	add		a0, gp, t0
	li		t0, MSG_OFF
	add		a1, gp, t0
	li		t0, SIG_OFF
	add		a2, gp, t0
	jal		wots_sign
	PASS_TEST

	RUN_TEST tn_wots_verify
	li		t0, PK_OFF
	add		a0, gp, t0
	li		t0, SIG_OFF
	add		a1, gp, t0
	li		t0, MSG_OFF
	add		a2, gp, t0
	jal		wots_verify
	bnez		a0, test_fail
	PASS_TEST

	RUN_TEST tn_wots_tmsg
	li		t0, MSG_OFF
	add		a0, gp, t0
	li		a1, 32
	jal		check_tamper
	PASS_TEST

	RUN_TEST tn_wots_tsig
	li		t0, SIG_OFF
	add		a0, gp, t0
	li		a1, 32
	jal		check_tamper
	PASS_TEST

	RUN_TEST tn_wots_tpk
	li		t0, PK_OFF
	add		a0, gp, t0
	li		a1, 32
	jal		check_tamper
	PASS_TEST

TEST_EXIT

# ──────────────────────────────────────────────────────────────────────────────
# Test-specific helpers
# ──────────────────────────────────────────────────────────────────────────────

# check_tamper: flip bit 0 of each byte in a0[0..a1-1], verify wots_verify rejects
check_tamper:
	SETUP	s0, s1, s2
	mv	s0, a0
	mv	s1, a1
	li	s2, 0
1:	bge	s2, s1, 2f
	add	t0, s0, s2
	lbu	t1, 0(t0)
	xori	t1, t1, 1
	sb	t1, 0(t0)
	li	t0, PK_OFF
	add	a0, gp, t0
	li	t0, SIG_OFF
	add	a1, gp, t0
	li	t0, MSG_OFF
	add	a2, gp, t0
	jal	wots_verify
	beqz	a0, test_fail
	add	t0, s0, s2
	lbu	t1, 0(t0)
	xori	t1, t1, 1
	sb	t1, 0(t0)
	addi	s2, s2, 1
	j	1b
2:	RETURN

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

# ══════════════════════════════════════════════════════════════════════════════
# Test vectors
# ══════════════════════════════════════════════════════════════════════════════
	.balign 4

tn_wots_hash:	.asciz	"wots msg hash       "
tn_wots_keygen:	.asciz	"wots keygen         "
tn_wots_sign:	.asciz	"wots sign           "
tn_wots_verify:	.asciz	"wots verify         "
tn_wots_tmsg:	.asciz	"wots tampered msg   "
tn_wots_tsig:	.asciz	"wots tampered sig   "
tn_wots_tpk:	.asciz	"wots tampered pk    "

tv_wots_msg_text:
	.ascii	"test message for wots"
	.balign 4
tv_wots_msg_hash:
	.word	0x124F6752, 0xCE245256, 0xF7351839, 0xE575CED0
	.word	0x5FD2F416, 0x266C31B0, 0xB1FA94D6, 0xDE134521
tv_wots_sk0:
	.word	0xA140DE27, 0x4B1070DA, 0xCEB4C263, 0x74D48709
	.word	0xB0ADA4FB, 0x3CC780CA, 0x42923694, 0x116E997A

_gp_base:
