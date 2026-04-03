# test_blake2s.S — Blake2s unit tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_b2s_empty
	LOAD_ADDRESS	a0, tv_b2s_empty
	li		a1, 0
	addi		sp, sp, -32
	mv		a2, sp
	jal		blake2s
	LOAD_ADDRESS	t0, tv_b2s_empty_hash
	mv		a0, sp
	jal		check_hash_32
	addi		sp, sp, 32
	PASS_TEST

	RUN_TEST tn_b2s_abc
	LOAD_ADDRESS	a0, tv_b2s_abc
	li		a1, 3
	addi		sp, sp, -32
	mv		a2, sp
	jal		blake2s
	LOAD_ADDRESS	t0, tv_b2s_abc_hash
	mv		a0, sp
	jal		check_hash_32
	addi		sp, sp, 32
	PASS_TEST

	RUN_TEST tn_b2s_64
	LOAD_ADDRESS	a0, tv_b2s_64
	li		a1, 64
	addi		sp, sp, -32
	mv		a2, sp
	jal		blake2s
	LOAD_ADDRESS	t0, tv_b2s_64_hash
	mv		a0, sp
	jal		check_hash_32
	addi		sp, sp, 32
	PASS_TEST

	RUN_TEST tn_b2s_65
	LOAD_ADDRESS	a0, tv_b2s_65
	li		a1, 65
	addi		sp, sp, -32
	mv		a2, sp
	jal		blake2s
	LOAD_ADDRESS	t0, tv_b2s_65_hash
	mv		a0, sp
	jal		check_hash_32
	addi		sp, sp, 32
	PASS_TEST

	RUN_TEST tn_b2s_opt
	LOAD_ADDRESS	a0, tv_b2s_64
	addi		sp, sp, -32
	mv		a1, sp
	jal		blake2s_64
	LOAD_ADDRESS	t0, tv_b2s_64_hash
	mv		a0, sp
	jal		check_hash_32
	addi		sp, sp, 32
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

# ══════════════════════════════════════════════════════════════════════════════
# Test vectors
# ══════════════════════════════════════════════════════════════════════════════
	.balign 4

tn_b2s_empty:	.asciz	"blake2s empty       "
tn_b2s_abc:	.asciz	"blake2s abc         "
tn_b2s_64:	.asciz	"blake2s 64 bytes    "
tn_b2s_65:	.asciz	"blake2s 65 bytes    "
tn_b2s_opt:	.asciz	"blake2s_64          "

tv_b2s_empty:
	.byte	0
tv_b2s_empty_hash:
	.word	0x307A2169, 0x94809079, 0xD02111E1, 0x7C4A3542
	.word	0x48B6551F, 0x1EA5A12C, 0xFD0D251B, 0xF9EED01E

tv_b2s_abc:
	.ascii	"abc"
	.balign 4
tv_b2s_abc_hash:
	.word	0x8C5E8C50, 0xE2147C32, 0xA32BA7E1, 0x2F45EB4E
	.word	0x208B4537, 0x293AD69E, 0x4C9B994D, 0x82596786

tv_b2s_64:
	.byte  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15
	.byte 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	.byte 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
	.byte 48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
tv_b2s_64_hash:
	.word	0x8B4EF356, 0x907E5596, 0x524BF2C1, 0x519DC8D0
	.word	0x1BCF6A08, 0xCF34F600, 0x3392DE1D, 0x3EAAEAB8

tv_b2s_65:
	.byte  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15
	.byte 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	.byte 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
	.byte 48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
	.byte 64
	.balign 4
tv_b2s_65_hash:
	.word	0x94EE531B, 0x4B4EF3AA, 0xDE489D15, 0x067F2C35
	.word	0x0EA4D061, 0x0B5AF9DF, 0x09B43916, 0x7244970E

_gp_base:
