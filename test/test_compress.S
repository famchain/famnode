# test_compress.S — LZ77+Huffman compression unit tests

.include "lib_includes.inc"
.include "test.inc"

TEST_INIT

	RUN_TEST tn_cz_rt
	LOAD_ADDRESS	a0, tv_cz_repeat
	li	a1, 24
	jal	check_roundtrip
	PASS_TEST

	RUN_TEST tn_cz_short
	LOAD_ADDRESS	a0, tv_cz_short
	li	a1, 5
	jal	check_roundtrip
	PASS_TEST

	RUN_TEST tn_cz_large
	LOAD_ADDRESS	a0, tv_cz_large
	LOAD_ADDRESS	a1, tv_cz_large_end
	sub	a1, a1, a0
	jal	check_roundtrip
	PASS_TEST

	RUN_TEST tn_cz_mozilla
	LOAD_ADDRESS	s0, tv_cz_mozilla
	LOAD_ADDRESS	s1, tv_cz_mozilla_end
	sub	s1, s1, s0
	li	s2, 0x82000000
	li	s3, 0x82100000
	li	s4, 0x82800000
	mv	a0, s0
	mv	a1, s1
	mv	a2, s2
	mv	a3, s3
	jal	compress_block
	blez	a0, test_fail
	# compressed must be < 80% of input
	srli	t0, s1, 1
	srli	t1, s1, 2
	add	t0, t0, t1
	bge	a0, t0, test_fail
	mv	s5, a0
	mv	a0, s2
	mv	a1, s5
	mv	a2, s4
	li	a3, 0x00200000
	jal	decompress_block
	bne	a0, s1, test_fail
	mv	t0, s0
	mv	t1, s4
	mv	t2, s1
_cz_moz_cmp:
	beqz	t2, _cz_moz_ok
	lbu	t3, 0(t0)
	lbu	t4, 0(t1)
	bne	t3, t4, test_fail
	addi	t0, t0, 1
	addi	t1, t1, 1
	addi	t2, t2, -1
	j	_cz_moz_cmp
_cz_moz_ok:
	PASS_TEST

	RUN_TEST tn_cz_bible
	LOAD_ADDRESS	s0, tv_cz_bible
	LOAD_ADDRESS	s1, tv_cz_bible_end
	sub	s1, s1, s0
	li	s2, 0x82000000
	li	s3, 0x83000000
	li	s4, 0x85000000
	mv	a0, s0
	mv	a1, s1
	mv	a2, s2
	mv	a3, s3
	jal	compress_block
	blez	a0, test_fail
	srli	t0, s1, 1
	srli	t1, s1, 2
	add	t0, t0, t1
	bge	a0, t0, test_fail
	mv	s5, a0
	mv	a0, s2
	mv	a1, s5
	mv	a2, s4
	li	a3, 0x00500000
	jal	decompress_block
	bne	a0, s1, test_fail
	mv	t0, s0
	mv	t1, s4
	mv	t2, s1
_cz_bible_cmp:
	beqz	t2, _cz_bible_ok
	lbu	t3, 0(t0)
	lbu	t4, 0(t1)
	bne	t3, t4, test_fail
	addi	t0, t0, 1
	addi	t1, t1, 1
	addi	t2, t2, -1
	j	_cz_bible_cmp
_cz_bible_ok:
	PASS_TEST

	# Negative: corrupt compressed bible data at several positions
	RUN_TEST tn_cz_corrupt
	li	s6, 4
_corrupt_loop:
	bge	s6, s5, _corrupt_done
	add	t0, s2, s6
	lbu	t1, 0(t0)
	xori	t1, t1, 0xFF
	sb	t1, 0(t0)
	mv	a0, s2
	mv	a1, s5
	li	t0, 0x40000
	add	a2, gp, t0
	li	a3, 4096
	jal	decompress_block
	mv	t5, a0
	add	t0, s2, s6
	lbu	t1, 0(t0)
	xori	t1, t1, 0xFF
	sb	t1, 0(t0)
	beq	t5, s1, test_fail
_corrupt_next:
	srli	t0, s5, 4
	li	t1, 1
	bge	t0, t1, _corrupt_step_ok
	mv	t0, t1
_corrupt_step_ok:
	add	s6, s6, t0
	j	_corrupt_loop
_corrupt_done:
	PASS_TEST

	# Fuzz: random data, varied sizes
	RUN_TEST tn_cz_fuzz
	li	s6, 0x12345678
	li	s7, 256
_fuzz_loop:
	beqz	s7, _fuzz_done
	li	t0, 0x40000
	add	t0, gp, t0
	li	t1, 256
	mv	t2, s6
_fuzz_fill:
	beqz	t1, _fuzz_try
	slli	t3, t2, 13
	xor	t2, t2, t3
	srli	t3, t2, 17
	xor	t2, t2, t3
	slli	t3, t2, 5
	xor	t2, t2, t3
	sw	t2, 0(t0)
	addi	t0, t0, 4
	addi	t1, t1, -1
	j	_fuzz_fill
_fuzz_try:
	mv	s6, t2
	andi	a1, s6, 0x3FF
	addi	a1, a1, 5
	li	t0, 0x40000
	add	a0, gp, t0
	li	t0, 0x50000
	add	a2, gp, t0
	li	a3, 4096
	jal	decompress_block
	addi	s7, s7, -1
	j	_fuzz_loop
_fuzz_done:
	PASS_TEST

	# Truncation: decompress valid data at progressively shorter lengths
	RUN_TEST tn_cz_trunc
	li	s6, 5
_trunc_loop:
	bge	s6, s5, _trunc_done
	mv	a0, s2
	mv	a1, s6
	li	t0, 0x40000
	add	a2, gp, t0
	li	a3, 4096
	jal	decompress_block
	beq	a0, s1, test_fail
_trunc_next:
	srli	t0, s5, 6
	li	t1, 1
	bge	t0, t1, _trunc_step_ok
	mv	t0, t1
_trunc_step_ok:
	add	s6, s6, t0
	j	_trunc_loop
_trunc_done:
	PASS_TEST

	# Edge cases
	RUN_TEST tn_cz_edge
	li	t0, 0x40000
	add	a0, gp, t0
	li	a1, 0
	li	t0, 0x50000
	add	a2, gp, t0
	li	a3, 4096
	jal	decompress_block
	li	t0, -1
	bne	a0, t0, test_fail
	li	t0, 0x40000
	add	a0, gp, t0
	li	a1, 4
	li	t0, 0x50000
	add	a2, gp, t0
	li	a3, 4096
	jal	decompress_block
	li	t0, -1
	bne	a0, t0, test_fail
	mv	a0, s2
	mv	a1, s5
	li	t0, 0x40000
	add	a2, gp, t0
	li	a3, 0
	jal	decompress_block
	li	t0, -1
	bne	a0, t0, test_fail
	PASS_TEST

TEST_EXIT

# ──────────────────────────────────────────────────────────────────────────────
# Test-specific helpers
# ──────────────────────────────────────────────────────────────────────────────

check_roundtrip:
	SETUP	s0, s1, s2
	mv	s0, a0
	mv	s1, a1
	li	t0, 0x10000
	add	a2, gp, t0
	li	t0, 0x20000
	add	a3, gp, t0
	jal	compress_block
	blez	a0, test_fail
	mv	s2, a0
	li	t0, 0x10000
	add	a0, gp, t0
	mv	a1, s2
	li	t0, 0x30000
	add	a2, gp, t0
	li	a3, 0x10000
	jal	decompress_block
	bne	a0, s1, test_fail
	mv	t0, s0
	li	t1, 0x30000
	add	t1, gp, t1
	mv	t2, s1
1:	beqz	t2, 2f
	lbu	t3, 0(t0)
	lbu	t4, 0(t1)
	bne	t3, t4, test_fail
	addi	t0, t0, 1
	addi	t1, t1, 1
	addi	t2, t2, -1
	j	1b
2:	RETURN

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

# ══════════════════════════════════════════════════════════════════════════════
# Test vectors
# ══════════════════════════════════════════════════════════════════════════════
	.balign 4

tn_cz_rt:	.asciz	"compress round-trip "
tn_cz_short:	.asciz	"compress short      "
tn_cz_large:	.asciz	"compress with match "
tn_cz_mozilla:	.asciz	"compress mozilla     "
tn_cz_bible:	.asciz	"compress bible 4MB  "
tn_cz_corrupt:	.asciz	"decompress corrupt  "
tn_cz_fuzz:	.asciz	"decompress fuzz     "
tn_cz_trunc:	.asciz	"decompress truncate "
tn_cz_edge:	.asciz	"decompress edge     "

tv_cz_repeat:
	.ascii	"ABCABCABCABCABCABCABCABC"

tv_cz_short:
	.ascii	"Hello"
	.balign 4

tv_cz_large:
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over the lazy dog. "
	.ascii	"The quick brown fox jumps over "
tv_cz_large_end:
	.balign 4

tv_cz_mozilla:
	.incbin "resources/mozilla"
tv_cz_mozilla_end:
	.balign 4

tv_cz_bible:
	.incbin "resources/bible.txt"
tv_cz_bible_end:
	.balign 4

_gp_base:
