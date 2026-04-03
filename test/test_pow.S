# test_pow.S — Bible-based PoW unit tests (requires disk for 16MB table cache)

.include "lib_includes.inc"
.include "test.inc"

.equ	POW_TABLE_SIZE,		(16 * 1024 * 1024)
.equ	POW_TABLE_MASK,		(POW_TABLE_SIZE / 32 - 1)
.equ	POW_TABLE_ADDR,		0x82000000
.equ	POW_DISK_MAGIC,		0x42494246

TEST_INIT

	# s8 = disk avail_idx counter
	li	s8, 0

	# Check if table is cached on disk
	li	a0, 0
	addi	s8, s8, 1
	mv	a1, s8
	jal	disk_read
	li	t0, DISK_DATA_BUFFER
	add	t0, gp, t0
	lw	t0, 0(t0)
	li	t1, POW_DISK_MAGIC
	beq	t0, t1, _pow_load

	# ── Generate table ──
	LOAD_ADDRESS	a0, _lbl_pow_gen
	jal	print_str

	LOAD_ADDRESS	s0, tv_pow_bible
	LOAD_ADDRESS	s1, tv_pow_bible_end
	sub	s1, s1, s0
	li	s2, POW_TABLE_ADDR

	# Copy compressed data
	mv	t0, s0
	mv	t1, s2
	srli	t2, s1, 2
_pow_copy:
	beqz	t2, _pow_copy_done
	lw	t3, 0(t0)
	sw	t3, 0(t1)
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	j	_pow_copy
_pow_copy_done:
	andi	t2, s1, 3
_pow_copy_tail:
	beqz	t2, _pow_copy_all
	lbu	t3, 0(t0)
	sb	t3, 0(t1)
	addi	t0, t0, 1
	addi	t1, t1, 1
	addi	t2, t2, -1
	j	_pow_copy_tail
_pow_copy_all:
	andi	t0, s1, 31
	beqz	t0, _pow_aligned
	li	t1, 32
	sub	t0, t1, t0
	add	t1, s2, s1
_pow_pad:
	beqz	t0, _pow_aligned
	sb	zero, 0(t1)
	addi	t1, t1, 1
	addi	t0, t0, -1
	j	_pow_pad
_pow_aligned:
	# blake2s chain
	addi	s3, s1, 31
	li	t0, -32
	and	s3, s3, t0
	li	s4, POW_TABLE_SIZE
	addi	sp, sp, -32
	mv	s5, sp
	li	s6, 0
_pow_gen_loop:
	bgeu	s3, s4, _pow_gen_done
	andi	t0, s6, 0x7FF
	bnez	t0, _pow_gen_no_dot
	li	a0, '.'
	jal	write_byte
_pow_gen_no_dot:
	addi	a0, s3, -32
	add	a0, s2, a0
	li	s8, POW_BLAKE2S_ITERS
_pow_gen_iter:
	beqz	s8, _pow_gen_iter_done
	li	a1, 32
	mv	a2, s5
	jal	blake2s
	mv	a0, s5
	addi	s8, s8, -1
	j	_pow_gen_iter
_pow_gen_iter_done:
	add	t0, s2, s3
	mv	t1, s5
	lw	t3, 0(t1)
	sw	t3, 0(t0)
	lw	t3, 4(t1)
	sw	t3, 4(t0)
	lw	t3, 8(t1)
	sw	t3, 8(t0)
	lw	t3, 12(t1)
	sw	t3, 12(t0)
	lw	t3, 16(t1)
	sw	t3, 16(t0)
	lw	t3, 20(t1)
	sw	t3, 20(t0)
	lw	t3, 24(t1)
	sw	t3, 24(t0)
	lw	t3, 28(t1)
	sw	t3, 28(t0)
	addi	s3, s3, 32
	addi	s6, s6, 1
	j	_pow_gen_loop
_pow_gen_done:
	addi	sp, sp, 32
	li	a0, '\n'
	jal	write_byte

	# Write magic + table to disk
	li	s8, 1
	li	t0, DISK_DATA_BUFFER
	add	t0, gp, t0
	li	t1, POW_DISK_MAGIC
	sw	t1, 0(t0)
	li	a0, 0
	addi	s8, s8, 1
	mv	a1, s8
	jal	disk_write
	li	s0, 0
	li	s1, 1
	li	s2, POW_TABLE_SIZE
_pow_write:
	bgeu	s0, s2, _pow_write_done
	li	t0, DISK_DATA_BUFFER
	add	t0, gp, t0
	li	t1, POW_TABLE_ADDR
	add	t1, t1, s0
	li	t2, 128
_pow_wcopy:
	lw	t3, 0(t1)
	sw	t3, 0(t0)
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	bnez	t2, _pow_wcopy
	mv	a0, s1
	addi	s8, s8, 1
	mv	a1, s8
	jal	disk_write
	addi	s0, s0, 512
	addi	s1, s1, 1
	andi	t0, s1, 0x3FF
	bnez	t0, _pow_write
	li	a0, '.'
	jal	write_byte
	j	_pow_write
_pow_write_done:
	LOAD_ADDRESS	a0, _lbl_pow_saved
	jal	print_str

_pow_load:
	LOAD_ADDRESS	a0, _lbl_pow_load
	jal	print_str
	li	s0, 0
	li	s1, 1
	li	s2, POW_TABLE_SIZE
_pow_read:
	bgeu	s0, s2, _pow_read_done
	mv	a0, s1
	addi	s8, s8, 1
	mv	a1, s8
	jal	disk_read
	li	t0, DISK_DATA_BUFFER
	add	t0, gp, t0
	li	t1, POW_TABLE_ADDR
	add	t1, t1, s0
	li	t2, 128
_pow_rcopy:
	lw	t3, 0(t0)
	sw	t3, 0(t1)
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	bnez	t2, _pow_rcopy
	addi	s0, s0, 512
	addi	s1, s1, 1
	j	_pow_read
_pow_read_done:
	LOAD_ADDRESS	a0, _lbl_pow_loaded
	jal	print_str

_pow_tests:
	RUN_TEST tn_pow_expand
	LOAD_ADDRESS	a0, tv_pow_bible
	LOAD_ADDRESS	a1, tv_pow_bible_end
	sub	a1, a1, a0
	li	a2, POW_TABLE_ADDR
	li	a3, 0x200000
	jal	bible_expand
	bltz	a0, test_fail
	PASS_TEST

	RUN_TEST tn_pow_hash
	li	a0, POW_TABLE_ADDR
	li	a1, POW_TABLE_MASK
	LOAD_ADDRESS	a2, _test_header
	addi	sp, sp, -32
	mv	a3, sp
	jal	pow_hash_full
	lw	t0, 0(sp)
	lw	t1, 4(sp)
	or	t0, t0, t1
	lw	t1, 8(sp)
	or	t0, t0, t1
	lw	t1, 12(sp)
	or	t0, t0, t1
	lw	t1, 16(sp)
	or	t0, t0, t1
	lw	t1, 20(sp)
	or	t0, t0, t1
	lw	t1, 24(sp)
	or	t0, t0, t1
	lw	t1, 28(sp)
	or	t0, t0, t1
	beqz	t0, test_fail
	addi	sp, sp, 32
	PASS_TEST

	RUN_TEST tn_pow_determ
	addi	sp, sp, -64
	li	a0, POW_TABLE_ADDR
	li	a1, POW_TABLE_MASK
	LOAD_ADDRESS	a2, _test_header
	mv	a3, sp
	jal	pow_hash_full
	li	a0, POW_TABLE_ADDR
	li	a1, POW_TABLE_MASK
	LOAD_ADDRESS	a2, _test_header
	addi	a3, sp, 32
	jal	pow_hash_full
	li	t2, 8
	mv	t0, sp
	addi	t1, sp, 32
_pow_det_cmp:
	beqz	t2, _pow_det_ok
	lw	t3, 0(t0)
	lw	t4, 0(t1)
	bne	t3, t4, test_fail
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	j	_pow_det_cmp
_pow_det_ok:
	addi	sp, sp, 64
	PASS_TEST

	RUN_TEST tn_pow_diff
	addi	sp, sp, -64
	li	a0, POW_TABLE_ADDR
	li	a1, POW_TABLE_MASK
	LOAD_ADDRESS	a2, _test_header
	mv	a3, sp
	jal	pow_hash_full
	LOAD_ADDRESS	t0, _test_header
	li	t1, 1
	sw	t1, POW_NONCE_OFFSET(t0)
	li	a0, POW_TABLE_ADDR
	li	a1, POW_TABLE_MASK
	mv	a2, t0
	addi	a3, sp, 32
	jal	pow_hash_full
	LOAD_ADDRESS	t0, _test_header
	sw	zero, POW_NONCE_OFFSET(t0)
	li	t2, 8
	mv	t0, sp
	addi	t1, sp, 32
	li	t5, 0
_pow_diff_cmp:
	beqz	t2, _pow_diff_check
	lw	t3, 0(t0)
	lw	t4, 0(t1)
	beq	t3, t4, _pow_diff_next
	addi	t5, t5, 1
_pow_diff_next:
	addi	t0, t0, 4
	addi	t1, t1, 4
	addi	t2, t2, -1
	j	_pow_diff_cmp
_pow_diff_check:
	beqz	t5, test_fail
	addi	sp, sp, 64
	PASS_TEST

	RUN_TEST tn_pow_mine_easy
	addi	sp, sp, -32
	mv	t0, sp
	addi	sp, sp, -8
	sw	t0, 0(sp)
	li	t0, 100
	sw	t0, 4(sp)
	li	a0, POW_TABLE_ADDR
	li	a1, POW_TABLE_MASK
	LOAD_ADDRESS	a2, _test_header
	LOAD_ADDRESS	a3, _target_easy
	jal	mine_block
	addi	sp, sp, 40
	bltz	a0, test_fail
	PASS_TEST

	RUN_TEST tn_pow_mine_fail
	addi	sp, sp, -32
	mv	t0, sp
	addi	sp, sp, -8
	sw	t0, 0(sp)
	li	t0, 10
	sw	t0, 4(sp)
	li	a0, POW_TABLE_ADDR
	li	a1, POW_TABLE_MASK
	LOAD_ADDRESS	a2, _test_header
	LOAD_ADDRESS	a3, _target_impossible
	jal	mine_block
	addi	sp, sp, 40
	li	t0, -1
	bne	a0, t0, test_fail
	PASS_TEST

TEST_EXIT

.include "lib_defines.inc"
DEFINE_TEST_HELPERS

# ══════════════════════════════════════════════════════════════════════════════
# Test data
# ══════════════════════════════════════════════════════════════════════════════
	.balign 4

tn_pow_expand:		.asciz	"bible_expand        "
tn_pow_hash:		.asciz	"pow_hash non-zero   "
tn_pow_determ:		.asciz	"pow_hash determinism"
tn_pow_diff:		.asciz	"pow_hash nonce diff "
tn_pow_mine_easy:	.asciz	"mine_block easy     "
tn_pow_mine_fail:	.asciz	"mine_block fail     "

_lbl_pow_gen:	.asciz	"Generating 16MB bible table...\n"
_lbl_pow_saved:	.asciz	"Saved to disk.\n"
_lbl_pow_load:	.asciz	"Loading table from disk...\n"
_lbl_pow_loaded: .asciz	"Loaded.\n"
	.balign 4

_test_header:
	.zero	124
	.word	0

_target_easy:
	.word	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
	.word	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF

_target_impossible:
	.word	0, 0, 0, 0, 0, 0, 0, 0

tv_pow_bible:
	.incbin	"resources/bible.compressed"
tv_pow_bible_end:
	.balign 4

_gp_base:
