# bench_compress.S — Compress datasets, verify round-trip, report ratio + cycles

.equ	EXIT_ADDR,	0x100000
.equ	EXIT_PASS,	0x5555
.equ	UART_BASE,	0x10000000
.equ	UART_LSR,	5
.equ	UART_WR_MASK,	0x20

.include "macros.inc"
.include "compress.inc"

_start:
	li	sp, 0x90000000

	# ── mozilla (164KB binary) ──
	LOAD_ADDRESS	a0, _lbl_mozilla
	jal	print_str
	LOAD_ADDRESS	a0, _mozilla_start
	LOAD_ADDRESS	a1, _mozilla_end
	sub	a1, a1, a0
	jal	bench_one

	# ── bible (4.4MB text) ──
	LOAD_ADDRESS	a0, _lbl_bible
	jal	print_str
	LOAD_ADDRESS	a0, _bible_start
	LOAD_ADDRESS	a1, _bible_end
	sub	a1, a1, a0
	jal	bench_one

	li	t0, EXIT_ADDR
	li	t1, EXIT_PASS
	sw	t1, 0(t0)
_halt:	wfi
	j	_halt

_error:
	LOAD_ADDRESS	a0, _lbl_err
	jal	print_str
_ehalt:	wfi
	j	_ehalt


# ── bench_one: compress + decompress + verify + report ──
# a0 = input_ptr, a1 = input_len
bench_one:
	SETUP	s0, s1, s2, s3, s4, s5, s6, s7

	mv	s0, a0				# input
	mv	s1, a1				# input len
	li	s2, 0x81000000			# output buffer
	li	s3, 0x81800000			# match_array
	li	s4, 0x82C00000			# decompress output

	# compress
	rdcycle	s6
	mv	a0, s0
	mv	a1, s1
	mv	a2, s2
	mv	a3, s3
	jal	compress_block
	rdcycle	s7
	bltz	a0, _error
	mv	s5, a0				# compressed size
	sub	s6, s7, s6			# compress cycles

	# decompress
	rdcycle	s7
	mv	a0, s2
	mv	a1, s5
	mv	a2, s4
	li	a3, 0x00500000
	jal	decompress_block
	rdcycle	t0
	bltz	a0, _error
	bne	a0, s1, _error
	sub	s7, t0, s7			# decompress cycles

	# verify
	mv	t0, s0
	mv	t1, s4
	mv	t2, s1
_bo_cmp:
	beqz	t2, _bo_report
	lbu	t3, 0(t0)
	lbu	t4, 0(t1)
	bne	t3, t4, _error
	addi	t0, t0, 1
	addi	t1, t1, 1
	addi	t2, t2, -1
	j	_bo_cmp

_bo_report:
	# input
	LOAD_ADDRESS	a0, _lbl_input
	jal	print_str
	mv	a0, s1
	jal	print_dec
	LOAD_ADDRESS	a0, _lbl_bytes
	jal	print_str

	# compressed
	LOAD_ADDRESS	a0, _lbl_compressed
	jal	print_str
	mv	a0, s5
	jal	print_dec
	LOAD_ADDRESS	a0, _lbl_bytes
	jal	print_str

	# ratio
	LOAD_ADDRESS	a0, _lbl_ratio
	jal	print_str
	slli	t0, s5, 6
	slli	t1, s5, 5
	add	t0, t0, t1
	slli	t1, s5, 2
	add	t0, t0, t1			# compressed * 100
	li	t1, 0
1:	bltu	t0, s1, 2f
	sub	t0, t0, s1
	addi	t1, t1, 1
	j	1b
2:	mv	a0, t1
	jal	print_dec
	LOAD_ADDRESS	a0, _lbl_pct
	jal	print_str

	# compress cycles
	LOAD_ADDRESS	a0, _lbl_compress
	jal	print_str
	mv	a0, s6
	jal	print_dec
	LOAD_ADDRESS	a0, _lbl_cyc_open
	jal	print_str
	mv	a0, s6
	mv	a1, s1
	jal	print_div
	LOAD_ADDRESS	a0, _lbl_cyc_close
	jal	print_str

	# decompress cycles
	LOAD_ADDRESS	a0, _lbl_decompress
	jal	print_str
	mv	a0, s7
	jal	print_dec
	LOAD_ADDRESS	a0, _lbl_cyc_open
	jal	print_str
	mv	a0, s7
	mv	a1, s1
	jal	print_div
	LOAD_ADDRESS	a0, _lbl_cyc_close
	jal	print_str

	# verify OK
	LOAD_ADDRESS	a0, _lbl_verify
	jal	print_str

	RETURN


# ── helpers ──

print_str:
	SETUP	s0
	mv	s0, a0
1:	lbu	a0, 0(s0)
	beqz	a0, 2f
	jal	write_byte
	addi	s0, s0, 1
	j	1b
2:	RETURN

print_dec:
	addi	sp, sp, -48
	sw	ra, 0(sp)
	mv	t0, a0
	li	t1, 0
	addi	t2, sp, 4
	beqz	t0, _pd_zero
_pd_loop:
	beqz	t0, _pd_print
	li	t3, 0
	mv	t4, t0
_pd_div10:
	li	t5, 10
	blt	t4, t5, _pd_div10_done
	sub	t4, t4, t5
	addi	t3, t3, 1
	j	_pd_div10
_pd_div10_done:
	addi	t4, t4, '0'
	add	t5, t2, t1
	sb	t4, 0(t5)
	addi	t1, t1, 1
	mv	t0, t3
	j	_pd_loop
_pd_zero:
	li	t4, '0'
	sb	t4, 0(t2)
	li	t1, 1
_pd_print:
	addi	t1, t1, -1
_pd_rev:
	bltz	t1, _pd_ret
	add	t0, t2, t1
	lbu	a0, 0(t0)
	li	t3, UART_BASE
_pd_wait:
	lbu	t4, UART_LSR(t3)
	andi	t4, t4, UART_WR_MASK
	beqz	t4, _pd_wait
	sb	a0, 0(t3)
	addi	t1, t1, -1
	j	_pd_rev
_pd_ret:
	lw	ra, 0(sp)
	addi	sp, sp, 48
	ret

print_div:
	addi	sp, sp, -4
	sw	ra, 0(sp)
	li	t0, 0
1:	bltu	a0, a1, 2f
	sub	a0, a0, a1
	addi	t0, t0, 1
	j	1b
2:	mv	a0, t0
	jal	print_dec
	lw	ra, 0(sp)
	addi	sp, sp, 4
	ret

write_byte:
	li	t1, UART_BASE
	lbu	t2, UART_LSR(t1)
	andi	t2, t2, UART_WR_MASK
	beqz	t2, write_byte
	sb	a0, 0(t1)
	ret


DEFINE_COMPRESS


# ── labels ──
.balign 4
_lbl_mozilla:
	.asciz	"\n── mozilla (binary) ──\n"
_lbl_bible:
	.asciz	"\n── bible (text) ──\n"
_lbl_input:
	.asciz	"input:      "
_lbl_compressed:
	.asciz	"compressed: "
_lbl_ratio:
	.asciz	"ratio:      "
_lbl_verify:
	.asciz	"verify:     OK\n"
_lbl_bytes:
	.asciz	" bytes\n"
_lbl_pct:
	.asciz	"%\n"
_lbl_compress:
	.asciz	"compress:   "
_lbl_decompress:
	.asciz	"decompress: "
_lbl_cyc_open:
	.asciz	" cycles ("
_lbl_cyc_close:
	.asciz	" cycles/byte)\n"
_lbl_err:
	.asciz	"ERROR\n"

.balign 4
_mozilla_start:
	.incbin "resources/mozilla"
_mozilla_end:
	.balign 4
_bible_start:
	.incbin "resources/bible.txt"
_bible_end:
