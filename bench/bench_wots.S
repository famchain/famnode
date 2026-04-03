# bench_wots.S — WOTS+ benchmark: measures cycles for keygen, sign, verify
#
# Prints cycle counts for each operation via UART, then exits.

.equ	EXIT_ADDR,	0x100000
.equ	EXIT_PASS,	0x5555
.equ	UART_BASE,	0x10000000
.equ	UART_LSR,	5
.equ	UART_WR_MASK,	0x20

.include "macros.inc"
.include "blake2s.inc"
.include "wots.inc"

.equ	SK_OFF,		0
.equ	PK_OFF,		576
.equ	SIG_OFF,	1152
.equ	MSG_OFF,	1728
.equ	SEED_OFF,	1760

_start:
	LOAD_ADDRESS	gp, _bench_data
	li		t0, 4095
	add		gp, gp, t0
	li		t0, -4096
	and		gp, gp, t0
	li		t0, 0x100000
	add		sp, gp, t0

	# ── setup seed (0xAA * 32) ──
	li		t0, SEED_OFF
	add		t0, gp, t0
	li		t1, 0xAAAAAAAA
	.set	_i, 0
	.rept	8
	sw		t1, (_i * 4)(t0)
	.set	_i, _i + 1
	.endr

	# ── compute message hash ──
	LOAD_ADDRESS	a0, _bench_msg
	li		a1, 21
	li		t0, MSG_OFF
	add		a2, gp, t0
	jal		blake2s

	# ══════════════════════════════════════════════════
	# Bench: blake2s (single 32-byte hash)
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS	a0, _lbl_blake2s
	jal		print_str

	rdcycle		s6
	LOAD_ADDRESS	a0, _bench_msg
	li		a1, 21
	addi		sp, sp, -32
	mv		a2, sp
	jal		blake2s
	addi		sp, sp, 32
	rdcycle		s7
	sub		a0, s7, s6
	jal		print_dec
	li		a0, '\n'
	jal		write_byte

	# ══════════════════════════════════════════════════
	# Bench: keygen
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS	a0, _lbl_keygen
	jal		print_str

	rdcycle		s6
	li		t0, SEED_OFF
	add		a0, gp, t0
	li		t0, PK_OFF
	add		a1, gp, t0
	li		t0, SK_OFF
	add		a2, gp, t0
	jal		wots_keyfrom
	rdcycle		s7
	sub		a0, s7, s6
	jal		print_dec
	li		a0, '\n'
	jal		write_byte

	# ══════════════════════════════════════════════════
	# Bench: sign
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS	a0, _lbl_sign
	jal		print_str

	rdcycle		s6
	li		t0, SK_OFF
	add		a0, gp, t0
	li		t0, MSG_OFF
	add		a1, gp, t0
	li		t0, SIG_OFF
	add		a2, gp, t0
	jal		wots_sign
	rdcycle		s7
	sub		a0, s7, s6
	jal		print_dec
	li		a0, '\n'
	jal		write_byte

	# ══════════════════════════════════════════════════
	# Bench: verify
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS	a0, _lbl_verify
	jal		print_str

	rdcycle		s6
	li		t0, PK_OFF
	add		a0, gp, t0
	li		t0, SIG_OFF
	add		a1, gp, t0
	li		t0, MSG_OFF
	add		a2, gp, t0
	jal		wots_verify
	rdcycle		s7
	sub		a0, s7, s6
	jal		print_dec
	li		a0, '\n'
	jal		write_byte

	# ── exit ──
	li		t0, EXIT_ADDR
	li		t1, EXIT_PASS
	sw		t1, 0(t0)
1:	wfi
	j		1b


# ──────────────────────────────────────────────────────────────────────────────
# print_str: print null-terminated string at a0
print_str:
	SETUP	s0
	mv	s0, a0
1:	lbu	a0, 0(s0)
	beqz	a0, 2f
	jal	write_byte
	addi	s0, s0, 1
	j	1b
2:	RETURN

# ──────────────────────────────────────────────────────────────────────────────
# print_dec: print unsigned 32-bit integer in a0 as decimal
print_dec:
	SETUP	s0, s1, s2
	mv	s0, a0
	LOAD_ADDRESS s1, _powers_of_10
	li	s2, 0			# leading zero suppression

_pd_loop:
	lw	t0, 0(s1)		# current power of 10
	beqz	t0, _pd_done		# sentinel
	li	t1, 0			# digit count
1:	bltu	s0, t0, 2f
	sub	s0, s0, t0
	addi	t1, t1, 1
	j	1b
2:	or	s2, s2, t1		# track if we've seen non-zero
	beqz	s2, 3f			# skip leading zeros
	addi	a0, t1, '0'
	jal	write_byte
3:	addi	s1, s1, 4
	j	_pd_loop

_pd_done:
	# always print at least '0'
	bnez	s2, 4f
	li	a0, '0'
	jal	write_byte
4:	RETURN

# ──────────────────────────────────────────────────────────────────────────────
write_byte:
	li	t1, UART_BASE
	lbu	t2, UART_LSR(t1)
	andi	t2, t2, UART_WR_MASK
	beqz	t2, write_byte
	sb	a0, 0(t1)
	ret


# ──────────────────────────────────────────────────────────────────────────────
DEFINE_BLAKE2S
DEFINE_WOTS


# ──────────────────────────────────────────────────────────────────────────────
	.balign 4
_powers_of_10:
	.word	1000000000, 100000000, 10000000, 1000000
	.word	100000, 10000, 1000, 100, 10, 1, 0

_bench_msg:
	.ascii	"test message for wots"
	.balign	4

_lbl_blake2s:
	.asciz	"blake2s   cycles: "
_lbl_keygen:
	.asciz	"keygen    cycles: "
_lbl_sign:
	.asciz	"sign      cycles: "
_lbl_verify:
	.asciz	"verify    cycles: "
	.balign	4

_bench_data:
