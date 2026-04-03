# bench_stark.S — STARK prover + verifier benchmark
#
# Measures cycle counts for:
#   - stark_prove (trace_len=4, the a+b=c constraint)
#   - stark_verify (verify the proof just generated)
#   - Individual components: NTT, Poseidon2, fp_mul, fp_inv

.equ	EXIT_ADDR,	0x100000
.equ	EXIT_PASS,	0x5555
.equ	UART_BASE,	0x10000000
.equ	UART_LSR,	5
.equ	UART_WR_MASK,	0x20

.include "lib_includes.inc"

_start:
	LOAD_ADDRESS	gp, _bench_base
	li		t0, 4095
	add		gp, gp, t0
	li		t0, -4096
	and		gp, gp, t0
	li		sp, 0x88000000

	# Detect M extension
	jal	fp_probe_m_ext

	# ── Setup trace: a=[1,4,7,10] b=[2,5,8,11] c=[3,9,15,21] ──
	li	t0, 0x1000
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

	# ══════════════════════════════════════════════════
	# Bench: fp_mul (1000 iterations)
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS a0, _lbl_fpmul
	jal	print_str
	rdcycle	s6
	li	s0, 1000
	li	a0, 123456789
	li	a1, 987654321
1:	jal	fp_mul
	li	a1, 987654321
	addi	s0, s0, -1
	bnez	s0, 1b
	rdcycle	s7
	sub	a0, s7, s6
	jal	print_dec
	li	a0, '\n'
	jal	write_byte

	# ══════════════════════════════════════════════════
	# Bench: fp_inv
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS a0, _lbl_fpinv
	jal	print_str
	rdcycle	s6
	li	a0, 42
	jal	fp_inv
	rdcycle	s7
	sub	a0, s7, s6
	jal	print_dec
	li	a0, '\n'
	jal	write_byte

	# ══════════════════════════════════════════════════
	# Bench: Poseidon2 permutation
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS a0, _lbl_p2perm
	jal	print_str
	addi	sp, sp, -64
	li	t0, 16
	mv	t1, sp
1:	sw	zero, 0(t1)
	addi	t1, t1, 4
	addi	t0, t0, -1
	bnez	t0, 1b
	rdcycle	s6
	mv	a0, sp
	jal	poseidon2_perm
	rdcycle	s7
	addi	sp, sp, 64
	sub	a0, s7, s6
	jal	print_dec
	li	a0, '\n'
	jal	write_byte

	# ══════════════════════════════════════════════════
	# Bench: NTT forward (size=16)
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS a0, _lbl_ntt16
	jal	print_str
	addi	sp, sp, -64
	li	t0, 16
	li	t1, 1
	mv	t2, sp
1:	sw	t1, 0(t2)
	addi	t2, t2, 4
	addi	t1, t1, 1
	addi	t0, t0, -1
	bnez	t0, 1b
	# Get omega_16
	li	a0, 4			# log2(16) = 4
	jal	fri_domain_gen
	mv	s0, a0
	rdcycle	s6
	mv	a0, sp
	li	a1, 16
	mv	a2, s0
	jal	ntt_forward
	rdcycle	s7
	addi	sp, sp, 64
	sub	a0, s7, s6
	jal	print_dec
	li	a0, '\n'
	jal	write_byte

	# ══════════════════════════════════════════════════
	# Bench: stark_prove (trace_len=4)
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS a0, _lbl_prove
	jal	print_str
	rdcycle	s6
	li	t0, 0x1000
	add	a0, gp, t0			# trace
	li	a1, 4				# trace_len
	li	t0, 0x2000
	add	a2, gp, t0			# work (8KB)
	li	t0, 0x4000
	add	a3, gp, t0			# proof (4KB)
	jal	stark_prove
	rdcycle	s7
	mv	s0, a0				# save proof size
	sub	a0, s7, s6
	jal	print_dec
	li	a0, '\n'
	jal	write_byte

	# Print proof size
	LOAD_ADDRESS a0, _lbl_proofsz
	jal	print_str
	mv	a0, s0
	jal	print_dec
	li	a0, '\n'
	jal	write_byte

	# ══════════════════════════════════════════════════
	# Bench: stark_verify (on proof we just generated)
	# ══════════════════════════════════════════════════
	LOAD_ADDRESS a0, _lbl_verify
	jal	print_str
	rdcycle	s6
	li	t0, 0x4000
	add	a0, gp, t0
	jal	stark_verify
	rdcycle	s7
	mv	s0, a0				# save result
	sub	a0, s7, s6
	jal	print_dec
	li	a0, '\n'
	jal	write_byte

	# Print verify result
	LOAD_ADDRESS a0, _lbl_result
	jal	print_str
	mv	a0, s0
	jal	print_dec
	li	a0, '\n'
	jal	write_byte

	# ── exit ──
	li	t0, EXIT_ADDR
	li	t1, EXIT_PASS
	sw	t1, 0(t0)
1:	wfi
	j	1b


# ──────────────────────────────────────────────────────────────────────────────
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
	SETUP	s0, s1, s2
	mv	s0, a0
	LOAD_ADDRESS s1, _powers_of_10
	li	s2, 0
_pd_loop:
	lw	t0, 0(s1)
	beqz	t0, _pd_done
	li	t1, 0
1:	bltu	s0, t0, 2f
	sub	s0, s0, t0
	addi	t1, t1, 1
	j	1b
2:	or	s2, s2, t1
	beqz	s2, 3f
	addi	a0, t1, '0'
	jal	write_byte
3:	addi	s1, s1, 4
	j	_pd_loop
_pd_done:
	bnez	s2, 4f
	li	a0, '0'
	jal	write_byte
4:	RETURN

write_byte:
	li	t1, UART_BASE
	lbu	t2, UART_LSR(t1)
	andi	t2, t2, UART_WR_MASK
	beqz	t2, write_byte
	sb	a0, 0(t1)
	ret


# ──────────────────────────────────────────────────────────────────────────────
.include "lib_defines.inc"

	.balign 4
_powers_of_10:
	.word	1000000000, 100000000, 10000000, 1000000
	.word	100000, 10000, 1000, 100, 10, 1, 0

_lbl_fpmul:	.asciz	"fp_mul ×1000  cyc: "
_lbl_fpinv:	.asciz	"fp_inv        cyc: "
_lbl_p2perm:	.asciz	"poseidon2     cyc: "
_lbl_ntt16:	.asciz	"ntt fwd n=16  cyc: "
_lbl_prove:	.asciz	"stark_prove   cyc: "
_lbl_proofsz:	.asciz	"proof size  bytes: "
_lbl_verify:	.asciz	"stark_verify  cyc: "
_lbl_result:	.asciz	"verify result    : "
	.balign 4

_bench_base:
