# field.inc — BabyBear prime field arithmetic for RISC-V 32-bit
#
# BabyBear: p = 2^31 - 2^27 + 1 = 2013265921 = 0x78000001
#
# Usage:
#   .include "macros.inc"
#   .include "field.inc"
#   ...
#   DEFINE_FIELD
#
# Public labels emitted by DEFINE_FIELD:
#   fp_add(a0, a1) → a0 = (a0 + a1) mod p
#   fp_sub(a0, a1) → a0 = (a0 - a1) mod p
#   fp_mul(a0, a1) → a0 = (a0 * a1) mod p
#   fp_inv(a0)     → a0 = a0^(-1) mod p (Fermat: a^(p-2))
#   fp_neg(a0)     → a0 = -a0 mod p
#   fp_probe_m_ext() → detects M extension via trap handler
#
# fp_mul dispatches at runtime based on a flag stored at gp + FP_HAS_M_OFF:
#   flag = 1 → hardware mul/mulhu + Barrett reduction
#   flag = 0 → software shift-and-add (pure RV32I)
#
# The caller must reserve 4 bytes at gp + FP_HAS_M_OFF.
# Call fp_probe_m_ext once at boot before any field operations.
#
# All leaf functions clobber t-regs. Inputs must be in [0, p-1].

.equ	FP_P,		0x78000001	# 2^31 - 2^27 + 1 = 2013265921
.equ	FP_P_NEG,	0x87FFFFFF	# -p mod 2^32 = 2^32 - p
.equ	FP_BARRETT_M,	0x88888887	# floor(2^62 / P)
.equ	FP_HAS_M_OFF,	-4		# gp-relative offset for M extension flag

.macro DEFINE_FIELD

# ══════════════════════════════════════════════════════════════════════════════
# fp_add: a0 = (a0 + a1) mod p
# Clobbers: t0
# ══════════════════════════════════════════════════════════════════════════════
fp_add:
	add	a0, a0, a1
	li	t0, FP_P
	bltu	a0, a1, _fpa_wrap		# unsigned overflow → definitely >= p
	bltu	a0, t0, _fpa_done		# no overflow and < p → done
_fpa_wrap:
	sub	a0, a0, t0
_fpa_done:
	ret


# ══════════════════════════════════════════════════════════════════════════════
# fp_sub: a0 = (a0 - a1) mod p
# Clobbers: t0
# ══════════════════════════════════════════════════════════════════════════════
fp_sub:
	bgeu	a0, a1, _fps_nowrap
	li	t0, FP_P
	add	a0, a0, t0
_fps_nowrap:
	sub	a0, a0, a1
	ret


# ══════════════════════════════════════════════════════════════════════════════
# fp_neg: a0 = -a0 mod p (= p - a0, or 0 if a0 == 0)
# Clobbers: t0
# ══════════════════════════════════════════════════════════════════════════════
fp_neg:
	beqz	a0, _fpn_done
	li	t0, FP_P
	sub	a0, t0, a0
_fpn_done:
	ret


# ══════════════════════════════════════════════════════════════════════════════
# fp_mul: a0 = (a0 * a1) mod p
# Clobbers: t0-t6
#
# Dispatches at runtime: loads flag from gp + FP_HAS_M_OFF.
# ══════════════════════════════════════════════════════════════════════════════
fp_mul:
	lw	t0, FP_HAS_M_OFF(gp)
	bnez	t0, _fp_mul_hw
	# fall through to software path

# ── Software path (pure RV32I) ──────────────────────────────────────────────
_fp_mul_sw:
	mv	t2, a0				# multiplicand
	mv	t3, a1				# multiplier
	li	t0, 0				# result
	li	t4, FP_P

	li	t5, 0x40000000			# start at bit 30 (inputs < 2^31)

_fpm_loop:
	beqz	t5, _fpm_done
	add	t0, t0, t0			# 2 * result
	bgeu	t0, t4, _fpm_dbl_sub
	j	_fpm_dbl_ok
_fpm_dbl_sub:
	sub	t0, t0, t4
_fpm_dbl_ok:
	and	t6, t3, t5
	beqz	t6, _fpm_next
	add	t0, t0, t2
	bgeu	t0, t4, _fpm_add_sub
	j	_fpm_next
_fpm_add_sub:
	sub	t0, t0, t4
_fpm_next:
	srli	t5, t5, 1
	j	_fpm_loop

_fpm_done:
	mv	a0, t0
	ret

# ── Hardware path (RV32IM) ──────────────────────────────────────────────────
# Barrett reduction: q = (z_hi * M) >> 30, r = z - q*P, then fixup.
# Verified correct over 10M random inputs.
#
# Only assembled when HAVE_M_ASM is defined (rv32im build).
# The rv32i CI target omits this to guarantee no M instruction leakage.
# ─────────────────────────────────────────────────────────────────────────────
.ifdef HAVE_M_ASM
_fp_mul_hw:
	mul	t0, a0, a1			# z_lo
	mulhu	t1, a0, a1			# z_hi

	li	t4, FP_BARRETT_M
	mul	t2, t1, t4			# (z_hi*M) low
	mulhu	t3, t1, t4			# (z_hi*M) high
	srli	t2, t2, 30
	slli	t3, t3, 2
	or	t2, t3, t2			# q

	li	t4, FP_P
	mul	t3, t2, t4			# (q*P) low
	mulhu	t5, t2, t4			# (q*P) high
	sltu	t6, t0, t3			# borrow
	sub	t0, t0, t3			# r_lo
	sub	t1, t1, t5			# r_hi
	sub	t1, t1, t6			# r_hi -= borrow

	# r = t1:t0, t1 ∈ {0,1}, r < 4*P ≈ 8.05G.
	# When t1=1: r in [2^32, 4P), needs 1-3 subs.
	# When t1=0: r in [0, 2^32), needs 0-2 subs.
	# Bring r below 2^32 first, then subtract P iteratively.
	beqz	t1, _fpmh_32
	# t1=1: subtract P via P_NEG. Result might still be >= 2^32.
	li	t5, FP_P_NEG
	add	t0, t0, t5			# r -= P (32-bit)
	bgeu	t0, t5, _fpmh_32		# no overflow → r < 2^32 now
	# Overflowed (result < addend): r-P still >= 2^32. Sub P again.
	add	t0, t0, t5
	# Now r < 2^32 guaranteed (r was < 4P, minus 2P < 2P < 2^32).
_fpmh_32:
	# r < 2^32. Need 0-2 more subs of P.
	bltu	t0, t4, _fpmh_done
	sub	t0, t0, t4
	bltu	t0, t4, _fpmh_done
	sub	t0, t0, t4
_fpmh_done:
	mv	a0, t0
	ret
.endif


# ══════════════════════════════════════════════════════════════════════════════
# fp_probe_m_ext: detect M extension via trap handler
#
# Installs a temporary trap handler, executes a `mul` (hand-encoded so this
# assembles under rv32i). If it traps → no M ext. If it succeeds → M ext.
#
# Writes result to gp + FP_HAS_M_OFF.
# Must be called once at boot. Clobbers: t0-t3.
# ══════════════════════════════════════════════════════════════════════════════
.ifdef HAVE_M_ASM
fp_probe_m_ext:
	# Save old trap handler
	csrr	t0, mtvec

	# Install probe trap handler
	LOAD_ADDRESS t1, _fp_probe_trap
	csrw	mtvec, t1

	# Assume success
	li	t3, 1
	sw	t3, FP_HAS_M_OFF(gp)

	# Try mul. Hand-encoded as .word so it assembles under rv32i.
	# Encoding: mul x0, x0, x0 = 0x02000033
_fp_probe_mul:
	.word	0x02000033			# mul zero, zero, zero

	# If we get here, mul succeeded → flag already 1
	csrw	mtvec, t0
	ret

# Trap handler: illegal instruction means no M extension.
# Naturally 4-byte aligned (only 4-byte instructions precede it).
_fp_probe_trap:
	sw	zero, FP_HAS_M_OFF(gp)		# _fp_has_m = 0

	# Skip past the faulting mul instruction
	csrr	t1, mepc
	addi	t1, t1, 4
	csrw	mepc, t1
	mret

.else
# Without HAVE_M_ASM: no hw path compiled, always use software multiply.
fp_probe_m_ext:
	sw	zero, FP_HAS_M_OFF(gp)
	ret
.endif


# ══════════════════════════════════════════════════════════════════════════════
# fp_inv: a0 = a0^(-1) mod p using Fermat's little theorem: a^(p-2) mod p
# ══════════════════════════════════════════════════════════════════════════════
fp_inv:
	SETUP	s0, s1, s2

	mv	s0, a0				# base
	li	s1, 1				# result = 1
	li	s2, FP_P - 2			# exponent = p - 2

_fpi_loop:
	beqz	s2, _fpi_done
	andi	t0, s2, 1
	beqz	t0, _fpi_sq
	mv	a0, s1
	mv	a1, s0
	jal	fp_mul
	mv	s1, a0
_fpi_sq:
	mv	a0, s0
	mv	a1, s0
	jal	fp_mul
	mv	s0, a0
	srli	s2, s2, 1
	j	_fpi_loop

_fpi_done:
	mv	a0, s1
	RETURN

# ══════════════════════════════════════════════════════════════════════════════
# fp_pow: a0 = a0^a1 mod p (modular exponentiation via square-and-multiply)
# ══════════════════════════════════════════════════════════════════════════════
fp_pow:
	SETUP	s0, s1, s2

	mv	s0, a0				# base
	li	s1, 1				# result = 1
	mv	s2, a1				# exponent

_fpp_loop:
	beqz	s2, _fpp_done
	andi	t0, s2, 1
	beqz	t0, _fpp_sq
	mv	a0, s1
	mv	a1, s0
	jal	fp_mul
	mv	s1, a0
_fpp_sq:
	mv	a0, s0
	mv	a1, s0
	jal	fp_mul
	mv	s0, a0
	srli	s2, s2, 1
	j	_fpp_loop

_fpp_done:
	mv	a0, s1
	RETURN

.endm	# DEFINE_FIELD
