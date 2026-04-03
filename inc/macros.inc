# macros.inc — Common macros for RISC-V 32-bit assembly
#
# Provides: LOAD_ADDRESS, SETUP, TEAR_DOWN, RETURN
#
# Usage:
#   .include "macros.inc"

.altmacro

# ──────────────────────────────────────────────────────────────────────────────
# LOAD_ADDRESS: PC-relative address load (replaces la for position-independent)
# ──────────────────────────────────────────────────────────────────────────────
.macro LOAD_ADDRESS reg, label
_base\@:
	.equ _offset\@, (\label - _base\@)
	auipc	\reg, %hi(_offset\@)
	addi	\reg, \reg, %lo(_offset\@)
.endm

# ──────────────────────────────────────────────────────────────────────────────
# SETUP / TEAR_DOWN / RETURN: callee-saved register management
#
# SETUP saves ra + listed registers to stack. RETURN restores and returns.
# Supports nested SETUP/RETURN (macro depth tracking).
#
# Usage:
#   my_func:
#       SETUP s0, s1, s2
#       ...
#       RETURN
# ──────────────────────────────────────────────────────────────────────────────

.set _macro_depth, 0

.macro _def_restore_macro depth, sz, regs:vararg
	.macro _do_tear_down_\depth
	.ifnc "\regs", ""
		.set _off, 4
		.irp reg, \regs
		lw \reg, _off(sp)
		.set _off, _off + 4
		.endr
	.endif
	lw ra, 0(sp)
	addi sp, sp, \sz
	.endm
.endm

.macro _exec_tear_down depth
	_do_tear_down_\depth
.endm

.macro _kill_tear_down depth
	.purgem _do_tear_down_\depth
.endm

.macro SETUP regs:vararg
	.set _macro_depth, _macro_depth + 1

	.set _cnt, 1
	.ifnc "\regs", ""
	.irp item, \regs
		.set _cnt, _cnt + 1
	.endr
	.endif
	.set _sz, ((_cnt * 4) + 15) & -16

	_def_restore_macro %_macro_depth, %_sz, \regs

	addi sp, sp, -_sz
	sw	ra, 0(sp)
	.ifnc "\regs", ""
	.set _off, 4
	.irp reg, \regs
		sw \reg, _off(sp)
		.set _off, _off + 4
	.endr
	.endif
.endm

.macro TEAR_DOWN
	_exec_tear_down %_macro_depth
	_kill_tear_down %_macro_depth
	.set _macro_depth, _macro_depth - 1
.endm

.macro RETURN
	TEAR_DOWN
	ret
.endm
