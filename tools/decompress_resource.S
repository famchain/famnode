# decompress_resource.S — Decompress an embedded resource and output via UART
# Used by tools/decompress_resource.py to decompress .cz files.
# The .incbin path is patched by the tool before assembly.

.equ	EXIT_ADDR,	0x100000
.equ	EXIT_PASS,	0x5555
.equ	UART_BASE,	0x10000000
.equ	UART_LSR,	5
.equ	UART_WR_MASK,	0x20

.include "macros.inc"
.include "compress.inc"

_start:
	li	sp, 0x90000000

	LOAD_ADDRESS	s0, _resource_start
	LOAD_ADDRESS	s1, _resource_end
	sub	s1, s1, s0

	# Decompress
	mv	a0, s0
	mv	a1, s1
	li	a2, 0x82000000			# output
	li	a3, 0x00500000			# 5MB capacity
	jal	decompress_block
	bltz	a0, _fail
	mv	s2, a0				# decompressed size

	# Output decompressed size as 4-byte LE header
	li	t0, UART_BASE
	sb	s2, 0(t0)
	srli	t1, s2, 8
	sb	t1, 0(t0)
	srli	t1, s2, 16
	sb	t1, 0(t0)
	srli	t1, s2, 24
	sb	t1, 0(t0)

	# Output decompressed data
	li	s3, 0
	li	s4, 0x82000000
_out_loop:
	bge	s3, s2, _done
	add	t0, s4, s3
	lbu	a0, 0(t0)
	li	t0, UART_BASE
1:	lbu	t1, UART_LSR(t0)
	andi	t1, t1, UART_WR_MASK
	beqz	t1, 1b
	sb	a0, 0(t0)
	addi	s3, s3, 1
	j	_out_loop

_done:
	li	t0, EXIT_ADDR
	li	t1, EXIT_PASS
	sw	t1, 0(t0)
2:	wfi
	j	2b

_fail:
3:	wfi
	j	3b

DEFINE_COMPRESS

.balign 4
_resource_start:
	.incbin "RESOURCE_PATH"
_resource_end:
