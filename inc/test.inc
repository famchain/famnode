# test.inc — Test harness for famnode unit tests
#
# Provides macros and helpers for writing bare-metal QEMU unit tests.
# Each test file should follow this pattern:
#
#   .include "lib_includes.inc"
#   .include "test.inc"
#
#   TEST_INIT
#       RUN_TEST test_name
#       ... test code ...
#       PASS_TEST
#   TEST_EXIT
#
#   .include "lib_defines.inc"
#   DEFINE_TEST_HELPERS
#
#   # test vectors
#   .balign 4
#   test_name: .asciz "my test             "
#   ...
#   _gp_base:
#
# Requires: macros.inc (SETUP/RETURN/LOAD_ADDRESS) via lib_includes.inc

# ──────────────────────────────────────────────────────────────────────────────
# Platform constants
# ──────────────────────────────────────────────────────────────────────────────

.equ	EXIT_ADDR,		0x100000
.equ	EXIT_PASS,		0x5555
.equ	UART_BASE,		0x10000000
.equ	UART_LSR,		5
.equ	UART_WR_MASK,		0x20

# Virtio disk
.equ	VIRTIO_DISK_BASE,	0x10001000
.equ	VIRT_QUEUE0,		0x050
.equ	VIO_MAGIC,		0x000
.equ	VIO_DEVICE_ID,		0x008
.equ	VIO_DEVICE_FEATURES,	0x010
.equ	VIO_DRIVER_FEATURES,	0x020
.equ	VIO_GUEST_PAGE_SIZE,	0x028
.equ	VIO_QUEUE_SEL,		0x030
.equ	VIO_QUEUE_NUM,		0x038
.equ	VIO_QUEUE_ALIGN,	0x03C
.equ	VIO_QUEUE_PFN,		0x040
.equ	VIO_STATUS,		0x070
.equ	VIRT_MAGIC,		0x74726976

# Data region offsets (from gp)
.equ	DISK_DATA_BUFFER,	0
.equ	VIRT_DESCRIPTOR_TABLE,	4096
.equ	VIRT_DISK_STATUS,	4096 + 4096 + 512
.equ	VIRT_DISK_HEADER,	4096 + 4096 + 512 + 2

# ──────────────────────────────────────────────────────────────────────────────
# TEST_INIT: entry point boilerplate
#
# Sets up gp (page-aligned, pointing to _gp_base), sp, zeros disk area,
# optionally initializes virtio disk (skips if no disk present),
# probes M extension for field arithmetic.
# ──────────────────────────────────────────────────────────────────────────────
.macro TEST_INIT
_start:
	LOAD_ADDRESS	gp, _gp_base
	li		t0, 4095
	add		gp, gp, t0
	li		t0, -4096
	and		gp, gp, t0
	li		sp, 0x90000000

	# Zero disk structures at gp
	mv		t0, gp
	li		t1, VIRT_DISK_HEADER + 18
	add		t1, gp, t1
1:	sw		zero, 0(t0)
	addi		t0, t0, 4
	bltu		t0, t1, 1b

	# Init virtio disk if present
	li		t0, VIRTIO_DISK_BASE
	lw		t1, VIO_MAGIC(t0)
	li		t2, VIRT_MAGIC
	bne		t1, t2, _test_skip_disk
	sw		zero, VIO_STATUS(t0)
	li		t1, 1
	sw		t1, VIO_STATUS(t0)
	lw		t1, VIO_STATUS(t0)
	ori		t1, t1, 2
	sw		t1, VIO_STATUS(t0)
	lw		t1, VIO_DEVICE_FEATURES(t0)
	sw		zero, VIO_DRIVER_FEATURES(t0)
	lw		t1, VIO_STATUS(t0)
	ori		t1, t1, 8
	sw		t1, VIO_STATUS(t0)
	li		t1, 4096
	sw		t1, VIO_GUEST_PAGE_SIZE(t0)
	sw		zero, VIO_QUEUE_SEL(t0)
	li		t1, 16
	sw		t1, VIO_QUEUE_NUM(t0)
	li		t1, 4096
	sw		t1, VIO_QUEUE_ALIGN(t0)
	li		t1, VIRT_DESCRIPTOR_TABLE
	add		t1, gp, t1
	srli		t1, t1, 12
	sw		t1, VIO_QUEUE_PFN(t0)
	lw		t1, VIO_STATUS(t0)
	ori		t1, t1, 4
	sw		t1, VIO_STATUS(t0)
_test_skip_disk:

	# Detect M extension
	jal		fp_probe_m_ext
.endm


# ──────────────────────────────────────────────────────────────────────────────
# TEST_EXIT: successful exit
# ──────────────────────────────────────────────────────────────────────────────
.macro TEST_EXIT
	li		t0, EXIT_ADDR
	li		t1, EXIT_PASS
	sw		t1, 0(t0)
1:	wfi
	j		1b
.endm


# ──────────────────────────────────────────────────────────────────────────────
# RUN_TEST / PASS_TEST: print test name / print PASS
# ──────────────────────────────────────────────────────────────────────────────
.macro RUN_TEST label
	LOAD_ADDRESS	a0, \label
	jal		print_str
.endm

.macro PASS_TEST
	LOAD_ADDRESS	a0, _str_pass
	jal		print_str
.endm


# ──────────────────────────────────────────────────────────────────────────────
# DEFINE_TEST_HELPERS: emit shared test helper functions and strings
#
# Labels emitted:
#   test_fail      — print FAIL and halt
#   print_str      — print null-terminated string at a0
#   write_byte     — write byte in a0 to UART
#   check_hash_32  — compare 32 bytes at a0 vs t0, jump test_fail on mismatch
#   disk_read      — read sector a0 into DISK_DATA_BUFFER (a1=avail_idx)
#   disk_write     — write DISK_DATA_BUFFER to sector a0 (a1=avail_idx)
# ──────────────────────────────────────────────────────────────────────────────
.macro DEFINE_TEST_HELPERS

test_fail:
	LOAD_ADDRESS	a0, _str_fail
	jal		print_str
1:	wfi
	j		1b

print_str:
	SETUP	s0
	mv	s0, a0
1:	lbu	a0, 0(s0)
	beqz	a0, 2f
	jal	write_byte
	addi	s0, s0, 1
	j	1b
2:	RETURN

write_byte:
	li	t1, UART_BASE
	lbu	t2, UART_LSR(t1)
	andi	t2, t2, UART_WR_MASK
	beqz	t2, write_byte
	sb	a0, 0(t1)
	ret

check_hash_32:
	SETUP	s0, s1
	mv	s0, a0
	mv	s1, t0
	li	t2, 8
1:	lw	t3, 0(s0)
	lw	t4, 0(s1)
	bne	t3, t4, test_fail
	addi	s0, s0, 4
	addi	s1, s1, 4
	addi	t2, t2, -1
	bnez	t2, 1b
	RETURN

disk_read:
	li	t5, VIRT_DESCRIPTOR_TABLE
	add	t1, gp, t5
	li	t3, VIRT_DISK_STATUS
	add	t3, gp, t3
	addi	t2, t3, 2
	sw	zero, 0(t2)
	sw	a0, 8(t2)
	sw	t2, 0(t1)
	sw	zero, 4(t1)
	li	t4, 16
	sw	t4, 8(t1)
	li	t4, 1
	sh	t4, 12(t1)
	sh	t4, 14(t1)
	li	t5, DISK_DATA_BUFFER
	add	t5, gp, t5
	sw	t5, 16(t1)
	sw	zero, 20(t1)
	li	t4, 512
	sw	t4, 24(t1)
	li	t4, 3
	sh	t4, 28(t1)
	li	t4, 2
	sh	t4, 30(t1)
	sw	t3, 32(t1)
	sw	zero, 36(t1)
	li	t4, 1
	sw	t4, 40(t1)
	li	t4, 2
	sh	t4, 44(t1)
	sh	zero, 46(t1)
	addi	t4, t1, 256
	sh	zero, 4(t4)
	li	t5, 0xFF
	sb	t5, 0(t3)
	sh	a1, 2(t4)
	fence	w, w
	li	t5, VIRTIO_DISK_BASE
	sw	zero, VIRT_QUEUE0(t5)
	li	t5, 0xFF
1:	lbu	t4, 0(t3)
	beq	t4, t5, 1b
	fence	r, r
	ret

disk_write:
	li	t5, VIRT_DESCRIPTOR_TABLE
	add	t1, gp, t5
	li	t3, VIRT_DISK_STATUS
	add	t3, gp, t3
	addi	t2, t3, 2
	li	t4, 1
	sw	t4, 0(t2)
	sw	a0, 8(t2)
	sw	t2, 0(t1)
	sw	zero, 4(t1)
	li	t4, 16
	sw	t4, 8(t1)
	li	t4, 1
	sh	t4, 12(t1)
	sh	t4, 14(t1)
	li	t5, DISK_DATA_BUFFER
	add	t5, gp, t5
	sw	t5, 16(t1)
	sw	zero, 20(t1)
	li	t4, 512
	sw	t4, 24(t1)
	li	t4, 1
	sh	t4, 28(t1)
	li	t4, 2
	sh	t4, 30(t1)
	sw	t3, 32(t1)
	sw	zero, 36(t1)
	li	t4, 1
	sw	t4, 40(t1)
	li	t4, 2
	sh	t4, 44(t1)
	sh	zero, 46(t1)
	addi	t4, t1, 256
	sh	zero, 4(t4)
	li	t5, 0xFF
	sb	t5, 0(t3)
	sh	a1, 2(t4)
	fence	w, w
	li	t5, VIRTIO_DISK_BASE
	sw	zero, VIRT_QUEUE0(t5)
	li	t5, 0xFF
1:	lbu	t4, 0(t3)
	beq	t4, t5, 1b
	fence	r, r
	ret

	.balign 4
_str_pass:
	.asciz	"PASS\n"
_str_fail:
	.asciz	"FAIL\n"

.endm
