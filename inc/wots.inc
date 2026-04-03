# wots.inc — WOTS+ One-Time Signature Scheme for RISC-V 32-bit
#
# Constant-time implementation using BLAKE2s as the hash function.
# Always performs 255 hash iterations per chain regardless of the digit value.
#
# Usage:
#   .include "macros.inc"
#   .include "blake2s.inc"
#   .include "wots.inc"
#   ...
#   DEFINE_BLAKE2S
#   DEFINE_WOTS
#
# Public labels emitted by DEFINE_WOTS:
#   wots_keyfrom(a0=seed_ptr, a1=pk_ptr, a2=sk_ptr)
#   wots_sign(a0=sk_ptr, a1=msg_ptr, a2=sig_ptr)
#   wots_verify(a0=pk_ptr, a1=sig_ptr, a2=msg_ptr) → a0=0 pass, a0=-1 fail
#
# Constants:
#   WOTS_W     = 256   (Winternitz parameter)
#   WOTS_N     = 32    (hash output size = blake2s digest)
#   WOTS_LEN1  = 16    (message chains)
#   WOTS_LEN2  = 2     (checksum chains)
#   WOTS_LEN   = 18    (total chains)
#   WOTS_SIGLEN = 576  (18 × 32 bytes)
#
# Requires: blake2s (from blake2s.inc) and SETUP/RETURN/LOAD_ADDRESS (from macros.inc)

.equ	WOTS_W,		256
.equ	WOTS_N,		32
.equ	WOTS_LEN1,	16
.equ	WOTS_LEN2,	2
.equ	WOTS_LEN,	(WOTS_LEN1 + WOTS_LEN2)
.equ	WOTS_SIGLEN,	(WOTS_LEN * WOTS_N)

.macro DEFINE_WOTS

# ──────────────────────────────────────────────────────────────────────────────
# wots_chain: constant-time hash chain
# a0 = out_ptr (32 bytes, modified in place — must be pre-loaded with input)
# a1 = steps (0..255)
#
# Always performs 255 blake2s iterations. Uses a mask to conditionally update
# the output, ensuring constant-time execution regardless of steps value.
#
# Each iteration: tmp = blake2s(DOMAIN_CHAIN || out), then conditionally
# copies tmp → out if iteration < steps.
#
# Stack usage: 64 bytes (domain || out) + 32 bytes (tmp hash output) = 96
# ──────────────────────────────────────────────────────────────────────────────
wots_chain:
	SETUP	s0, s1, s2, s3, s4

	mv	s0, a0				# s0 = out_ptr
	mv	s1, a1				# s1 = steps
	li	s2, 0				# s2 = iteration counter

	# allocate: 64 bytes (hash input: domain || out) + 32 bytes (hash output) = 96
	addi	sp, sp, -96
	mv	s3, sp				# s3 = hash input buffer (64 bytes)
	addi	s4, sp, 64			# s4 = hash output buffer (32 bytes)

	# copy DOMAIN_CHAIN into first 32 bytes of hash input (constant, done once)
	LOAD_ADDRESS t0, _wots_domain
	.set	_i, 0
	.rept	8
	lw	t1, (_i * 4)(t0)
	sw	t1, (_i * 4)(s3)
	.set	_i, _i + 1
	.endr

_wots_chain_loop:
	li	t0, WOTS_W - 1			# 255 iterations
	bge	s2, t0, _wots_chain_done

	# copy out[0..31] into hash_input[32..63]
	.set	_i, 0
	.rept	8
	lw	t0, (_i * 4)(s0)
	sw	t0, (32 + _i * 4)(s3)
	.set	_i, _i + 1
	.endr

	# tmp = blake2s_64(hash_input, tmp_buffer)
	mv	a0, s3				# 64-byte input (domain || out)
	mv	a1, s4				# 32-byte output
	jal	blake2s_64

	# mask = (s2 < s1) ? -1 : 0  (constant-time, no branch)
	sub	t0, s2, s1			# t0 = i - steps
	srai	t0, t0, 31			# t0 = -1 if i < steps, else 0
	xori	t1, t0, -1			# t1 = ~mask

	# out = (tmp & mask) | (out & ~mask) for each of 8 words
	.set	_i, 0
	.rept	8
	lw	t2, (_i * 4)(s4)		# tmp word
	lw	t3, (_i * 4)(s0)		# out word
	and	t2, t2, t0			# tmp & mask
	and	t3, t3, t1			# out & ~mask
	or	t3, t3, t2			# selected
	sw	t3, (_i * 4)(s0)		# store back
	.set	_i, _i + 1
	.endr

	addi	s2, s2, 1
	j	_wots_chain_loop

_wots_chain_done:
	addi	sp, sp, 96
	RETURN


# ──────────────────────────────────────────────────────────────────────────────
# wots_keyfrom: generate WOTS+ keypair from a 32-byte seed
# a0 = seed_ptr (32 bytes)
# a1 = pk_ptr   (576 bytes output)
# a2 = sk_ptr   (576 bytes output)
#
# Derives 18 secret key blocks: sk[i] = blake2s(seed || i)
# Then computes public key: pk[i] = chain(sk[i], 255)
# ──────────────────────────────────────────────────────────────────────────────
wots_keyfrom:
	SETUP	s0, s1, s2, s3, s4

	mv	s0, a0				# seed_ptr
	mv	s1, a1				# pk_ptr
	mv	s2, a2				# sk_ptr
	li	s3, 0				# chain index

	# allocate 33-byte buffer for seed || counter
	addi	sp, sp, -48			# 48 = 33 rounded up to 16-byte align
	mv	s4, sp

	# copy seed into buffer[0..31]
	.set	_i, 0
	.rept	8
	lw	t0, (_i * 4)(s0)
	sw	t0, (_i * 4)(s4)
	.set	_i, _i + 1
	.endr

_wots_keygen_loop:
	li	t0, WOTS_LEN
	bge	s3, t0, _wots_keygen_pk

	# buffer[32] = chain index
	sb	s3, 32(s4)

	# sk[i] = blake2s(seed || i, 33)
	mv	a0, s4				# input = seed || i
	li	a1, 33				# length
	# output directly into sk[i * 32]
	slli	t0, s3, 5			# t0 = i * 32
	add	a2, s2, t0
	jal	blake2s

	addi	s3, s3, 1
	j	_wots_keygen_loop

_wots_keygen_pk:
	# compute pk[i] = chain(sk[i], 255) for each chain
	li	s3, 0

_wots_pk_loop:
	li	t0, WOTS_LEN
	bge	s3, t0, _wots_keygen_done

	# copy sk[i] → pk[i] (chain works in-place)
	slli	t0, s3, 5
	add	t1, s2, t0			# src = sk + i*32
	add	t2, s1, t0			# dst = pk + i*32
	.set	_i, 0
	.rept	8
	lw	t3, (_i * 4)(t1)
	sw	t3, (_i * 4)(t2)
	.set	_i, _i + 1
	.endr

	# chain(pk[i], 255)
	add	a0, s1, t0			# a0 = pk + i*32
	li	a1, WOTS_W - 1			# steps = 255
	jal	wots_chain

	addi	s3, s3, 1
	j	_wots_pk_loop

_wots_keygen_done:
	addi	sp, sp, 48
	RETURN


# ──────────────────────────────────────────────────────────────────────────────
# wots_sign: sign a 32-byte message
# a0 = sk_ptr   (576 bytes, secret key)
# a1 = msg_ptr  (32 bytes, message hash)
# a2 = sig_ptr  (576 bytes output)
#
# For each message chain: digit = msg[i] ^ msg[i+16], chain sk[i] by digit steps
# For checksum chains: digit from checksum, chain sk[i] by digit steps
# ──────────────────────────────────────────────────────────────────────────────
wots_sign:
	SETUP	s0, s1, s2, s3, s4, s5

	mv	s0, a0				# sk_ptr
	mv	s1, a1				# msg_ptr
	mv	s2, a2				# sig_ptr
	li	s3, 0				# chain index
	li	s4, 0				# checksum

	# ── message chains (i = 0..15) ──
_wots_sign_msg:
	li	t0, WOTS_LEN1
	bge	s3, t0, _wots_sign_cksum

	# digit = msg[i] ^ msg[i + 16]
	lbu	t0, 0(s1)
	addi	t1, s1, WOTS_LEN1
	lbu	t1, 0(t1)
	xor	s5, t0, t1			# s5 = digit
	addi	s1, s1, 1			# advance msg ptr

	# checksum += 255 - digit
	li	t0, WOTS_W - 1
	sub	t0, t0, s5
	add	s4, s4, t0

	# copy sk[i] → sig[i]
	slli	t0, s3, 5
	add	t1, s0, t0			# src = sk + i*32
	add	t2, s2, t0			# dst = sig + i*32
	.set	_i, 0
	.rept	8
	lw	t3, (_i * 4)(t1)
	sw	t3, (_i * 4)(t2)
	.set	_i, _i + 1
	.endr

	# chain(sig[i], digit)
	slli	t0, s3, 5
	add	a0, s2, t0			# a0 = sig + i*32
	mv	a1, s5				# steps = digit
	jal	wots_chain

	addi	s3, s3, 1
	j	_wots_sign_msg

	# ── checksum chains (i = 0..1) ──
_wots_sign_cksum:
	li	t0, WOTS_LEN
	bge	s3, t0, _wots_sign_done

	# digit = (checksum >> (8 * (i - LEN1))) & 0xFF
	li	t0, WOTS_LEN1
	sub	t0, s3, t0			# t0 = i - LEN1 (0 or 1)
	slli	t0, t0, 3			# t0 = (i - LEN1) * 8
	srl	s5, s4, t0			# shift checksum
	andi	s5, s5, 0xFF			# mask to byte

	# copy sk[i] → sig[i]
	slli	t0, s3, 5
	add	t1, s0, t0
	add	t2, s2, t0
	.set	_i, 0
	.rept	8
	lw	t3, (_i * 4)(t1)
	sw	t3, (_i * 4)(t2)
	.set	_i, _i + 1
	.endr

	# chain(sig[i], digit)
	slli	t0, s3, 5
	add	a0, s2, t0
	mv	a1, s5
	jal	wots_chain

	addi	s3, s3, 1
	j	_wots_sign_cksum

_wots_sign_done:
	RETURN


# ──────────────────────────────────────────────────────────────────────────────
# wots_verify: verify a WOTS+ signature
# a0 = pk_ptr   (576 bytes, public key)
# a1 = sig_ptr  (576 bytes, signature)
# a2 = msg_ptr  (32 bytes, message hash)
# Returns: a0 = 0 (valid), a0 = -1 (invalid)
#
# For each chain: compute remaining chain from signature, compare to public key.
# Constant-time comparison (no early exit).
# ──────────────────────────────────────────────────────────────────────────────
wots_verify:
	SETUP	s0, s1, s2, s3, s4, s5, s6

	mv	s0, a0				# pk_ptr
	mv	s1, a1				# sig_ptr
	mv	s2, a2				# msg_ptr
	li	s3, 0				# chain index
	li	s4, 0				# checksum
	li	s6, 0				# result (0 = pass)

	# allocate 32-byte tmp buffer for chain computation
	addi	sp, sp, -32

	# ── message chains (i = 0..15) ──
_wots_verify_msg:
	li	t0, WOTS_LEN1
	bge	s3, t0, _wots_verify_cksum

	# digit = msg[i] ^ msg[i + 16]
	add	t0, s2, s3
	lbu	t0, 0(t0)			# msg[i]
	addi	t1, s3, WOTS_LEN1
	add	t1, s2, t1
	lbu	t1, 0(t1)			# msg[i + 16]
	xor	s5, t0, t1			# s5 = digit

	# checksum += 255 - digit
	li	t0, WOTS_W - 1
	sub	t0, t0, s5
	add	s4, s4, t0

	# steps = 255 - digit (remaining chain to complete)
	li	t0, WOTS_W - 1
	sub	s5, t0, s5			# s5 = steps

	# copy sig[i] → tmp
	slli	t0, s3, 5
	add	t1, s1, t0			# src = sig + i*32
	mv	t2, sp				# dst = tmp
	.set	_i, 0
	.rept	8
	lw	t3, (_i * 4)(t1)
	sw	t3, (_i * 4)(t2)
	.set	_i, _i + 1
	.endr

	# chain(tmp, steps)
	mv	a0, sp
	mv	a1, s5
	jal	wots_chain

	# constant-time compare tmp vs pk[i] — accumulate mismatches into s6
	slli	t0, s3, 5
	add	t1, s0, t0			# t1 = pk + i*32
	.set	_i, 0
	.rept	8
	lw	t2, (_i * 4)(sp)		# tmp word
	lw	t3, (_i * 4)(t1)		# pk word
	xor	t2, t2, t3			# nonzero if different
	or	s6, s6, t2			# accumulate
	.set	_i, _i + 1
	.endr

	addi	s3, s3, 1
	j	_wots_verify_msg

	# ── checksum chains (i = 0..1) ──
_wots_verify_cksum:
	li	t0, WOTS_LEN
	bge	s3, t0, _wots_verify_done

	# digit = (checksum >> (8 * (i - LEN1))) & 0xFF
	li	t0, WOTS_LEN1
	sub	t0, s3, t0
	slli	t0, t0, 3
	srl	s5, s4, t0
	andi	s5, s5, 0xFF

	# steps = 255 - digit
	li	t0, WOTS_W - 1
	sub	s5, t0, s5

	# copy sig[i] → tmp
	slli	t0, s3, 5
	add	t1, s1, t0
	mv	t2, sp
	.set	_i, 0
	.rept	8
	lw	t3, (_i * 4)(t1)
	sw	t3, (_i * 4)(t2)
	.set	_i, _i + 1
	.endr

	# chain(tmp, steps)
	mv	a0, sp
	mv	a1, s5
	jal	wots_chain

	# constant-time compare tmp vs pk[i]
	slli	t0, s3, 5
	add	t1, s0, t0
	.set	_i, 0
	.rept	8
	lw	t2, (_i * 4)(sp)
	lw	t3, (_i * 4)(t1)
	xor	t2, t2, t3
	or	s6, s6, t2
	.set	_i, _i + 1
	.endr

	addi	s3, s3, 1
	j	_wots_verify_cksum

_wots_verify_done:
	addi	sp, sp, 32

	# convert s6 to return value: 0 if all zeros, -1 if any mismatch
	snez	a0, s6				# a0 = (s6 != 0) ? 1 : 0
	neg	a0, a0				# a0 = -1 or 0

	RETURN


# ──────────────────────────────────────────────────────────────────────────────
# Domain separation constant for hash chains
	.balign 4
_wots_domain:
	.byte	0x01, 'W', 'O', 'T', 'S', '+', 'c', 'h', 'a', 'i', 'n'
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0

.endm	# DEFINE_WOTS
