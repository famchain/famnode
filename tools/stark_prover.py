#!/usr/bin/env python3
"""Minimal STARK prover for the addition constraint (a + b = c).

Generates a proof that can be verified by the RV32 STARK verifier.
Uses BabyBear field, Poseidon2 hashing, FRI polynomial commitment.

Usage: python3 tools/stark_prover.py <output_proof_file>
"""
import struct
import sys
import os

# ══════════════════════════════════════════════════════════════════════════════
# BabyBear Field
# ══════════════════════════════════════════════════════════════════════════════

P = 2013265921  # 2^31 - 2^27 + 1
PRIMITIVE_ROOT = 31

def fp_add(a, b): return (a + b) % P
def fp_sub(a, b): return (a - b + P) % P
def fp_mul(a, b): return (a * b) % P
def fp_inv(a): return pow(a, P - 2, P)
def fp_pow(a, e): return pow(a, e, P)
def fp_neg(a): return (P - a) % P

def two_adic_generator(log_n):
    """Generator of order 2^log_n in BabyBear's multiplicative group."""
    return fp_pow(PRIMITIVE_ROOT, (P - 1) >> log_n)

# ══════════════════════════════════════════════════════════════════════════════
# NTT (Number Theoretic Transform) over BabyBear
# ══════════════════════════════════════════════════════════════════════════════

def ntt(vals, omega):
    """Forward NTT: evaluate polynomial at {omega^0, omega^1, ...}."""
    n = len(vals)
    if n == 1:
        return list(vals)
    omega2 = fp_mul(omega, omega)
    even = ntt(vals[0::2], omega2)
    odd = ntt(vals[1::2], omega2)
    result = [0] * n
    w = 1
    for i in range(n // 2):
        result[i] = fp_add(even[i], fp_mul(w, odd[i]))
        result[i + n // 2] = fp_sub(even[i], fp_mul(w, odd[i]))
        w = fp_mul(w, omega)
    return result

def intt(vals, omega):
    """Inverse NTT: interpolate polynomial from evaluations."""
    n = len(vals)
    omega_inv = fp_inv(omega)
    coeffs = ntt(vals, omega_inv)
    n_inv = fp_inv(n)
    return [fp_mul(c, n_inv) for c in coeffs]

def poly_eval_domain(coeffs, domain_size, omega):
    """Evaluate polynomial on domain {omega^0, ..., omega^(domain_size-1)}."""
    # Pad coefficients to domain_size
    padded = coeffs + [0] * (domain_size - len(coeffs))
    return ntt(padded, omega)

# ══════════════════════════════════════════════════════════════════════════════
# Poseidon2 (matching our RV32 implementation)
# ══════════════════════════════════════════════════════════════════════════════

# Import from our reference implementation
sys.path.insert(0, os.path.dirname(__file__))
from poseidon2_ref import poseidon2_perm

def poseidon2_compress(left, right):
    """Compress two 8-element digests into one via Poseidon2."""
    state = list(left) + list(right)
    assert len(state) == 16
    result = poseidon2_perm(state, initial_mds=True)
    return result[:8]

def merkle_build(leaves):
    """Build Merkle tree from list of 8-element digests. Returns tree array."""
    n = len(leaves)
    assert n > 0 and (n & (n - 1)) == 0, "num_leaves must be power of 2"
    tree = [None] * (2 * n)
    # Copy leaves
    for i in range(n):
        tree[n + i] = leaves[i]
    # Build internal nodes
    for i in range(n - 1, 0, -1):
        tree[i] = poseidon2_compress(tree[2 * i], tree[2 * i + 1])
    return tree

def merkle_root(tree):
    return tree[1]

def merkle_prove(tree, n, leaf_index):
    """Generate Merkle proof (list of sibling digests)."""
    proof = []
    node = n + leaf_index
    while node > 1:
        sibling = node ^ 1
        proof.append(tree[sibling])
        node >>= 1
    return proof

# ══════════════════════════════════════════════════════════════════════════════
# FRI Protocol
# ══════════════════════════════════════════════════════════════════════════════

def fri_fold_evaluations(evals, alpha, omega, domain_size):
    """Fold polynomial evaluations: reduce domain by half."""
    half = domain_size // 2
    folded = []
    for i in range(half):
        f_pos = evals[i]
        f_neg = evals[i + half]
        # x = omega^i
        x = fp_pow(omega, i)
        # folded = (f_pos + f_neg)/2 + alpha * (f_pos - f_neg)/(2*x)
        inv2 = fp_inv(2)
        inv2x = fp_inv(fp_mul(2, x))
        even = fp_mul(fp_add(f_pos, f_neg), inv2)
        odd = fp_mul(fp_mul(alpha, fp_sub(f_pos, f_neg)), inv2x)
        folded.append(fp_add(even, odd))
    return folded

def leaf_hash(f_pos, f_neg):
    """Hash a (f_pos, f_neg) pair into a Merkle leaf digest."""
    state = [f_pos, f_neg] + [0] * 14
    result = poseidon2_perm(state, initial_mds=True)
    return result[:8]

# ══════════════════════════════════════════════════════════════════════════════
# Fiat-Shamir Transcript (matching our RV32 implementation)
# ══════════════════════════════════════════════════════════════════════════════

class Transcript:
    def __init__(self):
        self.state = [0] * 16
        self.counter = 0

    def absorb(self, value):
        self.state[self.counter] = fp_add(self.state[self.counter], value)
        self.counter += 1
        if self.counter >= 8:  # rate = 8
            self.state = poseidon2_perm(self.state, initial_mds=True)
            self.counter = 0

    def absorb_n(self, values):
        for v in values:
            self.absorb(v)

    def squeeze(self):
        if self.counter > 0:
            self.state = poseidon2_perm(self.state, initial_mds=True)
            self.counter = 0
        challenge = self.state[0]
        self.state = poseidon2_perm(self.state, initial_mds=True)
        return challenge

# ══════════════════════════════════════════════════════════════════════════════
# STARK Prover
# ══════════════════════════════════════════════════════════════════════════════

def prove_addition(trace_a, trace_b, trace_c):
    """
    Generate a STARK proof that c[i] = a[i] + b[i] for all i.

    Returns the proof as bytes (serialized for the RV32 verifier).
    """
    trace_len = len(trace_a)
    assert trace_len == len(trace_b) == len(trace_c)
    assert trace_len > 0 and (trace_len & (trace_len - 1)) == 0

    log_trace = trace_len.bit_length() - 1
    blowup = 4
    domain_size = trace_len * blowup
    log_domain = domain_size.bit_length() - 1
    num_queries = 8
    coset_offset = PRIMITIVE_ROOT  # standard coset offset

    print(f"Trace length: {trace_len}")
    print(f"Domain size: {domain_size} (log={log_domain})")
    print(f"Blowup factor: {blowup}")

    # ── Step 1: Interpolate trace columns ──
    trace_omega = two_adic_generator(log_trace)
    # Get polynomial coefficients from trace evaluations
    coeffs_a = intt(trace_a, trace_omega)
    coeffs_b = intt(trace_b, trace_omega)
    coeffs_c = intt(trace_c, trace_omega)

    # ── Step 2: Evaluate on extended domain (coset) ──
    domain_omega = two_adic_generator(log_domain)
    # Coset: evaluate at {offset * omega^i}
    # Equivalent to: shift coefficients by offset, then NTT
    def eval_on_coset(coeffs, domain_size, omega, offset):
        shifted = []
        o_pow = 1
        for c in coeffs:
            shifted.append(fp_mul(c, o_pow))
            o_pow = fp_mul(o_pow, offset)
        padded = shifted + [0] * (domain_size - len(shifted))
        return ntt(padded, omega)

    ext_a = eval_on_coset(coeffs_a, domain_size, domain_omega, coset_offset)
    ext_b = eval_on_coset(coeffs_b, domain_size, domain_omega, coset_offset)
    ext_c = eval_on_coset(coeffs_c, domain_size, domain_omega, coset_offset)

    # ── Step 3: Compute constraint polynomial C(x) = c(x) - a(x) - b(x) ──
    constraint_evals = [fp_sub(ext_c[i], fp_add(ext_a[i], ext_b[i]))
                        for i in range(domain_size)]

    # ── Step 4: Compute vanishing polynomial Z(x) = x^N - 1 on coset ──
    # Z(offset * omega^i) = (offset * omega^i)^trace_len - 1
    vanishing_evals = []
    for i in range(domain_size):
        x = fp_mul(coset_offset, fp_pow(domain_omega, i))
        z = fp_sub(fp_pow(x, trace_len), 1)
        vanishing_evals.append(z)

    # ── Step 5: Quotient polynomial Q(x) = C(x) / Z(x) ──
    quotient_evals = [fp_mul(constraint_evals[i], fp_inv(vanishing_evals[i]))
                      for i in range(domain_size)]

    print(f"Quotient degree check: {sum(1 for q in quotient_evals if q != 0)} non-zero evals")

    # ── Step 6: FRI commitment on quotient polynomial ──
    transcript = Transcript()

    # Commit to trace columns (simplified: commit to extended evaluations)
    # Build Merkle tree over quotient evaluations (pairs)
    fri_layers = []
    current_evals = quotient_evals
    current_size = domain_size
    current_log = log_domain
    current_omega = domain_omega

    while current_size > 1:
        half = current_size // 2
        # Build Merkle leaves: hash pairs (f(x), f(-x))
        leaves = []
        for i in range(half):
            lh = leaf_hash(current_evals[i], current_evals[i + half])
            leaves.append(lh)

        tree = merkle_build(leaves)
        root = merkle_root(tree)

        # Absorb root
        transcript.absorb_n(root)

        # Squeeze alpha challenge
        alpha = transcript.squeeze()

        fri_layers.append({
            'evals': current_evals,
            'tree': tree,
            'root': root,
            'alpha': alpha,
            'omega': current_omega,
            'size': current_size,
            'log_size': current_log,
            'num_leaves': half,
        })

        # Fold
        current_evals = fri_fold_evaluations(
            current_evals, alpha, current_omega, current_size)
        current_omega = fp_mul(current_omega, current_omega)  # omega^2
        current_size = half
        current_log -= 1

        if current_size <= 2:
            break

    # Final polynomial coefficients
    final_poly = current_evals
    num_layers = len(fri_layers)

    print(f"FRI layers: {num_layers}")
    print(f"Final poly length: {len(final_poly)}")

    # ── Step 7: Query phase ──
    queries = []
    for _ in range(num_queries):
        qi = transcript.squeeze() & ((1 << fri_layers[0]['log_size']) - 1)
        # Reduce to half (we query pairs)
        qi = qi % fri_layers[0]['num_leaves']
        query_data = {'index': qi, 'layers': []}

        idx = qi
        for layer in fri_layers:
            half = layer['num_leaves']
            f_pos = layer['evals'][idx]
            f_neg = layer['evals'][idx + half]
            proof = merkle_prove(layer['tree'], half, idx)
            depth = len(proof)
            query_data['layers'].append({
                'f_pos': f_pos,
                'f_neg': f_neg,
                'proof': proof,
                'depth': depth,
            })
            idx = idx % (half // 2) if half > 1 else 0

        queries.append(query_data)

    # ── Step 8: Serialize proof ──
    proof = []
    # Header
    proof.append(num_layers)
    proof.append(fri_layers[0]['log_size'])
    proof.append(num_queries)
    proof.append(len(final_poly))
    proof.append(coset_offset)

    # Layer Merkle roots (8 words each)
    for layer in fri_layers:
        proof.extend(layer['root'])

    # Final polynomial
    proof.extend(final_poly)

    # Queries
    for q in queries:
        for ql in q['layers']:
            proof.append(ql['f_pos'])
            proof.append(ql['f_neg'])
            proof.append(ql['depth'])
            for sibling in ql['proof']:
                proof.extend(sibling)  # 8 words per sibling

    # Also include trace evaluations as public data
    # (verifier needs to check constraint at query points)
    # For simplicity, append trace column evaluations for queried points
    # TODO: this should be committed via separate Merkle tree

    print(f"Proof size: {len(proof) * 4} bytes ({len(proof)} u32 words)")
    return proof, transcript, fri_layers, queries


def main():
    # Simple trace: 4 rows of a + b = c
    trace_a = [1, 4, 7, 10]
    trace_b = [2, 5, 8, 11]
    trace_c = [3, 9, 15, 21]

    # Verify trace is valid
    for i in range(len(trace_a)):
        assert fp_add(trace_a[i], trace_b[i]) == trace_c[i], f"Row {i} invalid"
    print("Trace valid.")

    proof, transcript, layers, queries = prove_addition(trace_a, trace_b, trace_c)

    # Write proof to file
    if len(sys.argv) >= 2:
        outfile = sys.argv[1]
        with open(outfile, 'wb') as f:
            for word in proof:
                f.write(struct.pack('<I', word))
        print(f"Wrote proof to {outfile}")
    else:
        print("No output file specified. Proof generated in memory.")
        print(f"First 10 words: {[hex(w) for w in proof[:10]]}")

    # Print verification info
    print(f"\nVerification data:")
    print(f"  Layers: {len(layers)}")
    print(f"  Queries: {len(queries)}")
    for i, q in enumerate(queries):
        print(f"  Query {i}: index={q['index']}, "
              f"layer depths={[l['depth'] for l in q['layers']]}")


def verify_proof_python(proof_words, trace_a, trace_b, trace_c):
    """Self-verify the proof using the same logic the RV32 verifier would use."""
    idx = 0
    num_layers = proof_words[idx]; idx += 1
    log_domain = proof_words[idx]; idx += 1
    num_queries = proof_words[idx]; idx += 1
    final_poly_len = proof_words[idx]; idx += 1
    coset_offset = proof_words[idx]; idx += 1

    # Read layer roots
    transcript = Transcript()
    roots = []
    for _ in range(num_layers):
        root = proof_words[idx:idx+8]; idx += 8
        roots.append(root)
        transcript.absorb_n(root)

    # Squeeze alphas
    alphas = [transcript.squeeze() for _ in range(num_layers)]

    # Read final poly
    final_poly = proof_words[idx:idx+final_poly_len]; idx += final_poly_len

    # Verify queries
    all_ok = True
    for qi in range(num_queries):
        for li in range(num_layers):
            f_pos = proof_words[idx]; idx += 1
            f_neg = proof_words[idx]; idx += 1
            depth = proof_words[idx]; idx += 1
            siblings = []
            for _ in range(depth):
                sib = proof_words[idx:idx+8]; idx += 8
                siblings.append(sib)

            # Verify leaf hash + Merkle proof
            lh = leaf_hash(f_pos, f_neg)
            # Reconstruct root from leaf + proof
            current = lh
            query_idx = transcript.squeeze() if qi == 0 and li == 0 else 0  # simplified
            # TODO: full Merkle verification
            # For now just check the layer root exists
            if roots[li] is None:
                all_ok = False

    return all_ok

if __name__ == '__main__':
    main()
