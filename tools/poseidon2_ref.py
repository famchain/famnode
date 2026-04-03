#!/usr/bin/env python3
"""Poseidon2 BabyBear reference implementation for verifying assembly."""

P = 2013265921  # 2^31 - 2^27 + 1

def fp_add(a, b): return (a + b) % P
def fp_mul(a, b): return (a * b) % P
def fp_sub(a, b): return (a - b) % P

def sbox7(x):
    x2 = fp_mul(x, x)
    x4 = fp_mul(x2, x2)
    x6 = fp_mul(x4, x2)
    return fp_mul(x6, x)

# MDSMat4 applied to a 4-element vector
def mds_mat4(v):
    s = fp_add(fp_add(v[0], v[1]), fp_add(v[2], v[3]))
    return [
        fp_add(fp_add(s, v[0]), fp_add(v[1], v[1])),  # s + a + 2b
        fp_add(fp_add(s, v[1]), fp_add(v[2], v[2])),  # s + b + 2c
        fp_add(fp_add(s, v[2]), fp_add(v[3], v[3])),  # s + c + 2d
        fp_add(fp_add(s, v[3]), fp_add(v[0], v[0])),  # s + d + 2a
    ]

def mds_external(state):
    # Apply MDSMat4 to each 4-element chunk
    chunks = [mds_mat4(state[i:i+4]) for i in range(0, 16, 4)]
    # Sum all chunks element-wise by position
    sums = [0, 0, 0, 0]
    for c in chunks:
        for j in range(4):
            sums[j] = fp_add(sums[j], c[j])
    # Add sums to each chunk
    result = []
    for c in chunks:
        for j in range(4):
            result.append(fp_add(c[j], sums[j]))
    return result

DIAG_INT = [
    0x77ffffff, 0x00000001, 0x00000002, 0x3c000001,
    0x00000003, 0x00000004, 0x3c000000, 0x77fffffe,
    0x77fffffd, 0x77880001, 0x5a000001, 0x69000001,
    0x77fffff2, 0x00780000, 0x07800000, 0x0000000f,
]

def mds_internal(state):
    s = 0
    for x in state:
        s = fp_add(s, x)
    return [fp_add(s, fp_mul(DIAG_INT[i], state[i])) for i in range(16)]

RC_EXT_INIT = [
    [0x69cbb6af, 0x46ad93f9, 0x60a00f4e, 0x6b1297cd,
     0x23189afe, 0x732e7bef, 0x72c246de, 0x2c941900,
     0x0557eede, 0x1580496f, 0x3a3ea77b, 0x54f3f271,
     0x0f49b029, 0x47872fe1, 0x221e2e36, 0x1ab7202e],
    [0x487779a6, 0x3851c9d8, 0x38dc17c0, 0x209f8849,
     0x268dcee8, 0x350c48da, 0x5b9ad32e, 0x0523272b,
     0x3f89055b, 0x01e894b2, 0x13ddedde, 0x1b2ef334,
     0x7507d8b4, 0x6ceeb94e, 0x52eb6ba2, 0x50642905],
    [0x05453f3f, 0x06349efc, 0x6922787c, 0x04bfff9c,
     0x768c714a, 0x3e9ff21a, 0x15737c9c, 0x2229c807,
     0x0d47f88c, 0x097e0ecc, 0x27eadba0, 0x2d7d29e4,
     0x3502aaa0, 0x0f475fd7, 0x29fbda49, 0x018afffd],
    [0x0315b618, 0x6d4497d1, 0x1b171d9e, 0x52861abd,
     0x2e5d0501, 0x3ec8646c, 0x6e5f250a, 0x148ae8e6,
     0x17f5fa4a, 0x3e66d284, 0x0051aa3b, 0x483f7913,
     0x2cfe5f15, 0x023427ca, 0x2cc78315, 0x1e36ea47],
]

RC_INT = [
    0x5a8053c0, 0x693be639, 0x3858867d, 0x19334f6b,
    0x128f0fd8, 0x4e2b1ccb, 0x61210ce0, 0x3c318939,
    0x0b5b2f22, 0x2edb11d5, 0x213effdf, 0x0cac4606,
    0x241af16d,
]

RC_EXT_FINAL = [
    [0x7290a80d, 0x6f7e5329, 0x598ec8a8, 0x76a859a0,
     0x6559e868, 0x657b83af, 0x13271d3f, 0x1f876063,
     0x0aeeae37, 0x706e9ca6, 0x46400cee, 0x72a05c26,
     0x2c589c9e, 0x20bd37a7, 0x6a2d3d10, 0x20523767],
    [0x5b8fe9c4, 0x2aa501d6, 0x1e01ac3e, 0x1448bc54,
     0x5ce5ad1c, 0x4918a14d, 0x2c46a83f, 0x4fcf6876,
     0x61d8d5c8, 0x6ddf4ff9, 0x11fda4d3, 0x02933a8f,
     0x170eaf81, 0x5a9c314f, 0x49a12590, 0x35ec52a1],
    [0x58eb1611, 0x5e481e65, 0x367125c9, 0x0eba33ba,
     0x1fc28ded, 0x066399ad, 0x0cbec0ea, 0x75fd1af0,
     0x50f5bf4e, 0x643d5f41, 0x6f4fe718, 0x5b3cbbde,
     0x1e3afb3e, 0x296fb027, 0x45e1547b, 0x4a8db2ab],
    [0x59986d19, 0x30bcdfa3, 0x1db63932, 0x1d7c2824,
     0x53b33681, 0x0673b747, 0x038a98a3, 0x2c5bce60,
     0x351979cd, 0x5008fb73, 0x547bca78, 0x711af481,
     0x3f93bf64, 0x644d987b, 0x3c8bcd87, 0x608758b8],
]

def external_round(state, rc):
    # Add constants + sbox + MDS
    state = [fp_add(state[i], rc[i]) for i in range(16)]
    state = [sbox7(x) for x in state]
    state = mds_external(state)
    return state

def internal_round(state, rc):
    # Add constant to state[0] + sbox state[0] + internal MDS
    state[0] = fp_add(state[0], rc)
    state[0] = sbox7(state[0])
    state = mds_internal(state)
    return state

def poseidon2_perm(state, initial_mds=False):
    state = list(state)
    # Some implementations apply initial external MDS
    if initial_mds:
        state = mds_external(state)
    # 4 initial external rounds
    for r in range(4):
        state = external_round(state, RC_EXT_INIT[r])
    # 13 internal rounds
    for r in range(13):
        state = internal_round(state, RC_INT[r])
    # 4 final external rounds
    for r in range(4):
        state = external_round(state, RC_EXT_FINAL[r])
    return state

if __name__ == '__main__':
    inp = [894848333, 1437655012, 1200606629, 1690012884,
           71131202, 1749206695, 1717947831, 120589055,
           19776022, 42382981, 1831865506, 724844064,
           171220207, 1299207443, 227047920, 1783754913]
    expected = [516096821, 90309867, 1101817252, 1660784290,
                360715097, 1789519026, 1788910906, 563338433,
                319524748, 1741414159, 1650859320, 894311162,
                1121347488, 1692793758, 1052633829, 1344246938]
    result = poseidon2_perm(inp, initial_mds=True)
    if result == expected:
        print("MATCH — Poseidon2 reference matches Plonky3 test vector")
    else:
        print("MISMATCH")
        print(f"Expected: {[hex(x) for x in expected[:4]]}...")
        print(f"Got:      {[hex(x) for x in result[:4]]}...")
