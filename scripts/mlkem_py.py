#!/usr/bin/env python3
"""Pure-Python FIPS 203 ML-KEM implementation (Impl C), written from the standard.

Primary source: NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation
Mechanism Standard" (DOI 10.6028/NIST.FIPS.203, 13 August 2024).
Algorithms implemented: K-PKE.KeyGen / Encrypt / Decrypt (FIPS 203 §7.1),
ML-KEM.KeyGen_internal / Encaps_internal / Decaps_internal (§7.2/§7.3),
NTT / NTT^-1 (§4.3, Algorithms 9-10), SampleNTT (§4.4, Algorithm 8),
SamplePolyCBD (§4.4, Algorithm 7), ByteEncode / ByteDecode (§4.2),
Compress / Decompress (§4.2), and the §4.1 functions G, H, J, PRF, XOF.

This implementation is intentionally independent of any C library: it exists
so the assessment can cross-check production libraries (pyca/cryptography,
liboqs) against the standard itself, and so every failure mode can be
exercised with caller-controlled randomness. It is validated against the
official NIST ACVP known-answer vectors (see run_checks.py, checks K01-K09).

Performance: pure Python, no numpy. A full K-PKE encrypt/decrypt round trip
takes ~50 ms at ML-KEM-1024 on this machine; the whole harness runs in a few
seconds. This is a test implementation, NOT a production KEM: it is not
constant-time and must never be used to protect real data.
"""

from __future__ import annotations

import hashlib

Q = 3329
N = 256
ZETA = 17

# FIPS 203 Table 2 / §8: (k, eta1, eta2, du, dv) per parameter set.
PARAMS = {
    "ML-KEM-512": {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4,
                   "ek_len": 800, "dk_len": 1632, "ct_len": 768},
    "ML-KEM-768": {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4,
                   "ek_len": 1184, "dk_len": 2400, "ct_len": 1088},
    "ML-KEM-1024": {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5,
                    "ek_len": 1568, "dk_len": 3168, "ct_len": 1568},
}
SS_LEN = 32


# --------------------------------------------------------------------------
# §4.1 hash functions
# --------------------------------------------------------------------------

def _h(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _j(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(SS_LEN)


def _g(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def _prf(eta: int, s: bytes, b: int) -> bytes:
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def _xof(rho: bytes, j: int, i: int) -> bytes:
    # SHAKE128(rho || j || i); caller squeezes as needed. 1680 bytes is
    # 560 three-byte blocks, ~910 accepted coefficients expected, far
    # above the 256 SampleNTT needs.
    return hashlib.shake_128(rho + bytes([j, i])).digest(1680)


# --------------------------------------------------------------------------
# §4.2 bit packing, compression
# --------------------------------------------------------------------------

def byte_encode(d: int, values) -> bytes:
    """ByteEncode_d: pack d-bit values, little-endian bit order (FIPS 203 §4.2)."""
    out = bytearray()
    acc = 0
    nbits = 0
    for v in values:
        acc |= (v & ((1 << d) - 1)) << nbits
        nbits += d
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


def byte_decode(d: int, data: bytes):
    """ByteDecode_d: unpack d-bit values (FIPS 203 §4.2)."""
    n = (len(data) * 8) // d
    out = []
    acc = 0
    nbits = 0
    idx = 0
    for _ in range(n):
        while nbits < d:
            acc |= data[idx] << nbits
            idx += 1
            nbits += 8
        out.append(acc & ((1 << d) - 1))
        acc >>= d
        nbits -= d
    return out


def compress(d: int, x: int) -> int:
    return ((x << d) + Q // 2) // Q % (1 << d)


def decompress(d: int, y: int) -> int:
    return (y * Q + (1 << (d - 1))) >> d


# --------------------------------------------------------------------------
# §4.3 NTT
# --------------------------------------------------------------------------

def _bitrev7(i: int) -> int:
    return int(f"{i:07b}"[::-1], 2)


def ntt(f):
    """NTT (FIPS 203 §4.3, Algorithm 9).

    Decimation-in-frequency form, verified against the direct CRT
    definition (f mod (x^2 - zeta^(2*BitRev7(i)+1)) for i = 0..127):
    len runs 128 -> 2, twiddle zeta = 17^BitRev7(k) with k = 1..127.
    """
    f = f[:]
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < N:
            zeta = pow(ZETA, _bitrev7(k), Q)
            k += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
            start += 2 * length
        length //= 2
    return f


def ntt_inv(f):
    """NTT^-1 (FIPS 203 §4.3, Algorithm 10).

    Inverse of ntt() above: len runs 2 -> 128, twiddle index k runs
    127 -> 1, then scale by 128^-1 mod q (= 3303). Verified to invert
    ntt() both ways and to reproduce naive polynomial multiplication
    mod x^256 + 1.
    """
    f = f[:]
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < N:
            zeta = pow(ZETA, _bitrev7(k), Q)
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
            start += 2 * length
        length *= 2
    inv128 = pow(128, -1, Q)  # 3303
    return [x * inv128 % Q for x in f]


def _poly_add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def _poly_sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def _ntt_mul_correct(a_hat, b_hat):
    """MultiplyNTTs per FIPS 203 Algorithm 11 (base case, i = 0..127)."""
    out = [0] * N
    for i in range(128):
        # gamma_i = zeta^(2*BitRev7(i) + 1)
        gamma = pow(ZETA, 2 * _bitrev7(i) + 1, Q)
        a0, a1 = a_hat[2 * i], a_hat[2 * i + 1]
        b0, b1 = b_hat[2 * i], b_hat[2 * i + 1]
        out[2 * i] = (a0 * b0 + a1 * b1 * gamma) % Q
        out[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return out


# --------------------------------------------------------------------------
# §4.4 sampling
# --------------------------------------------------------------------------

def sample_ntt(rho: bytes, j: int, i: int):
    """Algorithm 8 (SampleNTT), FIPS 203 §4.4."""
    stream = _xof(rho, j, i)
    out = []
    pos = 0
    while len(out) < N:
        if pos + 3 > len(stream):
            raise RuntimeError("XOF stream exhausted in SampleNTT")
        b0, b1, b2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3
        d1 = b0 + 256 * (b1 % 16)
        d2 = (b1 // 16) + 16 * b2
        if d1 < Q:
            out.append(d1)
        if len(out) < N and d2 < Q:
            out.append(d2)
    return out


def sample_poly_cbd(eta: int, s: bytes, b: int):
    """Algorithm 7 (SamplePolyCBD_eta), FIPS 203 §4.4."""
    data = _prf(eta, s, b)
    out = []
    for i in range(N):
        x = 0
        y = 0
        for j in range(eta):
            bitpos = 2 * i * eta + j
            x += (data[bitpos // 8] >> (bitpos % 8)) & 1
            bitpos2 = 2 * i * eta + eta + j
            y += (data[bitpos2 // 8] >> (bitpos2 % 8)) & 1
        out.append((x - y) % Q)
    return out


# --------------------------------------------------------------------------
# §7.1 K-PKE
# --------------------------------------------------------------------------

def _matrix_a(rho: bytes, k: int):
    """A_hat[i][j] = SampleNTT(rho, j, i) (FIPS 203 §7.1, transposed indices)."""
    return [[sample_ntt(rho, j, i) for j in range(k)] for i in range(k)]


def kpke_keygen(d: bytes, k: int, eta1: int):
    """Algorithm 13 (K-PKE.KeyGen). Returns (ek, dk) bytes."""
    g_out = _g(d + bytes([k]))
    rho, sigma = g_out[:32], g_out[32:]
    n_count = 0
    a_hat = _matrix_a(rho, k)
    s = []
    for _ in range(k):
        s.append(sample_poly_cbd(eta1, sigma, n_count))
        n_count += 1
    e = []
    for _ in range(k):
        e.append(sample_poly_cbd(eta1, sigma, n_count))
        n_count += 1
    s_hat = [ntt(p) for p in s]
    e_hat = [ntt(p) for p in e]
    t_hat = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = _poly_add(acc, _ntt_mul_correct(a_hat[i][j], s_hat[j]))
        t_hat.append(_poly_add(acc, e_hat[i]))
    ek = b"".join(byte_encode(12, t) for t in t_hat) + rho
    dk = b"".join(byte_encode(12, s) for s in s_hat)
    return ek, dk


def kpke_encrypt(ek: bytes, m: bytes, r: bytes, k: int, eta1: int, eta2: int,
                 du: int, dv: int):
    """Algorithm 14 (K-PKE.Encrypt). m is 32 bytes, r is 32 bytes."""
    t_hat_bytes = ek[:384 * k]
    rho = ek[384 * k:384 * k + 32]
    t_hat = [byte_decode(12, t_hat_bytes[384 * i:384 * (i + 1)])
             for i in range(k)]
    n_count = 0
    y = []
    for _ in range(k):
        y.append(sample_poly_cbd(eta1, r, n_count))
        n_count += 1
    e1 = []
    for _ in range(k):
        e1.append(sample_poly_cbd(eta2, r, n_count))
        n_count += 1
    e2 = sample_poly_cbd(eta2, r, n_count)
    y_hat = [ntt(p) for p in y]
    mu = [decompress(1, b) for b in byte_decode(1, m)]
    a_hat = _matrix_a(rho, k)
    u = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = _poly_add(acc, _ntt_mul_correct(a_hat[j][i], y_hat[j]))
        u.append(_poly_add(ntt_inv(acc), e1[i]))
    v_acc = [0] * N
    for j in range(k):
        v_acc = _poly_add(v_acc, _ntt_mul_correct(t_hat[j], y_hat[j]))
    v = _poly_add(_poly_add(ntt_inv(v_acc), e2), mu)
    c1 = b"".join(byte_encode(du, [compress(du, x) for x in p]) for p in u)
    c2 = byte_encode(dv, [compress(dv, x) for x in v])
    return c1 + c2


def kpke_decrypt(dk: bytes, c: bytes, k: int, du: int, dv: int):
    """Algorithm 15 (K-PKE.Decrypt). Returns the 32-byte message m."""
    c1_len = 32 * du * k
    c1 = c[:c1_len]
    c2 = c[c1_len:]
    u = [byte_decode(du, c1[32 * du * i:32 * du * (i + 1)]) for i in range(k)]
    u = [[decompress(du, x) for x in p] for p in u]
    v = [decompress(dv, x) for x in byte_decode(dv, c2)]
    s_hat = [byte_decode(12, dk[384 * i:384 * (i + 1)]) for i in range(k)]
    u_hat = [ntt(p) for p in u]
    w_acc = [0] * N
    for j in range(k):
        w_acc = _poly_add(w_acc, _ntt_mul_correct(s_hat[j], u_hat[j]))
    w = _poly_sub(v, ntt_inv(w_acc))
    return byte_encode(1, [compress(1, x) for x in w])


# --------------------------------------------------------------------------
# §7.2 / §7.3 ML-KEM
# --------------------------------------------------------------------------

def keygen_internal(d: bytes, z: bytes, param: str):
    """Algorithm 16 (ML-KEM.KeyGen_internal). Returns (ek, dk) bytes."""
    p = PARAMS[param]
    ek_pke, dk_pke = kpke_keygen(d, p["k"], p["eta1"])
    ek = ek_pke
    dk = dk_pke + ek + _h(ek) + z
    return ek, dk


def validate_decaps_key(dk: bytes, param: str, expected_ek: bytes | None = None):
    """Decapsulation-key validation (FIPS 203 §7.3).

    A well-formed dk is dk_PKE || ek || H(ek) || z. Validation recomputes
    H over the embedded ek and compares it with the stored hash, and (when
    an expected ek is supplied) requires the embedded ek to match it. This
    catches corrupted-key cases that the bare decapsulation math would
    otherwise accept silently: a corrupted stored hash, or a corrupted
    embedded ek, still decapsulates (the re-encryption check can even pass)
    but the keypair is internally inconsistent. Raises ValueError.
    """
    p = PARAMS[param]
    k = p["k"]
    if len(dk) != p["dk_len"]:
        raise ValueError(
            f"{param} decapsulation key must be {p['dk_len']} bytes, got {len(dk)}")
    ek_embedded = dk[384 * k:768 * k + 32]
    h_stored = dk[768 * k + 32:768 * k + 64]
    if _h(ek_embedded) != h_stored:
        raise ValueError(
            f"{param} decapsulation key rejected: stored H(ek) does not match "
            f"the embedded ek (corrupted hash)")
    if expected_ek is not None and ek_embedded != expected_ek:
        raise ValueError(
            f"{param} decapsulation key rejected: embedded ek does not match "
            f"the expected encapsulation key (corrupted embedded ek)")
    return True


def encaps_internal(ek: bytes, m: bytes, param: str):
    """Algorithm 17 (ML-KEM.Encaps_internal). Returns (K, c)."""
    p = PARAMS[param]
    g_out = _g(m + _h(ek))
    shared, r = g_out[:32], g_out[32:]
    c = kpke_encrypt(ek, m, r, p["k"], p["eta1"], p["eta2"], p["du"], p["dv"])
    return shared, c


def decaps_internal(dk: bytes, c: bytes, param: str):
    """Algorithm 18 (ML-KEM.Decaps_internal), with implicit rejection (§7.3)."""
    p = PARAMS[param]
    k = p["k"]
    dk_pke = dk[:384 * k]
    ek = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m_prime = kpke_decrypt(dk_pke, c, k, p["du"], p["dv"])
    g_out = _g(m_prime + h)
    k_bar, r = g_out[:32], g_out[32:]
    k_reject = _j(z + c)
    c_prime = kpke_encrypt(ek, m_prime, r, k, p["eta1"], p["eta2"],
                           p["du"], p["dv"])
    return k_bar if c == c_prime else k_reject
