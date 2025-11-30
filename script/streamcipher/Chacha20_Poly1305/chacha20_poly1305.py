#!/usr/bin/env python3
"""
Poly1305 and ChaCha20-Poly1305 AEAD (educational implementation).

Not for production. Use libsodium / cryptography for real systems.
"""

import struct
from typing import Tuple
import hmac

# ---------------------
# Poly1305 (big-int implementation)
# ---------------------
P130 = (1 << 130) - 5

def _clamp_r(r_bytes: bytes) -> int:
    """Convert 16-byte little-endian r_bytes to integer and apply clamp per RFC."""
    if len(r_bytes) != 16:
        raise ValueError("r must be 16 bytes")
    r = int.from_bytes(r_bytes, "little")
    # clamp mask: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    # expressed as integer:
    clamp_mask = 0x0ffffffc0ffffffc0ffffffc0fffffff
    return r & clamp_mask

def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """
    Compute Poly1305 tag for message `msg` using 32-byte one-time key `key` (r||s).
    Returns 16-byte tag.
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")

    r_bytes = key[:16]
    s_bytes = key[16:32]

    r = _clamp_r(r_bytes)
    s = int.from_bytes(s_bytes, "little")  # s added at the end

    acc = 0
    # Process message in 16-byte blocks
    offset = 0
    while offset < len(msg):
        block = msg[offset:offset + 16]
        offset += len(block)
        # n = int.from_bytes(block, 'little') + (1 << (8*len(block)))
        # append the 1 byte in little-endian domain:
        n = int.from_bytes(block + b'\x01', "little")
        acc = (acc + n) % P130
        acc = (acc * r) % P130

    # Final tag = (acc + s) mod 2^128
    tag_int = (acc + s) % (1 << 128)
    tag = tag_int.to_bytes(16, "little")
    return tag

def poly1305_verify(tag: bytes, msg: bytes, key: bytes) -> bool:
    """Constant-time verification using hmac.compare_digest."""
    return hmac.compare_digest(poly1305_mac(msg, key), tag)

# ---------------------
# ChaCha20 block and encrypt (RFC 8439 mapping)
# ---------------------
def _rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def _quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a; d = _rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c; b = _rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF
    d ^= a; d = _rotl32(d, 8)
    c = (c + d) & 0xFFFFFFFF
    b ^= c; b = _rotl32(b, 7)
    return a, b, c, d

def chacha20_block(key32: bytes, counter: int, nonce12: bytes) -> bytes:
    """
    Return 64-byte ChaCha20 block for given 256-bit key, 32-bit counter, 96-bit nonce.
    Uses RFC 8439 state layout.
    """
    if len(key32) != 32 or len(nonce12) != 12:
        raise ValueError("key must be 32 bytes and nonce must be 12 bytes")
    def u32(b): return struct.unpack("<I", b)[0]
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        u32(key32[0:4]), u32(key32[4:8]), u32(key32[8:12]), u32(key32[12:16]),
        u32(key32[16:20]), u32(key32[20:24]), u32(key32[24:28]), u32(key32[28:32]),
        counter & 0xFFFFFFFF,
        u32(nonce12[0:4]), u32(nonce12[4:8]), u32(nonce12[8:12])
    ]
    x = state.copy()
    for _ in range(10):  # 20 rounds = 10 double rounds
        # column rounds
        x[0],x[4],x[8],x[12]   = _quarter_round(x[0],x[4],x[8],x[12])
        x[1],x[5],x[9],x[13]   = _quarter_round(x[1],x[5],x[9],x[13])
        x[2],x[6],x[10],x[14]  = _quarter_round(x[2],x[6],x[10],x[14])
        x[3],x[7],x[11],x[15]  = _quarter_round(x[3],x[7],x[11],x[15])
        # diagonal rounds
        x[0],x[5],x[10],x[15]  = _quarter_round(x[0],x[5],x[10],x[15])
        x[1],x[6],x[11],x[12]  = _quarter_round(x[1],x[6],x[11],x[12])
        x[2],x[7],x[8],x[13]   = _quarter_round(x[2],x[7],x[8],x[13])
        x[3],x[4],x[9],x[14]   = _quarter_round(x[3],x[4],x[9],x[14])
    out_words = [ (x[i] + state[i]) & 0xFFFFFFFF for i in range(16) ]
    out = b"".join(struct.pack("<I", w) for w in out_words)
    return out  # 64 bytes

def chacha20_encrypt(key32: bytes, nonce12: bytes, plaintext: bytes, initial_counter: int = 1) -> bytes:
    """
    ChaCha20 stream cipher encryption: start counter at initial_counter (usually 1 for AEAD).
    """
    out = bytearray()
    pos = 0
    counter = initial_counter & 0xFFFFFFFF
    while pos < len(plaintext):
        block = chacha20_block(key32, counter, nonce12)
        chunk = plaintext[pos:pos+64]
        for i, b in enumerate(chunk):
            out.append(b ^ block[i])
        pos += len(chunk)
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(out)

# ---------------------
# ChaCha20-Poly1305 AEAD (RFC 7539 style)
# ---------------------
def _pad16(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return b""
    return b"\x00" * (16 - (len(data) % 16))

def aead_chacha20_poly1305_encrypt(key32: bytes, nonce12: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Returns (ciphertext, tag) where tag is 16 bytes.
    Follows RFC 7539:
      - Compute one-time Poly1305 key = ChaCha20(key, counter=0, nonce) first 32 bytes
      - Encrypt plaintext with ChaCha20 starting at counter=1
      - Compute tag = Poly1305( aad || pad16(aad) || ciphertext || pad16(ciphertext) || le64(len(aad)) || le64(len(ciphertext)), poly_key )
    """
    # 1) derive one-time poly key
    block0 = chacha20_block(key32, 0, nonce12)
    poly_key = block0[:32]  # 16 bytes r || 16 bytes s

    # 2) encrypt with counter starting at 1
    ciphertext = chacha20_encrypt(key32, nonce12, plaintext, initial_counter=1)

    # 3) build auth data
    mac_data = bytearray()
    mac_data += aad
    mac_data += _pad16(aad)
    mac_data += ciphertext
    mac_data += _pad16(ciphertext)
    # 64-bit little-endian lengths
    mac_data += (len(aad)).to_bytes(8, "little")
    mac_data += (len(ciphertext)).to_bytes(8, "little")

    tag = poly1305_mac(bytes(mac_data), poly_key)
    return ciphertext, tag

def aead_chacha20_poly1305_decrypt(key32: bytes, nonce12: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Verify tag and decrypt, returning plaintext. Raises ValueError on auth failure.
    """
    # recompute poly key
    block0 = chacha20_block(key32, 0, nonce12)
    poly_key = block0[:32]

    mac_data = bytearray()
    mac_data += aad
    mac_data += _pad16(aad)
    mac_data += ciphertext
    mac_data += _pad16(ciphertext)
    mac_data += (len(aad)).to_bytes(8, "little")
    mac_data += (len(ciphertext)).to_bytes(8, "little")

    if not poly1305_verify(tag, bytes(mac_data), poly_key):
        raise ValueError("AEAD tag verification failed")
    # decrypt
    plaintext = chacha20_encrypt(key32, nonce12, ciphertext, initial_counter=1)
    return plaintext

# ---------------------
# Example / quick test
# ---------------------
if __name__ == "__main__":
    # Test vector (simple): encrypt then decrypt with empty AAD
    key = bytes(range(32))  # toy key (do not use in real use)
    nonce = bytes(range(12))
    aad = b""
    pt = b"Hello ChaCha20-Poly1305 world! This is a test."

    ct, tag = aead_chacha20_poly1305_encrypt(key, nonce, aad, pt)
    print("Ciphertext (hex):", ct.hex())
    print("Tag (hex):", tag.hex())

    pt2 = aead_chacha20_poly1305_decrypt(key, nonce, aad, ct, tag)
    print("Recovered plaintext:", pt2)
    assert pt == pt2
    print("Self-test ok.")
