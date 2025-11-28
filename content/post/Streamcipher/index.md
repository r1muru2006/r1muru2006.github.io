---
title: "Is stream encryption secure?"
description: "Today I will go over some stream ciphers and learn how they can be exploited by attackers."
date: 2025-11-25T14:33:54+07:00
cover: /images/StreamCipher/background.png
math: true
license: 
hidden: false
comments: true
tags: 
    - Research
    - Cryptography
categories:
    - Learning
---

# Chacha20-Poly1305
## Algorithm
### Chacha20
ChaCha20-Poly1305 architecture consists of two main components, the stream cipher ChaCha20 and the authentication mechanism Poly1305 by the same author D.J. Berstein.
The ChaCha20 algorithm uses ChaCha20 block functions to generate the encryption keystream.
![images](/images/StreamCipher/encrypt.png)

The input of the ChaCha20 block function is a 4x4 word matrix described as in this figure:
![images](/images/StreamCipher/input.png)

More details in figure a are 128 bit constant *C* (4-word), 256 bit key *K* (8-word), 32 bit counter parameter *Ctr* (1 word), 96 bit nonce *N* (3 words). Then perform 20 loops alternatingly executing the column round transformations according to figure b and the diagonal round transformations according to figure c.

These two circular shifts are implemented by a single QUARTERROUND transformation (cross or column shift based on the input index to the QUARTERROUND function) as shown in this:
![images](/images/StreamCipher/quarterround.png)

```python
def chacha20_quarter_round(a,b,c,d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a; d = ((d << 16) & 0xFFFFFFFF) | (d >> 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c; b = ((b << 12) & 0xFFFFFFFF) | (b >> 20)
    a = (a + b) & 0xFFFFFFFF
    d ^= a; d = ((d << 8) & 0xFFFFFFFF) | (d >> 24)
    c = (c + d) & 0xFFFFFFFF
    b ^= c; b = ((b << 7) & 0xFFFFFFFF) | (b >> 25)
    return a,b,c,d
```

In 20 loops, each loop performs 8 operations QUARTERROUND and the order is: QUARTERROUND from 1 to 4 performs column rotation, while QUARTERROUND from 5 to 8 performs cross rotation. The output of the 20-loop block is 16 words, which are added to the 16 input words modulo $2^{32}$ to generate 16 key words. The 16 key words are XORed with the 16 plaintext words to obtain 16 ciphertext words.

```python
def chacha20_block(key32: bytes, counter: int, nonce12: bytes) -> bytes:
    def u32(b): return struct.unpack("<I", b)[0]
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        u32(key32[0:4]), u32(key32[4:8]), u32(key32[8:12]), u32(key32[12:16]),
        u32(key32[16:20]), u32(key32[20:24]), u32(key32[24:28]), u32(key32[28:32]),
        counter & 0xFFFFFFFF,
        u32(nonce12[0:4]), u32(nonce12[4:8]), u32(nonce12[8:12])
    ]
    x = state.copy()
    for _ in range(20):
        # column rounds
        x[0],x[4],x[8],x[12] = chacha20_quarter_round(x[0],x[4],x[8],x[12])
        x[1],x[5],x[9],x[13] = chacha20_quarter_round(x[1],x[5],x[9],x[13])
        x[2],x[6],x[10],x[14] = chacha20_quarter_round(x[2],x[6],x[10],x[14])
        x[3],x[7],x[11],x[15] = chacha20_quarter_round(x[3],x[7],x[11],x[15])
        # diagonal rounds
        x[0],x[5],x[10],x[15] = chacha20_quarter_round(x[0],x[5],x[10],x[15])
        x[1],x[6],x[11],x[12] = chacha20_quarter_round(x[1],x[6],x[11],x[12])
        x[2],x[7],x[8],x[13] = chacha20_quarter_round(x[2],x[7],x[8],x[13])
        x[3],x[4],x[9],x[14] = chacha20_quarter_round(x[3],x[4],x[9],x[14])
    out = b"".join(struct.pack("<I", (x[i] + state[i]) & 0xFFFFFFFF) for i in range(16))
    return out
```
### Poly1305
Poly1305 is a message authentication cipher (MAC) to ensure the authenticity and integrity of data.
The input key is divided into 2 parts called r and s, each part is 128 bits long. The pair (r,s) must be unique and unguessable for each call.

The input message is divided into 16-byte blocks (the last block can be padded with 0 bits), the 16-byte blocks are padded with 1 byte with value 0x01 to 17 bytes, calculations are performed on these blocks with r on the Z() field to create an accumulator.
![images](/images/StreamCipher/poly1305.png)

Finally the value s is added to the accumulator and the 128 bits are extracted as the authentication tag.
![images](/images/StreamCipher/poly1305_2.png)

```python
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
```

## Security
ChaCha20-Poly1305 is generally secure and offers better resistance to timing attacks than AES-GCM. However, like GCM, its security relies strictly on unique nonces. While specific implementations like SSH face vulnerabilities such as the Terrapin attack, this post focuses on a fundamental flaw: exploiting ChaCha20-Poly1305 under nonce reuse.

All of the code I put in [here](https://github.com/r1muru2006/r1muru2006.github.io/tree/main/static/script/streamcipher)
# Reference
1. [Hệ mã dòng có xác thực](https://tailieu.antoanthongtin.gov.vn/Files/files/site-2/files/Hemadongcoxacthuc.pdf)
2. [Security of Chacha20-Poly1305 by Wikipedia](https://en.wikipedia.org/wiki/ChaCha20-Poly1305#Security)