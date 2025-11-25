---
title: "Is stream encryption secure?"
description: "Today I will go over some stream ciphers and learn how they can be exploited by attackers."
date: 2025-11-25T14:33:54+07:00
cover: /images/patriot/patriot.png
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