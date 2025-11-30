# rc4.py - Simple RC4 (KSA + PRGA)
def rc4_ksa(key: bytes):
    keylen = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        yield K

def rc4_stream(key: bytes, data: bytes) -> bytes:
    S = rc4_ksa(list(key))
    gen = rc4_prga(S)
    out = bytearray(len(data))
    for idx, b in enumerate(data):
        out[idx] = b ^ next(gen)
    return bytes(out)

# Usage:
# key = b"secret"
# plaintext = b"Hello world"
# ciphertext = rc4_stream(key, plaintext)
# recovered = rc4_stream(key, ciphertext)   # same op recovers plaintext
