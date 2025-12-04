from tqdm import trange
from pwn import *

context.log_level = "error"
io = process(["python3", "chall.py"])
secret = []

A = 0
while True:
    probs = [0] * 256
    
    for v in trange(256):
        ct = b'00'
        nonce = bytes([A + 3, 255, v])
        io.sendlineafter(b": ", ct)
        io.sendlineafter(b": ", nonce.hex().encode())
        ks = int(io.recvline().split(b": ")[1], 16)

        key = nonce + bytes(secret)
        S = list(range(256))
        j = 0
        for i in range(A + 3):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
            if i == 1:
                o0, o1 = S[0], S[1]

        i = A + 3
        if S[1] < i and (S[1] + S[S[1]]) == i:
            if o0 != S[0] or o1 != S[1]:
                continue
            key_byte = (ks - j - S[i]) % 256
            probs[key_byte] += 1

    found = probs.index(max(probs))
    secret.append(found)
    print(bytes(secret))

    if found == 125:
        break

    A += 1

print("FLAG:", bytes(secret))