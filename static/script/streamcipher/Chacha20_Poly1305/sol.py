from pwn import process, xor
from sage.all import *

io = process(['python3', 'chall_chacha20_poly1305.py'])
def recv_data():
    io.recvuntil(b'(hex):')
    return bytes.fromhex(io.recvline().strip().decode())
to_int = lambda b: int.from_bytes(b, 'little')
clamp_check = lambda r: (r & 0x0ffffffc0ffffffc0ffffffc0fffffff) == r

pt1, ct1, pt2, ct2 = [recv_data() for _ in range(4)]
parse = lambda ct: (ct[:-28], to_int(ct[-28:-12]), ct[-12:])
c1, t1, n1 = parse(ct1)
c2, t2, n2 = parse(ct2)

p = 2**130 - 5
R = PolynomialRing(GF(p), 'r')
r_sym = R.gen()

def make_poly(data):
    padded = data + b'\x00' * ((16 - len(data) % 16) % 16)
    msg = padded + (0).to_bytes(8, 'little') + len(data).to_bytes(8, 'little')
    coeffs = [to_int(msg[i:i+16] + b'\x01') for i in range(0, len(msg), 16)]
    return sum(c * r_sym**(len(coeffs)-i) for i, c in enumerate(coeffs))

poly_diff = make_poly(c1) - make_poly(c2)
delta_tag = t1 - t2
r, s = None, None

for k in range(-5, 6):
    roots = (poly_diff - (delta_tag + k * 2**128)).roots()
    for r_val, _ in roots:
        r_int = int(r_val)
        if clamp_check(r_int):
            val_poly1 = int(make_poly(c1)(r_int))
            s_cand = (t1 - val_poly1) % 2**128
            val_poly2 = int(make_poly(c2)(r_int))
            if (t2 - val_poly2) % 2**128 == s_cand:
                r, s = r_int, s_cand
                break
    if r: break

print(f"r: {hex(r)}")
print(f"s: {hex(s)}")

goal = b"But it's only secure if used correctly!"
ks = xor(c1, pt1)
forge_ct = xor(goal, ks[:len(goal)])

newtag = (int(make_poly(forge_ct)(r)) + s) % 2**128
payload = forge_ct + newtag.to_bytes(16, 'little') + n1

io.sendline(payload.hex().encode())
print(io.recvall(timeout = 1.0).decode())
io.close()