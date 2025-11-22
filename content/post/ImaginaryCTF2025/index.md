---
title: "ImaginaryCTF 2025"
description: "Đây là các chall mình giải được trong quá trình thi cùng team aespaFanClub."
date: 2025-09-14T14:17:02+07:00
cover: /images/imaginary.jpg
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
categories:
    - CTF Write-up
---
> Shout out to others member for trying their best and reached the top 15 of the world, ranked 1st University of Technology.

## leaky-rsa
![image](https://hackmd.io/_uploads/HJRRJ-hqxl.png)
`chall.py`
```python
#!/usr/local/bin/python3
import json
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import randbelow, token_bytes
from hashlib import sha256

with open('flag.txt') as f:
    flag = f.read()

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537
d = pow(e, -1, (p-1)*(q-1))

key_m = randbelow(n)
key_c = pow(key_m, e, n)

key = sha256(str(key_m).encode()).digest()[:16]
iv = token_bytes(16)
ct = AES.new(key, AES.MODE_CBC, IV=iv).encrypt(pad(flag.encode(), 16))

print(json.dumps({'n': n, 'c': key_c, 'iv': iv.hex(), 'ct': ct.hex()}))

def get_bit(n, k):
    return (n >> k) % 2

for _ in range(1024):
    idx = randbelow(4)
    print(json.dumps({'idx': idx}))
    try:
        response = json.loads(input())
        c = response['c'] % n
        assert c != key_c
        m = pow(c, d, n)
        b = get_bit(m, idx)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError, AssertionError):
        b = 2
    print(json.dumps({'b': b}))
print(key_m)
```


### Phân tích và lời giải
Nhìn sơ qua thì đây là một bài ứng dụng thuật AES-RSA

Sơ đồ chính của thử thách là:
Random `key_m` bé hơn n -> dùng `key_m` mã hóa flag thành `ct` bằng AES mode CBC.
Mặt khác: Dùng RSA mã hóa `key_m` thành `key_c`
Cuối cùng tiết lộ `n, key_c, iv, ct` và cho ta gửi 1024 bản mã. Với mỗi bản mã, tiết lộ 1 bit nằm trong khoảng vị trí thứ 0 đến 3 từ phải qua sau khi giải mã với thuật RSA.

Tuy nhiên trong bài này, `key_m` đã bị leak khi hoàn thành 1024 bản mã và thế là ta có thể giải mã được AES mode CBC ngay
```python
# solution.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
from pwn import *
import json

context.log_level = 'debug'
# io = process(['python3', 'chall.py'])
io = remote("leaky-rsa.chal.imaginaryctf.org", 1337)

io.recvline()
data = json.loads(io.recvline())
n, iv, ct, c = data['n'], bytes.fromhex(data['iv']), bytes.fromhex(data['ct']), data['c']
count = 0
for _ in range(1024):
    idx = json.loads(io.recvline())['idx']
    send = json.dumps({'c': 0}).encode()
    io.sendline(send)
    b = json.loads(io.recvline())['b']
    count += 1
    print(count)
key_m = int(io.recvline().decode())
key = sha256(str(key_m).encode()).digest()[:16]
flag = unpad(AES.new(key, AES.MODE_CBC, IV=iv).decrypt(ct), 16).decode()
print(flag)
```

    Flag: ictf{p13cin9_7h3_b1t5_t0g37her_3f0068c1b9be2547ada52a8020420fb0}

## zkpow
![image](https://hackmd.io/_uploads/rkNys-hcgx.png)

```python
#!/usr/bin/env python3

import hashlib, secrets, json, time

# --- Utility functions ---
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()
def hexf(b: bytes) -> str:
    return b.hex()
def commit_vertex(v: int, color_label: int, nonce: bytes) -> bytes:
    return sha256(b"vertex:" + str(v).encode() + b":" + str(color_label).encode() + b":" + nonce)

# --- Merkle tree helpers ---
def build_merkle_tree(leaves_hex):
    leaves = [bytes.fromhex(h) for h in leaves_hex]
    if len(leaves) == 0:
        return hexf(sha256(b"")), [[sha256(b"")]]
    levels = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i+1] if i+1 < len(cur) else left
            nxt.append(sha256(left + right))
        levels.append(nxt)
        cur = nxt
    return hexf(levels[-1][0]), levels

def merkle_proof_for_index(levels, index):
    proof = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sib_index = idx + 1 if idx + 1 < len(level) else idx
            sibling = level[sib_index]
            proof.append((hexf(sibling), False))
        else:
            sib_index = idx - 1
            sibling = level[sib_index]
            proof.append((hexf(sibling), True))
        idx //= 2
    return proof

def verify_merkle_proof(root_hex, leaf_hex, proof):
    cur = bytes.fromhex(leaf_hex)
    for sibling_hex, sibling_is_left in proof:
        sibling = bytes.fromhex(sibling_hex)
        if sibling_is_left:
            cur = sha256(sibling + cur)
        else:
            cur = sha256(cur + sibling)
    return hexf(cur) == root_hex

# --- Fiat-Shamir edge selection ---
def fiat_shamir_select_index(root_hex, m):
    return int.from_bytes(hashlib.sha256(root_hex.encode()).digest(), "big") % m

# --- Configurable graph generator ---
def make_graph(n_vertices=1000, p_good=0.75, p_bad=0.003):
    coloring = [secrets.randbelow(3) for _ in range(n_vertices)]
    parts = {0: [], 1: [], 2: []}

    for v, c in enumerate(coloring):
        parts[c].append(v)
        edges = []

    for c1 in range(3):
        for c2 in range(c1+1, 3):
            A, B = parts[c1], parts[c2]
            for u in A:
               for v in B:
                   if secrets.randbelow(1_000_000) / 1_000_000 < p_good:
                       edges.append((u, v)) # spice things up :)

    for c in range(3):
        part = parts[c]
        for i in range(len(part)):
            for j in range(i+1, len(part)):
                if secrets.randbelow(1_000_000) / 1_000_000 < p_bad:
                    edges.append((part[i], part[j]))

    return edges, n_vertices

# --- zkPoW prover ---
def zkpow_prove(edges, coloring, n_vertices=1000):
    verts = list(range(n_vertices))

    # permutation + colors
    perm = [0,1,2]
    secrets.SystemRandom().shuffle(perm)
    permuted = {v: perm[coloring[v]] for v in verts}
    nonces = {v: secrets.token_bytes(16) for v in verts}

    leaves_hex = [hexf(commit_vertex(v, permuted[v], nonces[v])) for v in verts]
    merkle_root, levels = build_merkle_tree(leaves_hex)

    # pick single edge
    idx = fiat_shamir_select_index(merkle_root, len(edges))
    u,v = edges[idx]

    # prepare openings
    openings = {}
    for w in (u,v):
        openings[w] = {
            "color": permuted[w],
            "nonce": hexf(nonces[w]),
            "merkle_proof": merkle_proof_for_index(levels, w)
        }

    proof = {
        "merkle_root": merkle_root,
        "openings": openings,
    }
    return json.dumps(proof)

# --- zkPoW verifier ---
def zkpow_verify(proof, edges):
    merkle_root = proof["merkle_root"]
    openings = proof["openings"]

    # verify Merkle proofs
    for v_s, opened in openings.items():
        v = int(v_s)
        leaf_hex = hexf(commit_vertex(v, opened["color"], bytes.fromhex(opened["nonce"])))
        if not verify_merkle_proof(merkle_root, leaf_hex, opened["merkle_proof"]):
            print(f"Merkle proof failed for vertex {v}")
            return False

    # recompute chosen edge
    idx = fiat_shamir_select_index(merkle_root, len(edges))
    u,v = map(str, edges[idx])
    if u not in openings or v not in openings:
        print(f"Missing opening for endpoints of edge {idx}")
        return False
    if openings[u]["color"] == openings[v]["color"]:
        print(f"Edge {idx} endpoints same color -> invalid")
        return False
    return True

def main():
    print("==zk-proof-of-work: enabled==")
    for i in range(50):
        print(f"==round {i}==")
        edges, n_vertices = make_graph(i * 33 + 10, 0.8)
        print(json.dumps({"n": n_vertices, "edges": edges}))
        start = time.time()
        proof = json.loads(input("proof: "))
        end = time.time()
        if end - start > 5:
            print("too slow!")
            exit(-1)
        ok = zkpow_verify(proof, edges)
        if ok:
            print("verified!")
        else:
            print("failed!")
            exit(-1)

    flag = open("flag.txt").read()
    print("flag:", flag)

if __name__ == "__main__":
    main()
```

### Phân tích và lời giải
Ở thử thách này, ta không cần phải tô 3 màu cho đồ thị. Hàm `verify` chỉ kiểm tra hai điểm cuối của một cạnh, và chỉ số cạnh đó là H(merkle_root) % m. Vì ta kiểm soát tất cả các nonce (vì là gốc Merkle) nên có thể thử nonce của một lá cho đến khi thử thách trỏ đến một cạnh có các điểm cuối có màu khác nhau theo bất kỳ màu ngẫu nhiên nào ta chọn. Điều này làm cho mỗi vòng trở nên đơn giản, không cần `backtracking` mà chỉ cần một vài lần băm.

Sau đây là các bước giải:
1. Chọn một màu 3 ngẫu nhiên (bất kỳ màu nào cũng được).
2. Xây dựng cây Merkle một lần.
3. Liên tục điều chỉnh nonce của một lá và tính toán lại gốc Merkle theo từng bước (O(log n) mỗi lần thử).
4. Dừng ngay khi H(root) % m chọn một cạnh có màu khác nhau.
5. Gán hai đỉnh đó cho `openings`
```python
# solution.py
from pwn import *
import json, hashlib, secrets

# ===== Challenge-compatible helpers =====
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def commit_vertex_bytes(v: int, color_label: int, nonce: bytes) -> bytes:
    # EXACT match to the server's commit function (but returns raw bytes)
    return sha256(b"vertex:" + str(v).encode() + b":" + str(color_label).encode() + b":" + nonce)

def fiat_shamir_select_index(root_hex: str, m: int) -> int:
    return int.from_bytes(hashlib.sha256(root_hex.encode()).digest(), "big") % m

# ===== Merkle (bytes throughout, then hex only when serializing the proof) =====
def build_merkle_tree_bytes(leaves):
    """
    leaves: list[bytes]
    returns: (root_bytes, levels)
      levels[0] = leaves (bytes)
      levels[h] = list of bytes at height h
    """
    if not leaves:
        z = sha256(b"")
        return z, [[z]]
    levels = [list(leaves)]
    cur = levels[0]
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i+1] if i+1 < len(cur) else left
            nxt.append(sha256(left + right))
        levels.append(nxt)
        cur = nxt
    return levels[-1][0], levels

def update_leaf_inplace(levels, index, new_leaf):
    """
    Update levels in place after changing one leaf.
    O(log n) hashes up to the root, honoring the 'duplicate last' rule.
    """
    levels[0][index] = new_leaf
    idx = index
    for h in range(0, len(levels) - 1):
        level = levels[h]
        # figure siblings and parent
        if idx % 2 == 0:
            right_idx = idx + 1 if idx + 1 < len(level) else idx
            left = level[idx]
            right = level[right_idx]
            parent = sha256(left + right)
        else:
            left_idx = idx - 1
            left = level[left_idx]
            right = level[idx]
            parent = sha256(left + right)
        # write parent
        levels[h + 1][idx // 2] = parent
        idx //= 2

def merkle_proof_for_index(levels, index):
    """
    Returns proof as list of (sibling_hex, sibling_is_left_bool),
    exactly like the challenge expects.
    """
    proof = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sib_index = idx + 1 if idx + 1 < len(level) else idx
            sibling = level[sib_index]
            proof.append((sibling.hex(), False))  # sibling on the right
        else:
            sib_index = idx - 1
            sibling = level[sib_index]
            proof.append((sibling.hex(), True))   # sibling on the left
        idx //= 2
    return proof

# ===== Core: nonce grinding (no coloring solve needed) =====
def build_and_print_proof(graph_line: bytes) -> str:
    obj = json.loads(graph_line.decode())
    n = obj["n"]
    edges = obj["edges"]  # list of [u, v]
    m = len(edges)

    # 1) Any random 3-coloring works (we only need one good edge per round)
    rng = secrets.SystemRandom()
    colors = [rng.randrange(3) for _ in range(n)]

    # 2) Random nonces for all vertices; build initial tree once
    nonces = [secrets.token_bytes(16) for _ in range(n)]
    leaves = [commit_vertex_bytes(v, colors[v], nonces[v]) for v in range(n)]
    root_bytes, levels = build_merkle_tree_bytes(leaves)

    # 3) Grind a SINGLE leaf's nonce until H(root) % m hits a "good" edge
    pivot = 0  # any index works
    # Keep a small safety cap; expected tries ~ 1.5 because ~2/3 edges are "good"
    max_tries = 4096
    for _ in range(max_tries):
        # new nonce for pivot leaf
        nonces[pivot] = secrets.token_bytes(16)
        new_leaf = commit_vertex_bytes(pivot, colors[pivot], nonces[pivot])
        update_leaf_inplace(levels, pivot, new_leaf)

        root_hex = levels[-1][0].hex()
        idx = fiat_shamir_select_index(root_hex, m)
        u, v = edges[idx]
        if colors[u] != colors[v]:
            # 4) Prepare openings for the challenged edge only
            openings = {}
            for w in (u, v):
                openings[str(w)] = {
                    "color": colors[w],
                    "nonce": nonces[w].hex(),
                    "merkle_proof": merkle_proof_for_index(levels, w)
                }
            proof = {
                "merkle_root": root_hex,
                "openings": openings
            }
            return json.dumps(proof)

    # In practice we should never get here; fallback (recolor & retry once)
    colors = [rng.randrange(3) for _ in range(n)]
    nonces = [secrets.token_bytes(16) for _ in range(n)]
    leaves = [commit_vertex_bytes(v, colors[v], nonces[v]) for v in range(n)]
    root_bytes, levels = build_merkle_tree_bytes(leaves)
    for _ in range(max_tries):
        nonces[pivot] = secrets.token_bytes(16)
        new_leaf = commit_vertex_bytes(pivot, colors[pivot], nonces[pivot])
        update_leaf_inplace(levels, pivot, new_leaf)
        root_hex = levels[-1][0].hex()
        idx = fiat_shamir_select_index(root_hex, m)
        u, v = edges[idx]
        if colors[u] != colors[v]:
            openings = {}
            for w in (u, v):
                openings[str(w)] = {
                    "color": colors[w],
                    "nonce": nonces[w].hex(),
                    "merkle_proof": merkle_proof_for_index(levels, w)
                }
            proof = {
                "merkle_root": root_hex,
                "openings": openings
            }
            return json.dumps(proof)

    # If still unlucky, bail so you can inspect
    raise RuntimeError("Grinding failed unexpectedly")

# ===== Runner =====
def main():
    context.log_level = "error"  # keep pwntools quiet & fast

    # io = process(['python3', 'zkpow.py'])
    io = remote("zkpow.chal.imaginaryctf.org", 1337)

    # banner
    io.recvline()
    io.recvline()
    for i in range(50):
        io.recvline()          # "==round i=="
        graph_line = io.recvline()  # JSON line with n & edges

        proof = build_and_print_proof(graph_line)
        io.sendline(proof.encode())

        res = io.recvline().decode().strip()
        # print progress without slowing down
        print(f"Round {i+1}: {res}")

    # flag
    print(io.recvline().decode().strip())

if __name__ == "__main__":
    main()
```
    Flag: ictf{zero_knowledge_proof_more_like_i_have_zero_knowledge_of_how_to_prove_this}

## scalar-division
![image](https://hackmd.io/_uploads/SkB5UpJigx.png)

```python
# chall.sage
assert ((E:=EllipticCurve(GF(0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21),[5,7])).order().factor(limit=2**10)[3][0]*E.lift_x(ZZ(int.from_bytes((flag:=input('ictf{')).encode())))).x() == 0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5 and not print('\033[53C\033[1A}')
```

### Phân tích và lời giải
`assert` kiểm tra: nếu điểm có hoành độ là `Q.xy()[0]` lift và nhân với k thì nó phải bằng target_x. Tức là `assert(k * lift_x(x_Q)).x() == target_x`.

Ý tưởng chính:
Nguyên lý dùng ở đây là: nếu thứ tự nhóm điểm của elliptic curve là n và n có một nhân tử là k, thì phép nhân $[k]:P\rightarrow kP$ không phải là đơn ánh mà nó tồn tại một nhân tử (kernel) thứ bậc k.

Source
If n is a positive integer, we denote by $E(\mathbb{Q})[n]$ the subgroup of rational points of order dividing n, which is the kernel of the multiplication map from E to itself.
https://johncremona.github.io/book/fulltext/chapter3.pdf

Bằng cách dựng $Q = k^{-1} * R$ và sau đó cộng mọi phần tử thuộc kernel (jS), ta thu được nhiều $x_Q$ sao cho khi nhân k vẫn trả về R (tức là target_x).
```python
# solution.py
from sage.all import *
from Crypto.Util.number import long_to_bytes
import string

p = 0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21
E = EllipticCurve(GF(p), [5,7])
n = E.order()
fac = n.factor(limit=2**10)
k = int(fac[3][0])

target_x = 0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5

m = n // k

R = E.lift_x(ZZ(target_x))
k_inv_mod_m = inverse_mod(k, m)
Q = k_inv_mod_m * R

assert ((E:=EllipticCurve(GF(0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21),[5,7])).order().factor(limit=2**10)[3][0]*E.lift_x(ZZ(Q.xy()[0]))).x() == 0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5 and not print('\033[53C\033[1A}')

# S được chọn sao cho nhóm con sinh bởi S có kích thước k (tức là kS = O)
S = E.lift_x(ZZ(1908615609373310359393680708495309867245478461545179513106385994207950225114719305735749421285909081171302218073610177595))

lst = []
for j in range(k):
    Pj = Q + j * S
    x = int(Pj.xy()[0])
    b = long_to_bytes(x).decode('utf-8', errors='ignore')
    if all(ch in string.printable for ch in b):
        print(b)
```
    Flag: ictf{mayb3_d0nt_m4ke_th3_sca1ar_a_f4ctor_0f_the_ord3r}

## redacted
![image](https://hackmd.io/_uploads/SkhUIKHolx.png)
![image](https://hackmd.io/_uploads/Syuj8tHixg.png)

### Phân tích và lời giải
Theo lẽ thường, qua phép XOR thì 2 giá trị như nhau sẽ cho ra giá trị 0. Tuy nhiên, ở đây cùng 1 giá trị nhưng lại cho ra 1 output có giá trị khác 0... Là bởi phần key của phép XOR không phải dạng ASCII mà là dạng hex nên nó sẽ chỉ lấy những giá trị trong hệ thập lục phân.

Ở đây, phần key của CyberChef dạng hex được lấy theo kiểu sau:
```python
def cyberchef_hexparse(a):
    h = ''
    for ch in a:
        if ch in string.hexdigits:
            h += ch
            if ' ' not in h[-2:]:
                h += ' '
        else:
            h += ' '
    return bytes([int(x, 16) for x in h.split()])
```

Với bài này thì mình thử brute-force và mong rằng độ dài key là nhỏ :3 
```python
# solution.py
#!/bin/python

import string

def cyberchef_hexparse(a):
    h = ''
    for ch in a:
        if ch in string.hexdigits:
            h += ch
            if ' ' not in h[-2:]:
                h += ' '
        else:
            h += ' '
    return bytes([int(x, 16) for x in h.split()])

def cyberchef_xor(a, key):
    return bytes(a[i] ^ key[i % len(key)] for i in range(len(a)))

OUTPUT = bytes.fromhex('656cce6bc175617e5366c952d86c6a536e6ede52df636d7e757fce64d56373')
FLAG_PREFIX = b'ictf{'
key_prefix = cyberchef_xor(FLAG_PREFIX, OUTPUT[:len(FLAG_PREFIX)])

for attempt_length in range(len(key_prefix), len(OUTPUT) // 2):
    print(f'{attempt_length = }')
    for attempt in range(256 ** (attempt_length - len(key_prefix))):
        key = key_prefix + attempt.to_bytes(attempt_length - len(key_prefix))
        flag = cyberchef_xor(OUTPUT, key)
        if flag.isascii() and cyberchef_hexparse(flag.decode()) == key:
            print(f'Found: {flag}')
            exit(0)
```
    Flag: ictf{xor_is_bad_bad_encryption}
    
## leaky-rsa-revenge

![image](https://hackmd.io/_uploads/HJ8iRtLjge.png)

`chall.py`
```python
#!/usr/local/bin/python3
import json
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import randbelow, token_bytes
from hashlib import sha256

with open('flag.txt') as f:
    flag = f.read()

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537
d = pow(e, -1, (p-1)*(q-1))

key_m = randbelow(n)
key_c = pow(key_m, e, n)

key = sha256(str(key_m).encode()).digest()[:16]
iv = token_bytes(16)
ct = AES.new(key, AES.MODE_CBC, IV=iv).encrypt(pad(flag.encode(), 16))

print(json.dumps({'n': n, 'c': key_c, 'iv': iv.hex(), 'ct': ct.hex()}))

def get_bit(n, k):
    return (n >> k) % 2

for _ in range(1024):
    idx = randbelow(4)
    print(json.dumps({'idx': idx}))
    try:
        response = json.loads(input())
        c = response['c'] % n
        assert c != key_c
        m = pow(c, d, n)
        b = get_bit(m, idx)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError, AssertionError):
        b = 2
    print(json.dumps({'b': b}))
```

### Phân tích
Thử thách này đã sửa lỗi của bài trước bằng cách bỏ phần leak `key_m` ở cuối.
Ta được cung cấp các tham số như sau:
- `n`: tích của hai số nguyên tố 512 bit `p` và `q`
- `e`: Khóa công khai, có giá trị bằng `65537`
- `key_c`: là khóa `key_m` sau khi được mã hóa RSA với `n` và `e`
- `iv`: Là init vector khi mã hóa AES `flag` bằng khóa là `sha256` của `key_m`
- `ct`: Là mã hóa AES của `flag`.

Đề bài cho phép ta gửi lần lượt 1024 số và nhận một trong các bit thứ 0-3 của giải mã RSA của các số đó:
```python
for _ in range(1024):
    idx = randbelow(4)
    print(json.dumps({'idx': idx}))
    try:
        response = json.loads(input())
        c = response['c'] % n
        assert c != key_c
        m = pow(c, d, n)
        b = get_bit(m, idx)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError, AssertionError):
        b = 2
    print(json.dumps({'b': b}))
```

=> Ta phải khôi phục lại khóa `key_m` (từ đây gọi tắt là `m`) để lấy flag.
### Hướng giải
Bài này tương tự như tấn công LSB oracle.

https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack


Để tấn công, ta gửi $(2^{e \times i} \mod n)*c$ để giải mã và nhận $(((2^i\mod n) \times m) \mod n) \mod 2$.
Để ý rằng $((2^{i+1}\mod n) \times m) \mod n$ bằng $((2^i\mod n) \times m) \mod n$ và trừ cho $0$ hoặc $n$, tùy thuộc vào việc $((2^i\mod n) \times m) \mod n$ lớn hơn hay nhỏ hơn $\dfrac{n}{2}$.
Vì vậy, việc so sánh $(((2^i\mod n) \times m) \mod n) \mod 2$ và $(((2^{i+1}\mod n) \times m) \mod n) \mod 2$ cho ta MSB của $(2^i\mod n) \times m$. Ở đây, ta nhận được ngẫu nhiên một trong bốn bit thấp.

Đầu tiên, ta thử các trường hợp cho đến khi ta nhận được $n\equiv -1 \mod 16$.
Bây giờ, giả sử ta nhận được LSB thứ ba (chỉ số 2, vị trí thứ tư). Ta có thể gửi $(2^{e \times (i+3)} \mod n)*c$ và nhận lại $((8\times (2^i\mod n) \times m) \mod n)$ & 4.

Như vậy, $$((8\times (2^i\mod n) \times m) \mod n) & 4 =int((((8\times (2^i\mod n) \times m) \mod n)\mod  8) \ge 4)$$ và giá trị $((8\times (2^i\mod n) \times m) \mod n)\mod  8$ là bit đúng sai của đẳng thức $$0-n\times \lfloor\dfrac{(8\times (2^i\mod n) \times m)}{n}\rfloor\mod 8 =\lfloor\dfrac{(8\times (2^i\mod n) \times m)}{n}\rfloor\mod 8$$

Giá trị này cho chúng ta biết $(2^i \mod n) \times m$ nằm trong khoảng nào trong số các khoảng $[0, n/8), ..., [7*n/8, n)$, nhưng chúng ta chỉ nhận được MSB của nó (từ $\ge 4$ hoặc & 4), vì vậy về cơ bản chúng ta chỉ nhận được một MSG của $(2^i \mod n) \times m$.
Lặp lại điều này sẽ cho phép chúng ta thu được toàn bộ `m`.

Về bản chất, phương pháp này là binary-search trên phần fractional m/n: mỗi bit thu được sẽ cho ta cắt đôi khoảng hiện tại (giống LSB-oracle). Dùng việc hỏi “bit của octant” là một biến thể nhưng về lượng thông tin mỗi truy vấn vẫn ~1 bit, do đó độ phức tạp tương đương LSB-oracle cơ bản.

Sau đây là phần code giải:
```python
# get_key_m.py
from fractions import Fraction
from pwn import *
import json

# context.log_level = 'debug'
def get_data():
    # target = process(["python3", "chall.py"])
    target = remote('leaky-rsa-revenge.chal.imaginaryctf.org', 1337)
    target.recvline()
    data = target.recvline()
    params = json.loads(data)

    c = int(params['c'])
    n = int(params['n'])
    iv = params['iv']
    ct = params['ct']
    e = 65537
    
    return target, n, e, c, iv, ct

target, n, e, c, iv, ct = get_data()
while n & 0xf != 0xf:
    target.close()
    target, n, e, c, iv, ct = get_data()

open("ct.hex", "w").write(json.dumps({'iv': iv, 'ct': ct}))

print("n:", n)
print("c:", c)


low, high = Fraction(0), Fraction(n)

for _ in range(n.bit_length()):
    x = json.loads(target.recvline())['idx']
    print("----------------------")
    print(f"Round {_}, idx: {x}")
    c_i = c * pow(2**(_+1+x), e, n)% n
    target.sendline(json.dumps({'c': c_i}))
    parity = json.loads(target.recvline())['b']
    print("parity:", parity)
    mid = (low + high) / 2
    if parity == 0:
        high = mid
    else:
        low = mid
    if high - low <= Fraction(1, n):
        break
    print(f"low: {int(low)}")
    print(f"high: {int(high)}")
    print(f"high - low: {int(high - low)}")

print(int(high))
```

```python
# get_flag.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import json
with open("ct.hex", "r") as f:
    data = json.loads(f.read())
iv, ct = bytes.fromhex(data["iv"]), bytes.fromhex(data["ct"])
# copy key_m from the result
key_m = 66913879129427921532141095805213088350786068884711371183610467808888726432628555235077071240182816868700010352314530781554928879532699339797452869208244793928847297090122325104212375055788476001149144065203543329623887717342649312948304461426083404294042817825376050063313290113639594521177002093126711190702
key = sha256(str(key_m).encode()).digest()[:16]
flag = unpad(AES.new(key, AES.MODE_CBC, IV=iv).decrypt(ct), 16).decode()
print(flag)
```
    Flag: ictf{p13cin9_7h3_b1t5_t0g37her_7d092f5d43ebbf6fa60fba8c9e9ac4466daba9a71d04def7e5bf09bcce5649c8}
    
## clcg
![image](https://hackmd.io/_uploads/HkHj9cLsgl.png)

`chall.py`
```python
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import randbelow, token_bytes
import json

with open('flag.txt') as f:
    flag = f.read().strip()

class CLCG:
    
    def __init__(self, length):
        self.p = getPrime(256)
        self.A = [randbelow(self.p) for _ in range(length)]
        self.C = [randbelow(self.p) for _ in range(length)]
        self.X = [randbelow(self.p) for _ in range(length)]
    
    def rand(self):
        self.X = [(a * x + c) % self.p for a, x, c in zip(self.A, self.X, self.C)]
        return int.to_bytes((sum(self.X) % self.p) >> 192, 8)

NUM_HINTS = 36

clcg = CLCG(8)
data = dict()
data['p'] = clcg.p
data['A'] = clcg.A
data['hints'] = [clcg.rand().hex() for _ in range(NUM_HINTS)]

key = clcg.rand() + clcg.rand()
iv = token_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
data['iv'] = iv.hex()
data['ct'] = cipher.encrypt(pad(flag.encode(), 16)).hex()

print(json.dumps(data))
```

### Phân tích đề bài
- p, A, C, X lần luợt là số nguyên tố 256 bit và các list gồm 1 độ dài nhất định (theo đề là 8) các giá trị ngẫu nhiên bé hơn p.
- Hàm `rand()` cho đầu ra là top 64 bit đầu của tổng S là 8 giá trị LCG không phụ thuộc modulo p của các cặp (A, X, C) tương ứng và gán X mới lần lượt là 8 giá trị LCG này. $$X^{(i)}_{t+1}\equiv a_i\times X^{(i)}_t+c_i\mod p,i=[1, 8]$$ $$S =\displaystyle \sum_{i=1}^8 X_t^{(i)}\mod p$$
- Lấy hàm `rand()` 36 lần rồi lấy 2 lần tiếp theo làm key cho chế độ mã hóa AES mode CBC với iv là ngẫu nhiên và plaintext là flag.
```python
data['hints'] = [clcg.rand().hex() for _ in range(36)]

key = clcg.rand() + clcg.rand()
iv = token_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
```
### Hướng giải
Hint from admin

Note that if `x1 = a*x0 + c` then `x1 + c/(a-1) = a*x0 + ac/(a-1) = a(x0 + c/(a-1))` so `xi = C*a**i - c/(a-1)`. If we add up 8 LCGs, it will be of the form `sum(Cj*aj**i for j) - D`, and taking the partial differences gets rid of `D`. We now note that this satisfies the linear recurrence whose characteristic polynomial is `prod(x - aj for j)`. We use this recurrence to build a lattice that will be `0` mod `p` when multiplied by the vector of true differences between state sums. 

#### Khai thác từ LCG cho trước
Từ phép biến đổi affine LCG ta sẽ thử tạo chuỗi cấp số và trình bày công thức.
Giả sử, tồn tại $k$ sao cho: $$X^{(i)}_{t+1} + k\equiv a_i\times (X^{(i)}_t+k)\mod p,i=[1, 8]$$

$$\Leftrightarrow (a_i-1)\times k\equiv c\mod p,i=[1, 8]\Leftrightarrow k\equiv \dfrac{c}{a_i-1}\mod p,i=[1, 8]$$

Như vậy, ta hoàn toàn có thể biến đổi dãy trên thành dãy số hệ số nhân $$C^{(i)}_{t+1}\equiv a_i\times C^{(i)}_t\mod p,i=[1, 8]$$, với $C_i = X_i+\dfrac{c}{a_i-1}\mod p,i=[1, 8]$

Do đó, tổng S biến đổi thành:$$S\equiv \displaystyle \sum_{j=1}^8 K_ja^i_j-D\mod p$$
Có nghĩa là nếu ta lấy từng cặp hiệu của S đôi một liên tiếp thì nó sẽ khử D
($\Delta S_i=S_{i+1}-S_i$), để lại tổng của các thừa số thỏa mãn hồi quy tuyến tính bậc 8 với đa thức đặc trưng là:
$$m(x)=\displaystyle \prod_{j=1}^8(x-a_j)\in \mathbb{F}_p[x]$$

#### Khôi phục lại $\Delta S_t$
Theo đề bài, ta sẽ tách $\Delta S_t$ thành $2^{192}\Delta b_t+d_t$ với $d_t\in (-2^{192}, 2^{192})$

Từ phép hồi quy trên, suy ra được: $$\displaystyle \sum_{k=0}^8c_k\Delta S_{t+k}\equiv 0 \mod p\ \ (1)$$

Vì vậy, khi ta sử dụng phép tách trên, $(1)$ sẽ trở thành phương trình đồng dư tuyến tính modulo p với ẩn $d_t$

```python
from Crypto.Cipher import AES
from sage.all import *
import json

with open("out.txt") as f:
    out = json.load(f)

p = out["p"]
A = out["A"]
hints = [int(hint, 16) for hint in out["hints"]]
last = hints[-1] << 192
hints = [hints[i + 1] - hints[i] for i in range(len(hints) - 1)]
ct = bytes.fromhex(out["ct"])
iv = bytes.fromhex(out["iv"])


def decrypt(rand1, rand2):
    cipher = AES.new(
        int.to_bytes(rand1, 8) + int.to_bytes(rand2, 8), AES.MODE_CBC, iv=iv
    )
    return cipher.decrypt(ct)


x = PolynomialRing(GF(p), "x").gen()
rec = list(map(int, prod(x - a for a in A)))
L = [
    [0 for _ in range(i)] + rec + [0 for _ in range(len(hints) - len(rec) - i)]
    for i in range(len(hints) - len(rec) + 1)
] + [[p * int(i == j) for j in range(len(hints))] for i in range(len(rec) - 1)]
L = Matrix(ZZ, L)

B = L.LLL()
yprime = (2**192) * vector(ZZ, hints)
Byprime = B * yprime
v = vector(ZZ, [round(i / p) for i in Byprime])
Bzprime = v * p - Byprime
zprime = (B ** (-1)) * Bzprime
# print([len(bin(i)) for i in zprime]) - debug - should be around 192

xprime = list(yprime + zprime)
for _ in range(2):
    xprime.append((-vector(rec[:-1]) * vector(xprime[-len(rec) + 1 :])) % p)
rand1 = ((last + xprime[-2]) % p) >> 192
rand2 = ((last + xprime[-2] + xprime[-1]) % p) >> 192
for r1 in range(rand1 - 4, rand1 + 4):
    for r2 in range(rand2 - 4, rand2 + 4):
        flag = decrypt(r1, r2)
        if b"ictf" in flag:
            print(flag)
```
    Flag: ictf{y3t_an07h3r_lcg_ch411_7b24ac314588057bfd4b70b10585a277}

## Bigger-RSA
![image](https://hackmd.io/_uploads/HkRU3tD3eg.png)

`bigger_rsa.sage`
```python
from Crypto.Util.number import getPrime, bytes_to_long
import secrets

n = 32
e = 0x10001
N = 64

flag = b'ictf{REDACTED}'
flag = secrets.token_bytes((n * 63) - len(flag)) + flag

ps = [getPrime(512) for _ in range(n)]

m = 1
for i in ps:
    m *= i

nums = [CRT([1 + secrets.randbits(260) for _ in range(n)],ps) for __ in range(N)]
ct = pow(bytes_to_long(flag),e,m)
print(f"ct={ct}")
print(f"m={m}")
print(f"nums={nums}")
```

## Tài liệu
1. (scalar-division): https://johncremona.github.io/book/fulltext/chapter3.pdf
2. (zkpow): 
- https://en.wikipedia.org/wiki/Merkle_tree
- https://en.wikipedia.org/wiki/Zero-knowledge_proof
- https://blog.codeminer42.com/zero-knowledge-proofs-and-merkle-trees-an-overview-before-diving-into-it/
3. (leaky-rsa-revenge): https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack
4. (clcg):
- https://en.wikipedia.org/wiki/Linear_congruential_generator
- https://crypto.stackexchange.com/questions/2086/predicting-values-from-a-linear-congruential-generator