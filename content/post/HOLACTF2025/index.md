---
title: "HOLACTF 2025"
description: "Sau đây là những bài mình làm được trong thời gian của giải với tổng là 6 bài với 3 bài crypto, 2 bài misc và 1 bài osint."
date: 2025-09-09T08:42:30+07:00
cover: /images/holactf.jpg
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
    - Miscellaneous
    - Osint
categories:
    - CTF Write-up
---

## Crypto
### 1. Cs2RTrash
![image](https://hackmd.io/_uploads/B16EYV-qgl.png)
```python
# chall.py
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

e = 65537
n1 = 106274132069853085771962684070654057294853035674691451636354054913790308627721
n2 = 73202720518342632558813895439681594395095017145510800999002057461861058762579
n3 = 58129476807669651703262865829974447479957080526429581698674448004236654958847
message = b'HOLACTF{...}'
m = bytes_to_long(message)


c1 = pow(m, e, n1)
c2 = pow(m, e, n2)
c3 = pow(m, e, n3)


print(f"c1: {c1}")
print(f"c2: {c2}")
print(f"c3: {c3}")
```
```java
// output.txt
c1: 40409669713698525444927116587938485167766997176959778633087672968720888190012
c2: 50418608792183022472533104230595523000246213655735834753443442906871618770832
c3: 7151799367443802424297049002310776844321501905398348074481144597918413565153
```

Đây chỉ là 1 bài RSA đơn giản và mình để ý rằng n1 là số nguyên tố nên bài này có thể được giải như sau:
```python
# solution.py
from Crypto.Util.number import inverse, long_to_bytes

e = 65537

n1 = 106274132069853085771962684070654057294853035674691451636354054913790308627721
n2 = 73202720518342632558813895439681594395095017145510800999002057461861058762579
n3 = 58129476807669651703262865829974447479957080526429581698674448004236654958847

c1 = 40409669713698525444927116587938485167766997176959778633087672968720888190012
c2 = 50418608792183022472533104230595523000246213655735834753443442906871618770832
c3 = 7151799367443802424297049002310776844321501905398348074481144597918413565153

d1 = inverse(e, n1 - 1)
x = pow(c1, d1, n1)
print(long_to_bytes(x))
```
    Flag: HOLACTF{ju5t_a_b4s1c_CRT}
### 2. EnigmaHardCode
![image](https://hackmd.io/_uploads/rJ_aqNWcee.png)
![image](https://hackmd.io/_uploads/SkGCc4-cge.png)
![image](https://hackmd.io/_uploads/r1OJoEW9lx.png)
```java
// attachment
SWWSAOL{CRK_NTX_AGBXRRLNYQC_ANGQBQHR_TY_QNZ_PPLNFBFXX}
```

Ban đầu mình không biết cuộn tròn xuống là có reflector với plugboard nên đã bỏ qua :333
Khi phát hiện ra thì mình liên kết lại các dữ liệu đã có và tìm được trang [wiki](https://en.wikipedia.org/wiki/Enigma_rotor_details) có để thiết lập enigma machine
![Screenshot 2025-08-31 101011](https://hackmd.io/_uploads/ry14aV-cee.png)

Vì đã biết rotor order, reflector, ring settings và chỉ còn thiếu 1 cặp plugboard nên mình đã brute-force các cặp còn lại đến khi tìm ra flag format phù hợp như sau:
```python
# solution.py
import string, re, time
from itertools import combinations
from multiprocessing import Pool, cpu_count

ALPHA = string.ascii_uppercase
pattern = re.compile(r"HOLACTF\{.*\}")

# Machine parameters (use your exact ones)
ROTOR = {
    "I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
}
REFLECTOR_C = "FVPJIAOYEDRZXWGCTKUQSBNMHL"
ORDER = ("II", "III", "I")
RING = {"II": 4, "III": 7, "I": 2}  # use exactly what you intend
PLUG_KNOWN = ["AO", "DP", "ER", "FT", "IU", "JW", "KZ", "MX"]
MISSING_POOL = list("BCGHLNQSVY")
CIPH = "SWWSAOL{CRK_NTX_AGBXRRLNYQC_ANGQBQHR_TY_QNZ_PPLNFBFXX}"


# Precompute rotor inverse maps
def inv_map(w):
    r = ["?"] * 26
    for i, c in enumerate(w):
        r[ord(c) - 65] = ALPHA[i]
    return "".join(r)


L, M, R = ORDER
LW, Lnot = ROTOR[L]
MW, Mnot = ROTOR[M]
RW, Rnot = ROTOR[R]
LI = inv_map(LW)
MI = inv_map(MW)
RI = inv_map(RW)
rL, rM, rR = RING[L] - 1, RING[M] - 1, RING[R] - 1


# fast decrypt function for one pos/pair
def decrypt_with(pos, extra_pair):
    # Build plug mapping as a list for fast int ops
    pmap = list(range(26))
    for pair in PLUG_KNOWN + ([extra_pair] if extra_pair else []):
        a = pair[0]
        b = pair[1]
        ai = ord(a) - 65
        bi = ord(b) - 65
        pmap[ai] = bi
        pmap[bi] = ai

    pL, pM, pR = [ord(c) - 65 for c in pos]
    out_chars = []
    for ch in CIPH:
        if ch not in ALPHA:
            out_chars.append(ch)
            continue

        # stepping (double-step behavior)
        if ALPHA[pM] == Mnot:
            pM = (pM + 1) % 26
            pL = (pL + 1) % 26
        if ALPHA[pR] == Rnot:
            pM = (pM + 1) % 26
        pR = (pR + 1) % 26

        # plugboard in
        x = pmap[ord(ch) - 65]

        # forward through right, mid, left (account ringoffsets)
        def forward(w, x, p, r):
            idx = (x + p - r) % 26
            return (ord(w[idx]) - 65 - p + r) % 26

        x = forward(RW, x, pR, rR)
        x = forward(MW, x, pM, rM)
        x = forward(LW, x, pL, rL)

        # reflector
        x = ord(REFLECTOR_C[x]) - 65

        # back through left,middle,right (inverse maps)
        def back(iw, x, p, r):
            idx = (x + p - r) % 26
            return (ord(iw[idx]) - 65 - p + r) % 26

        x = back(LI, x, pL, rL)
        x = back(MI, x, pM, rM)
        x = back(RI, x, pR, rR)

        # plugboard out
        out_chars.append(chr(pmap[x] + 65))
    return "".join(out_chars)


# Worker: given a pair (like "BC"), test all positions and return any matches
def worker_for_pair(pair):
    found = []
    pair = "".join(pair)
    for a in ALPHA:
        for b in ALPHA:
            for c in ALPHA:
                pos = a + b + c
                pt = decrypt_with(pos, pair)
                if pattern.search(pt):
                    found.append((pair, pos, pt))
    return found


def main():
    pairs = list(combinations(MISSING_POOL, 2))
    print("Total pairs:", len(pairs))
    nproc = max(1, cpu_count() - 0)
    print("Using processes:", nproc)
    start = time.time()
    with Pool(nproc) as pool:
        # map worker across pairs; each worker tests all 26^3 positions for that pair
        results = pool.map(worker_for_pair, pairs)
    elapsed = time.time() - start
    matches = [m for sub in results for m in sub]
    print("Elapsed:", elapsed, "seconds")
    print("Matches found:", len(matches))
    for pair, pos, pt in matches:
        print("pair", pair, "pos", pos, "->", pt)


if __name__ == "__main__":
    main()
```
Kết quả trả về:
```
Total pairs: 45
Using processes: 12
Elapsed: 7.59969425201416 seconds
Matches found: 1
pair CV pos ULW -> HOLACTF{WAR_DIE_GEHEIMHISSE_WIRKLICH_SO_GUT_VERSTECKP}
```
Tuy nhiên, flag này vẫn chưa chính xác nên mình đã hỏi chatGPT thử thì nhận được prompt: 
```
...
Check adjacent starting positions:
Often the crib falls into place if the initial rotor position is shifted by 1–2 steps. Try decrypting again with positions just before and after ULW (e.g., ULV, ULX, UKW, etc.).

Double-check ring settings vs. rotor positions:
Sometimes code mixes up Ringstellung (internal offset) with Grundstellung (daily key start). If those were off, letters will be slightly wrong throughout.

Test all 45 possible plugboard completions again but only around ULW neighborhood (like ±5 positions). That should be much faster.

Language filter: Since the plaintext is clearly German, you can filter candidates through a simple dictionary check (look for "GEHEIMNISSE" and "VERSTECKT").

👉 I think the true flag should be:
HOLACTF{WAR_DIE_GEHEIMNISSE_WIRKLICH_SO_GUT_VERSTECKT}
```
Submit thử thì nhận được kết quả trả về đúng.

    Flag: HOLACTF{WAR_DIE_GEHEIMNISSE_WIRKLICH_SO_GUT_VERSTECKT}
    
### 3. ImLosingYou
![image](https://hackmd.io/_uploads/HydG1B-5gl.png)
```python
# encrypt.py
from random import getrandbits, FLAG
from Crypto.Util.number import *

e = 2
n = getPrime(256) * getPrime(256)

m = bytes_to_long(FLAG)
mod_m = m - getrandbits(80)
c = pow(m, 2, n)
print(f"n = {n}")
print(f"c = {c}")
print(f"mod_m = {mod_m}")
```
```java
n = 5655306554322573090396099186606396534230961323765470852969315242956396512318053585607579359989407371627321079880719083136343885009234351073645372666488587
c = 249064480176144876250402041707185886135379496538171928784862949393878232927200977890895568473400681389529997203697206006850790029940405682934025
mod_m = 499063603337435213780295973826237775412685978121823376141602090122856806
```
Mình giả sử `FLAG` có độ dài ngắn và thử lấy căn của `c` thì đúng là như vậy:
```python
# solution.py
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot
n = 5655306554322573090396099186606396534230961323765470852969315242956396512318053585607579359989407371627321079880719083136343885009234351073645372666488587
c = 249064480176144876250402041707185886135379496538171928784862949393878232927200977890895568473400681389529997203697206006850790029940405682934025
mod_m = 499063603337435213780295973826237775412685978121823376141602090122856806

pt = iroot(c, 2)[0]
print(long_to_bytes(pt))
```
    Flag: HOLACTF{f33ls_l1k3_l0s1ng_h3r}

## Misc
### 1. LunaDB
![image](https://hackmd.io/_uploads/S1XYxSWclg.png)
```rust=
// main.rs
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, BufRead, Cursor, Seek, SeekFrom};
use std::path::Path;
use std::env;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use openssl::symm::{Cipher, Crypter, Mode};
use hex_literal::hex;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use leb128;
const H_START: [u8; 4] = hex!("FF1337FF");
const H_END:   [u8; 4] = hex!("FFCAFEFF");
const D_START:   [u8; 4] = hex!("FF7270FF");
const D_END:     [u8; 4] = hex!("FFEDEDFF");
const F_START: [u8; 4] = hex!("FFDEADFF");
const F_END:   [u8; 4] = hex!("FFBEEFFF");
const SIG:    [u8; 4] = hex!("4C554E41"); 
enum DbMode<'a> {
    Append { existing: &'a [[u8; 8]] },
    Create,
}
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}
fn get_input(prompt_text: &str) -> io::Result<String> {
    print!("{}", prompt_text);
    io::stdout().flush()?;
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

...

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <lunadb_file>", args[0]);
        process::exit(1);
    }
    let db_path = Path::new(&args[1]);
    let num_notes_to_create: usize = loop {
        match get_input("How many notes do you want to create? ")?.parse() {
            Ok(n) if n > 0 => break n,
            _ => println!("Please enter a valid positive number."),
        }
    };
    if db_path.exists() {
        
        let mut f = Vec::new();
        File::open(&db_path)?.read_to_end(&mut f)?;
        let keys = {
            let start = find_pattern(&f, &F_START).unwrap() + F_START.len();
            let end   = find_pattern(&f, &F_END).unwrap();
            (&f[start..end]).chunks_exact(8)
                         .map(|c| c.try_into().unwrap())
                          .collect::<Vec<[u8;8]>>()
        };
        let next_id = get_next_id(&f)?;
        let (notes, _, _) = build(DbMode::Append { existing: &keys }, num_notes_to_create, next_id)?;
        write_db(&db_path, None, Some(&f), &notes, &[])?;
        println!("Appended {} notes", num_notes_to_create);
    } else {
        let header = Header {
            db_name:  get_input("Database Name: ")?,
            reg_name: get_input("Registered Name: ")?,
            license_key: get_input("License Key: ")?.into_bytes(),
        };
        let (notes, keys, _) = build(DbMode::Create, num_notes_to_create, 1)?;
        write_db(&db_path, Some(header), None, &notes, &keys)?;
        println!("Created new DB with {} notes", num_notes_to_create);
    }
    Ok(())
}
```
Đề cho ta hai tệp `main.rs` và `secret.lunadb`, với yêu cầu đọc tệp secret.
Từ `main.rs` thì mình biết được rằng:
- Ghi chú được mã hóa bằng DES-ECB
- Key được lưu trữ trong phần `F_START..F_END` (khối 8-bytes)
- Mỗi ghi chú có một `key_index_field`.
- Mảng string/byte sử dụng tùy chỉnh `tag + LEB128 length + data format`.

Sau đó, mình nhờ chatGPT tạo ra 1 cái decryptor thỏa mãn và dừng khi thấy flag format:
```python
# solution.py
import struct
from io import BytesIO
from Crypto.Cipher import DES

# ---- Constants (magic markers) ----
H_START = bytes.fromhex("FF1337FF")
H_END   = bytes.fromhex("FFCAFEFF")
D_START = bytes.fromhex("FF7270FF")
D_END   = bytes.fromhex("FFEDEDFF")
F_START = bytes.fromhex("FFDEADFF")
F_END   = bytes.fromhex("FFBEEFFF")
SIG     = b"LUNA"

# ---- Helpers ----
def find_pattern(data: bytes, pattern: bytes) -> int:
    """Find pattern inside data and return its position."""
    pos = data.find(pattern)
    if pos == -1:
        raise ValueError(f"Pattern {pattern.hex()} not found")
    return pos

def read_uleb128(f: BytesIO) -> int:
    """Read unsigned LEB128 integer."""
    result, shift = 0, 0
    while True:
        b = f.read(1)
        if not b:
            raise EOFError("Unexpected EOF in LEB128")
        b = b[0]
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result

def read_string(f: BytesIO) -> str:
    """Read custom encoded string (flag + LEB128 + data)."""
    flag = f.read(1)
    if not flag:
        raise EOFError("Unexpected EOF reading string")
    flag = flag[0]
    if flag == 0x00:
        return ""
    elif flag == 0x0b:
        length = read_uleb128(f)
        return f.read(length).decode("utf-8", errors="replace")
    elif flag == 0x0c:
        length = read_uleb128(f)
        return f.read(length).decode("utf-8", errors="replace")
    else:
        raise ValueError(f"Invalid string flag {flag:#x}")

def read_bytes(f: BytesIO) -> bytes:
    """Read custom encoded byte string."""
    flag = f.read(1)
    if not flag:
        raise EOFError("Unexpected EOF reading bytes")
    flag = flag[0]
    if flag == 0x00:
        return b""
    elif flag == 0x0c:
        length = read_uleb128(f)
        return f.read(length)
    elif flag == 0x0b:
        length = read_uleb128(f)
        return f.read(length)
    else:
        raise ValueError(f"Invalid byte flag {flag:#x}")

def des_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt DES-ECB with padding removal."""
    cipher = DES.new(key, DES.MODE_ECB)
    pt = cipher.decrypt(data)
    padlen = pt[-1]
    if 1 <= padlen <= 8 and pt.endswith(bytes([padlen])*padlen):
        pt = pt[:-padlen]
    return pt

# ---- Main LunaDB Parser ----
def parse_lunadb(filename: str):
    with open(filename, "rb") as f:
        data = f.read()

    # Validate
    if not data.startswith(SIG):
        raise ValueError("Not a valid LunaDB file")

    # Extract sections
    d_start = find_pattern(data, D_START) + len(D_START)
    d_end   = find_pattern(data, D_END)
    f_start = find_pattern(data, F_START) + len(F_START)
    f_end   = find_pattern(data, F_END)

    notes_section = data[d_start:d_end]
    keys_section  = data[f_start:f_end]

    # Parse keys
    keys = [keys_section[i:i+8] for i in range(0, len(keys_section), 8)]

    # Parse notes
    fnotes = BytesIO(notes_section)
    notes = []
    while fnotes.tell() < len(notes_section):
        try:
            note_id = struct.unpack("<H", fnotes.read(2))[0]
        except:
            break

        access_token = read_string(fnotes)
        first_name   = read_string(fnotes)
        last_name    = read_string(fnotes)
        email        = read_string(fnotes)
        title        = read_string(fnotes)

        key_index_field = struct.unpack("<Q", fnotes.read(8))[0]
        encrypted_content = read_bytes(fnotes)
        creation_date = struct.unpack("<Q", fnotes.read(8))[0]
        modification_date = struct.unpack("<Q", fnotes.read(8))[0]
        suspended = struct.unpack("<B", fnotes.read(1))[0]

        # Which key was used?
        plaintext = None
        if key_index_field != 0xFFFFFFFFFFFFFFFF:
            for idx in range(64):
                if key_index_field & (1 << idx):
                    if idx < len(keys):
                        try:
                            plaintext = des_decrypt(keys[idx], encrypted_content).decode("utf-8", errors="replace")
                        except Exception as e:
                            plaintext = f"<decrypt error: {e}>"
                    break
        else:
            plaintext = "<no content>"

        notes.append({
            "id": note_id,
            "title": title,
            "author": f"{first_name} {last_name}",
            "email": email,
            "content": plaintext,
            "suspended": suspended,
            "access_token": access_token,
        })

    return notes

# ---- Run ----
if __name__ == "__main__":
    import sys, json
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <lunadb_file>")
        sys.exit(1)

    notes = parse_lunadb(sys.argv[1])
    for n in notes:
        print("="*40)
        print(f"Note ID: {n['id']}")
        print(f"Title: {n['title']}")
        print(f"Author: {n['author']} <{n['email']}>")
        print(f"Access Token: {n['access_token']}")
        print(f"Suspended: {n['suspended']}")
        print(f"Content:\n{n['content']}")
        if "HOLACTF{" in n['content']:
            break
```
Kết quả trả về:
```java
...
Note ID: 2976
Title: coding
Author: Candice Debroux <Candice_Debroux@gmx.com>
Access Token: 7zVjVolwo0ZOXwnbexQEx7YsxyelEekQ
Suspended: 0
Content:
Programming today is a race between software engineers striving to build bigger and better idiot-proof programs and the Universe trying to produce bigger and better idiots. So far, the Universe is winning. 
========================================
Note ID: 7272
Title: This is real flag
Author: lunaere the secret agent <luna@osu.me>
Access Token: ZEBD9aJy8iMuGBqUaa1yUKoXvddvGLra
Suspended: 1
Content:
HOLACTF{4_c0Ol_Cu5t0m_f1lE_5truC7}
```
    Flag: HOLACTF{4_c0Ol_Cu5t0m_f1lE_5truC7}

### 2. Weird PNG
![image](https://hackmd.io/_uploads/Bkx6VSb5eg.png)

Đề cho ta một file `weird.png` và khi phân tích, ta được:
```javascript
➜  build git:(master) ✗ xxd weird.png
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 00ff 0000 00ff 0802 0000 0000 0000  ................
00000020: 008c c88e d88e c0b8 c007 8ed0 bc00 7c83  ..............|.
00000030: ec01 89e5 c646 0000 b85f 7d50 b832 3750  .....F..._}P.27P
00000040: b85f 3750 b821 4035 1212 50b8 bccc 3588  ._7P.!@5..P...5.
00000050: 8850 b8a8 a935 9999 50b8 5b78 350f 2750  .P...5..P.[x5.'P
00000060: b807 5c35 3713 50b8 2815 3577 7750 b85c  ..\57.P.(.5wwP.\
00000070: 3035 6969 50b8 5348 3560 0950 b864 5935  05iiP.SH5`.P.dY5
00000080: 2222 50b8 5245 3511 1150 b86d 0235 2143  ""P.RE5..P.m.5!C
00000090: 50b8 7c5d 3534 1250 89e5 8a46 0045 08c0  P.|]54.P...F.E..
000000a0: 740a b40e b700 b307 cd10 ebee ebfe 0000  t...............
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................

...

000001f0: 0000 0000 0000 0000 0000 0000 0000 55aa  ..............U.
```
Ở đây, sau IHDR đáng ra phải có CRC rồi tới các chunk như IDAT, IEND. Tuy nhiên, ta lại thấy byte như mã máy x86 và khi hỏi chatGPT thì được trả lời là: File không phải PNG thật, mà là MBR boot sector 512 bytes được bọc đầu PNG hợp lệ.
Vì vậy mình đã lấy chuỗi được in ra và nhờ AI tạo script python giải mã:
```python
data = bytes.fromhex(
"8c c8 8e d8 8e c0 b8 c0 07 8e d0 bc 00 7c 83 ec 01 89 e5 c6 46 00 00 "
"b8 5f 7d 50 b8 32 37 50 b8 5f 37 50 b8 21 40 35 12 12 50 b8 bc cc 35 "
"88 88 50 b8 a8 a9 35 99 99 50 b8 5b 78 35 0f 27 50 b8 07 5c 35 37 13 "
"50 b8 28 15 35 77 77 50 b8 5c 30 35 69 69 50 b8 53 48 35 60 09 50 b8 "
"64 59 35 22 22 50 b8 52 45 35 11 11 50 b8 6d 02 35 21 43 50 b8 7c 5d "
"35 34 12 50 89 e5 8a 46 00 45 08 c0 74 0a b4 0e b4 00 b3 07 cd 10 eb ee eb fe"
)
i=0; ax=None; words=[]
while i < len(data):
    b=data[i]
    if b==0xB8:
        ax = data[i+1] | (data[i+2]<<8)
        i+=3
    elif b==0x35:
        imm = data[i+1] | (data[i+2]<<8)
        ax = (ax ^ imm) & 0xffff
        i+=3
    elif b==0x50:
        words.append(ax & 0xffff)
        i+=1
    else:
        i+=1

# ghép theo thứ tự pop (đảo)
s = b''.join(((w & 0xff).to_bytes(1,'little') + ((w>>8)&0xff).to_bytes(1,'little')) for w in reversed(words))
print(s.decode('latin1'))
```
    Flag: HOLACTF{3A5Y_b0OT_104D3R_727_}
    
## Osint
### 1. EHC is my family
![image](https://hackmd.io/_uploads/Sy8IUr-qxe.png)
![danang_ehc](https://hackmd.io/_uploads/rknuIB-5gl.jpg)

Để ý bên trái mình thấy có logo của trường VKU, nên biết ngay đó là Trường Đại học Công nghệ Thông tin và Truyền thông Việt Hàn.

    Flag: HOLACTF{truong_dai_hoc_cong_nghe_thong_tin_va_truyen_thong_viet_han}