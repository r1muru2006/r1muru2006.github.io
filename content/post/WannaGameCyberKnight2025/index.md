---
title: "WannaGame Cyber Knight 2025"
description: "Đây là giải đấu do câu lạc bộ Wanna.W1n tổ chức để tuyển thành viên vào câu lạc bộ."
date: 2025-05-16T14:13:38+07:00
cover: /images/w1cyber.png
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
categories:
    - CTF Write-up
    - WannaGame
---

>  Trong giải đấu này, mình đã giải được 1 câu trong phần Cryptography và may mắn đứng thứ 8 trên bảng đến cuối (≧▽≦)
> ![image](https://hackmd.io/_uploads/BkKat26egg.png)
Sau đây là bài mình giải được trong giải đấu và tiếp đó là những bài mà mình chưa làm được khi còn trong giải.

## Choose!
![image](https://hackmd.io/_uploads/HkBEq3pexl.png)

Link: https://www.youtube.com/watch?v=1lqe8eU48HI

```python
# aes.py
#Implementation from https://github.com/boppreh/aes/blob/master/aes.py

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


# learned from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i^j for i, j in zip(a, b))

def inc_bytes(a):
    """ Returns a new byte array with the value increment by 1 """
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def split_blocks(message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]


class AES:
    """
    Class for AES-128 encryption with CBC mode and PKCS#7.

    This is a raw implementation of AES, without key stretching or IV
    management. Unless you need that, please use `encrypt` and `decrypt`.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext, step=[add_round_key, sub_bytes, shift_rows, mix_columns]):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        step[0](plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            step[1](plain_state)
            step[2](plain_state)
            step[3](plain_state)
            step[0](plain_state, self._key_matrices[i])

        step[1](plain_state)
        step[2](plain_state)
        step[0](plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)
    
    def encrypt(self, plaintext, step):
        plaintext = pad(plaintext)
        ciphertext = b""
        for block in split_blocks(plaintext):
            ciphertext_block = self.encrypt_block(block, step)
            ciphertext += ciphertext_block
        return ciphertext
```

```python
# chall.py
from aes import *
import random
import os

def dumb_step(s, key = None):
    pass

key = os.urandom(16)
cipher = AES(key)
init_step = [add_round_key, sub_bytes, shift_rows, mix_columns]

for round in range(50):
    try:
        print(f"Round {round + 1}/50")
        plaintext = bytes.fromhex(input(">>> "))
        assert len(plaintext) <= 16 * 3, "Too long!"
        step = init_step[:]
        pos = random.randint(0, 3)
        step.pop(pos)
        step.insert(pos, dumb_step)
        bit = random.randint(0, 1)
        print(cipher.encrypt(plaintext, [init_step, step][bit]).hex())
        if int(input(">>> ")) != bit:
            print("Wrong!")
            exit(0)
        else:
            print("Correct!")
    except:
        exit(0)

print("Here is your flag !")
print(open("WannaGame_CyberKnight/choose/flag.txt", "r").read())
```
> Bài này đơn giản là về phần mã hóa AES ([Advanced Encryption Standard](https://vi.wikipedia.org/wiki/Advanced_Encryption_Standard)) và mình có xem lại cấu trúc của nó tại wikipedia và [đây](https://hackmd.io/@r1muru/HJmSbUld1x#Bringing-It-All-Together) để tiếp cận.

![image](https://hackmd.io/_uploads/rkcm02pxex.png)

### Phân tích:
- Hàm `dumb_step` pass 1 phép biển đổi trong 4 phép cần thiết để mã hóa AES.
- Server tạo 50 vòng, trong đó mỗi vòng thực thi nhiệm vụ sau:
    - Nhập 1 đoạn tin có $length\le48$.
    - Random bỏ 1 trong 4 bước để tạo `step` mới chỉ còn 3 bước.
    - Random sử dụng `init_step` gồm 4 bước hay `step` để mã hóa.
    - In ra `ciphertext` tương ứng.
    - Yêu cầu nhập vào:
        - 0 nếu dùng `init_step` (4 bước)
        - 1 nếu dùng `step` (3 bước)

Bypass được 50 vòng thì ta sẽ nhận được flag.
Đề bài là vậy nên khi bắt tay vào làm và code thì mình đã giải thuật được cho 3 bước rồi nhưng còn bị kẹt lại ở phần **Skip SubBytes**, may sao trong lúc tìm tài liệu thì đã tìm thấy bài [này](https://wrth.medium.com/cracking-aes-without-any-one-of-its-operations-c42cdfc0452f) và giải quyết được thử thách.
### Ý tưởng:
- Chủ đích của ta là phải từ `plaintext` nhập vào và `ciphertext` tương ứng phải biết được nó đã được sử dụng bao nhiêu bước để trả về giá trị đúng trong 50 vòng.
- Yêu cầu của `plaintext` là 48 bytes (tức 3 khối AES) nhưng nếu để ý kỹ thì nó được `padding` trước khi mã hóa nên nếu gửi đủ 48 bytes thì `plaintext` sẽ thêm khối thứ 4 là
`b'\x10' * 16` và đây cũng là dữ kiện quan trọng để giải bài này.
- Để cho mạch suy nghĩ trôi chảy và dễ code thì ta chia nó làm 5 trường hợp chính và giải quyết như ngay sau đây:
1. Skip AddRoundKey
![image](https://hackmd.io/_uploads/ByNj-Caele.png)
Đây là phần dễ nhất mà ta chỉ cần encrypt cái `plaintext` mà mình nhập vào với thuật aes chỉ có 3 bước còn lại vì nó không còn phụ thuộc vào key. Do đó, ta không có điều kiện gì với `plaintext` nhập vào. Sau đây là script phần này:
```python
def encrypt_block1(plaintext, step=[sub_bytes, shift_rows, mix_columns]):
    assert len(plaintext) == 16

    plain_state = bytes2matrix(plaintext)

    for i in range(1, n_rounds):
        step[0](plain_state)
        step[1](plain_state)
        step[2](plain_state)

    step[0](plain_state)
    step[1](plain_state)

    return matrix2bytes(plain_state)
    
def encrypt1(plaintext, step):
    plaintext = pad(plaintext)
    ciphertext = b""
    for block in split_blocks(plaintext):
        ciphertext_block = encrypt_block1(block, step)
        ciphertext += ciphertext_block
    return ciphertext

    
# Skip AddRoundKey make weakest
def decrypt1(plaintext, ciphertext):
    step=[sub_bytes, shift_rows, mix_columns]
    if encrypt1(plaintext, step) == ciphertext: return 1
    return 0
```
2. Skip SubBytes
![image](https://hackmd.io/_uploads/Hk9KbC6gxg.png)
Phần này đối với mình là thử thách nhất vì khi phân tích, mình thấy rằng bỏ **SubBytes** đi sẽ làm cho phần mã hóa với 3 bước còn lại trở thành các bước với chuyển đổi và ma trận khá phức tạp.
Như ta đã biết, nếu bỏ SubBytes đi thì các vòng của AES sẽ trở thành:

Vòng 0: AddRoundKey

Vòng 1–9: ShiftRows, MixColumns, AddRoundKey

Vòng 10: ShiftRows, AddRoundKey



Để cho gọn thì ta đặt $S, M, k_i$ lần lượt là phép biển đổi ma trận bằng ShiftRows và MixColumns và AddRoundKey ở vòng thứ i. Sau đây là quá trình mã hóa `plaintext`($P$):

Vòng 0: $P + k_0$

Vòng 1: $M(S(P+k_0))+k_1$. Đơn giản hóa bằng cách tính $A =MS$.

Vòng 2-9: $...(A(A(A(P+k_0))+k_1)+k_2)+k_3+...$

Vòng 10: $S(...(A(A(A(P+k_0))+k_1)+k_2)+k_3+...)+k_{10}$

$=SA^9P+SA^8k_0+..Sk_9+k_{10}=SA^9P+K$

Ở cuối ta thấy là `plaintext` gắn với $SA^9=M^9S^{10}$ mà không phụ thuộc gì tới key.
Do đó, để tấn công thì ta có thể nghĩ rằng với cùng 1 key thì $K$ tính được ở trên sẽ như nhau tức là `ciphertext` đặt là $C$ sẽ cho ra 1 hằng số $K=C-SA^9P$.

Và để giải quyết phần này thì ta sẽ phải có 2 khối trong phần `plaintext` ngay trước mã hóa để chứng minh và tính $K$ bằng cách tìm được cả $SA^9$.
Với phần tính $SA^9$ thì không hề đơn giản và mình vẫn đang đọc và tìm hiểu qua bài [này](https://crypto.stackexchange.com/questions/89596/linear-aes-expression-of-k-in-aesp-apk/89607#89607). Còn thuật toán thì mình sẽ sử dụng 1 phần của implement trong [bài báo](https://wrth.medium.com/cracking-aes-without-any-one-of-its-operations-c42cdfc0452f) cho trên.

Tiếp theo là phần 2 khối trong `plaintext` thì mình chọn khối 1 và khối 4 để sử dụng với khối 1 mình đưa vào là: `b'\x00' * 16` và khối 4 mặc định là: `b'\x10' * 16`.

Script:
```python
# Skip SubBytes
def bytes2mat(b):
    a = []
    for i in b:
        tmp = bin(i)[2:].zfill(8)
        for j in tmp:
            a.append(int(j))
    return Matrix(GF(2), a)

def mat2bytes(m):
    a = ""
    for i in range(128):
        a += str(m[0, i])
    a = [a[i:i+8] for i in range(0, 128, 8)]
    a = [int(i, 2) for i in a]
    return bytes(a)


def decrypt2(ciphertext):
    I = identity_matrix(GF(2), 8)
    X = Matrix(GF(2), 8, 8)
    for i in range(7):
        X[i, i+1] = 1
    X[3, 0] = 1
    X[4, 0] = 1
    X[6, 0] = 1
    X[7, 0] = 1

    C = block_matrix([
        [X, X+I, I, I],
        [I, X, X+I, I],
        [I, I, X, X+I],
        [X+I, I, I, X]
    ])

    zeros = Matrix(GF(2), 8, 8)
    zeros2 = Matrix(GF(2), 32, 32)
    o0 = block_matrix([
        [I, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros]
    ])

    o1 = block_matrix([
        [zeros, zeros, zeros, zeros],
        [zeros, I, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros]
    ])

    o2 = block_matrix([
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, I, zeros],
        [zeros, zeros, zeros, zeros]
    ])

    o3 = block_matrix([
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, I]
    ])

    S = block_matrix([
        [o0, o1, o2, o3],
        [o3, o0, o1, o2],
        [o2, o3, o0, o1],
        [o1, o2, o3, o0]
    ])

    M = block_matrix([
        [C, zeros2, zeros2, zeros2],
        [zeros2, C, zeros2, zeros2],
        [zeros2, zeros2, C, zeros2],
        [zeros2, zeros2, zeros2, C]
    ])

    R = M*S
    A = S*(R**9)

    pt1 = b'\x00' * 16
    ct1 = ciphertext[:16]
    pt2 = b'\x10' * 16
    ct2 = ciphertext[48:]
    pt2 = bytes2mat(pt2).transpose()
    ct2 = bytes2mat(ct2).transpose()

    K = ct2 - A*pt2
    recv = mat2bytes((A.inverse() * (bytes2mat(ct1).transpose() - K)).transpose())
    if recv == pt1: return 1
    return 0
```
3. Skip ShiftRows
![image](https://hackmd.io/_uploads/BywObRpglx.png)
Khi bỏ phần này thì rõ ràng các cột sẽ luôn giữ nguyên vị trí vì khi thực hiện MixColumns xáo cột chỉ làm thay đổi được vị trí của nó chứ không phải những thành phần bên trong đó. Vì vậy ta sẽ chia 1 khối trong `plaintext` ra thành 4 block và so sánh, nghĩa là hai cặp `plaintext - ciphertext` ứng với 1 cặp block tương ứng giống nhau ở mỗi phần.
Ở đây, mình sử dụng khối 2 và khối 4 với dữ liệu là: `b'\x10' * 4 + b'\x30' * 12` và `b'\x10' * 16` rồi so sánh block đầu của `ciphertext`.
Script:
```python
# Skip ShiftRows
def decrypt3(ciphertext):
    if ciphertext[16:20] == ciphertext[48:52]: return 1
    return 0
# block2: b'\x10' * 4 + b'\x30' * 12
# block4: b'\x10' * 16
```
4. Skip MixColumns
Ở bước này, nó không những chuyển vị các cột mà còn nhân với 1 hệ số cố định $c(x)$
![image](https://hackmd.io/_uploads/rkXPbAaele.png)
Do đó, khi ta bỏ bước MixColumns thì 1 khối 16 byte sẽ được mã hóa theo 16 khối khác nhau ứng với từng byte và không phụ thuộc đôi một vào nhau.
Điều này nghĩa là tồn tại 1 song ánh ứng với 1 byte của `plaintext` với 1 byte của `ciphertext` và mình bypass phần này bằng cách xét chỉ 1 byte khác nhau của 2 khối ở `plaintext` và đếm số lượng khác nhau của chúng ở `ciphertext`
Ở bài này, mình sử dụng khối 3 và khối 4 với dữ liệu là: `b'\x00' + b'\x10' * 15` và `b'\x10' * 16` rồi so sánh count của chúng.
Script:
```python
# Skip MixColumns
def decrypt4(ciphertext):
    ct1 = ciphertext[32:48]
    ct2 = ciphertext[48:]
    diff_count = sum(c1 != c2 for c1, c2 in zip(ct1, ct2))
    if diff_count == 1: return 1
    return 0
# block3: b'\x00' + b'\x10' * 15
# block4: b'\x10' * 16
```

Sau đây là script tổng hợp cả 4 phần và cũng là solution mà mình viết ra được cho chall:
```python
# solution.py
from sage.all import *
from pwn import *
from aes import *

def encrypt_block1(plaintext, step=[sub_bytes, shift_rows, mix_columns]):
    assert len(plaintext) == 16

    plain_state = bytes2matrix(plaintext)

    for i in range(1, 10):
        step[0](plain_state)
        step[1](plain_state)
        step[2](plain_state)

    step[0](plain_state)
    step[1](plain_state)

    return matrix2bytes(plain_state)
    
def encrypt1(plaintext, step):
    plaintext = pad(plaintext)
    ciphertext = b""
    for block in split_blocks(plaintext):
        ciphertext_block = encrypt_block1(block, step)
        ciphertext += ciphertext_block
    return ciphertext

    
# Skip AddRoundKey make weakest
def decrypt1(plaintext, ciphertext):
    step=[sub_bytes, shift_rows, mix_columns]
    if encrypt1(plaintext, step) == ciphertext: return 1
    return 0


# Skip SubBytes
def bytes2mat(b):
    a = []
    for i in b:
        tmp = bin(i)[2:].zfill(8)
        for j in tmp:
            a.append(int(j))
    return Matrix(GF(2), a)

def mat2bytes(m):
    a = ""
    for i in range(128):
        a += str(m[0, i])
    a = [a[i:i+8] for i in range(0, 128, 8)]
    a = [int(i, 2) for i in a]
    return bytes(a)


def decrypt2(ciphertext):
    I = identity_matrix(GF(2), 8)
    X = Matrix(GF(2), 8, 8)
    for i in range(7):
        X[i, i+1] = 1
    X[3, 0] = 1
    X[4, 0] = 1
    X[6, 0] = 1
    X[7, 0] = 1

    C = block_matrix([
        [X, X+I, I, I],
        [I, X, X+I, I],
        [I, I, X, X+I],
        [X+I, I, I, X]
    ])

    zeros = Matrix(GF(2), 8, 8)
    zeros2 = Matrix(GF(2), 32, 32)
    o0 = block_matrix([
        [I, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros]
    ])

    o1 = block_matrix([
        [zeros, zeros, zeros, zeros],
        [zeros, I, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros]
    ])

    o2 = block_matrix([
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, I, zeros],
        [zeros, zeros, zeros, zeros]
    ])

    o3 = block_matrix([
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, zeros],
        [zeros, zeros, zeros, I]
    ])

    S = block_matrix([
        [o0, o1, o2, o3],
        [o3, o0, o1, o2],
        [o2, o3, o0, o1],
        [o1, o2, o3, o0]
    ])

    M = block_matrix([
        [C, zeros2, zeros2, zeros2],
        [zeros2, C, zeros2, zeros2],
        [zeros2, zeros2, C, zeros2],
        [zeros2, zeros2, zeros2, C]
    ])

    R = M*S
    A = S*(R**9)

    pt1 = b'\x00' * 16
    ct1 = ciphertext[:16]
    pt2 = b'\x10' * 16
    ct2 = ciphertext[48:]
    pt2 = bytes2mat(pt2).transpose()
    ct2 = bytes2mat(ct2).transpose()

    K = ct2 - A*pt2
    recv = mat2bytes((A.inverse() * (bytes2mat(ct1).transpose() - K)).transpose())
    if recv == pt1: return 1
    return 0


# Skip ShiftRows
def decrypt3(ciphertext):
    if ciphertext[16:20] == ciphertext[48:52]: return 1
    return 0
# block2: b'\x10' * 4 + b'\x30' * 12
# block4: b'\x10' * 16

# Skip MixColumns
def decrypt4(ciphertext):
    ct1 = ciphertext[32:48]
    ct2 = ciphertext[48:]
    diff_count = sum(c1 != c2 for c1, c2 in zip(ct1, ct2))
    if diff_count == 1: return 1
    return 0
# block3: b'\x00' + b'\x10' * 15
# block4: b'\x10' * 16

def decrypt(data, ciphertext):
    type1 = decrypt1(data, ciphertext)
    type2 = decrypt2(ciphertext)
    type3 = decrypt3(ciphertext)
    type4 = decrypt4(ciphertext)
    if type1 | type2 | type3 | type4 : return type1, type2, type3, type4, 1
    return 0, 0, 0, 0, 0

io = process(["python3", "WannaGame_CyberKnight/choose/chall.py"])

data = b'\x00' * 16 + (b'\x10' * 4 + b'\x30' * 12) + (b'\x00' + b'\x10' * 15)
for i in range(50):
    io.recvline()
    io.sendlineafter(b">>> ", data.hex().encode())
    ciphertext = io.recvline().strip().decode()
    ct = bytes.fromhex(ciphertext)
    type1, type2, type3, type4, bol = decrypt(data, ct)
    if bol == 1: print(type1, type2, type3, type4)
    io.sendlineafter(b">>> ", str(bol).encode())
    io.recvline()
io.interactive()
```
    Flag: W1{aAESEEESaEsaAEaSesEEEsAaseseesaSSEaaASeAAESEESSSaASeAsSSAAAAeAsE_baCsDCbtqU}
    
## heartbreak
![image](https://hackmd.io/_uploads/HkKwhbQbll.png)
```python
# chall.py
from Crypto.Util.number import getPrime, bytes_to_long
FLAG = "W1{???}"

FLAG_PART1, FLAG_PART2 = FLAG[:len(FLAG)//2], FLAG[len(FLAG)//2:]

f =  open("output.txt", "w")

def part1():
    p = getPrime(2048)
    q = getPrime(2048)
    e = 0x10001
    n = p * q
    d = pow(e, -1, (p-1)*(q-1))

    m = bytes_to_long(FLAG_PART1.encode())

    c = pow(m, e, n)

    f.write("ct = " + str(c))

    hints = [p, q, e, n, d]
    for _ in range(len(hints)):
        hints[_] = (hints[_] * getPrime(1024)) % n
        if hints[_] == 0: hints[_] = (hints[_] - 1) % n

    f.write("\nHints = " + str(hints) + "\n")


def part2():
    e = getPrime(10)
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    # print(e)
    m1 = bytes_to_long(FLAG_PART2.encode())
    m2 = m1 >> 8


    c1, c2 = pow(m1, e, n), pow(m2, e, n)
    f.write(f"n = {n}\nc1 = {c1}\nc2 = {c2}\n")

if __name__ == "__main__":
    part1()
    part2()
```
Flag của thử thách được chia làm 2 và mã hóa bằng 2 phần khác nhau.
### Part 1:
```python
def part1():
    p = getPrime(2048)
    q = getPrime(2048)
    e = 0x10001
    n = p * q
    d = pow(e, -1, (p-1)*(q-1))

    m = bytes_to_long(FLAG_PART1.encode())

    c = pow(m, e, n)

    f.write("ct = " + str(c))

    hints = [p, q, e, n, d]
    for _ in range(len(hints)):
        hints[_] = (hints[_] * getPrime(1024)) % n
        if hints[_] == 0: hints[_] = (hints[_] - 1) % n

    f.write("\nHints = " + str(hints) + "\n")
```
Bộ khóa RSA được gửi ra sau khi được nhân với 1 số nguyên tố 1024 bit ngẫu nhiên.

Chú ý điều kiện: `if hints[_] == 0: hints[_] = (hints[_] - 1) % n`

=> Từ đây, ta có thể tính được ngay $n = hint(n) + 1$

Thêm nữa, ta có hệ phương trình:
$$
\begin{cases}
    p = getPrime(2048) \\
    q = getPrime(2048) \\
    n = p * q          \\
    hint(p) = p * getPrime(1024)
\end{cases}
$$
Tức là $n$ có 4096 bit, còn `hint(p)` chỉ có 3072 bit và vì nó bé hơn $n$ nên khi lấy đồng dư thì nó sẽ không thay đổi.
Khi đó, ta hoàn toàn có thể lấy được $p$ bằng cách lấy GCD của `(n, hint(p))`

Cuối cùng, ta khôi phục dữ liệu cần thiết của bộ khóa và giải mã được part 1.
```python
def Part1():
   e = 0x10001
   ct = 239991743627005761506047553716973180857493049128968395824678613535924041735819278721655197652704368009118731671080782572692443257002266295841054097811995343407149181564647568019524547331554506022380795516159222363510661688595308307174873885160951837722610012918052195448795081291878933355634383798002056753336540546915811592763747343189324926404600658482137848658910189331650916354541907427173491308413908173314104508974384232290785538938623142120477030045742266779693627293755590884412082209151425384896460777577066084111556036719259982254175935197376972307183776259868229411302259648873045160120795060467866459055693698198316577983136619062944244317116994863470942099523485902299419458583301056211340627830237050622364646501838811516544340499168319955128200158195905283972429746772105746244910156671549456233908152186037286726530314472293814226978595268877619521165090870514287104577960355240428728213124348138646047728851553209042359051265045752603864312856768918350064549850618348693037041311112677351368226231458377933846664981185928405481697006968220556167073996713389716367133156065980195285148700027809062253416860922839857907535460170132744912543758918516134641462581544039400881675553681819294266618981791250077585566821053
   Hints = [1659380349228980310793195740551091998951133377142727433181233112954301485314646349955561783455759149036476737520702967988760310760312391176774501840210477308343796277178701715703164651184747756453236376960884981254635386807663657355175214655034193946682205904113897156938926175413312324159809831274187894029251371896829385517428693915588566248998565348483747234270329027561433356156355227738138379418717200316600111392671357267757409316691191187929104999221832963378673907868493499459459256894553552195468110517716115678897171373484791903085022119845347228569870830569321957438966030560930098761455953418479618027428739560761186901956751224602703471828674970337530768801203531827467185690264637238603523292728974955840936711823826949100349569805942227432262275344597592991937770320032450419910426614638156263968483514069904464463402987714698220412063100772910040673056263954301063853666792319306234733964442731206579494701823, 2473062479389297534384652365580702456631745761133091301459488546735676124432184165907268360691972078275036508838070797476235444908532100862886958054816201240359777405719375503276188588243722655521225159899315126844306119104997283731460041142142861614319514182297180409656236066011186834375282437648078334082114411988739789392926471318552017202390239258487258487037639778148532362214152519137264282830808294108610004403460587358629486534247288993860831438267841520573973916758902637404855712721811250301202405252158590233975917681798839166192235032424495289048875626437256513981936177292903742966118351026329401662519672777610159422234703124064225710846129876359778079390437505753932101501472252131924073957349012610362952003934494293369977045255000415066563914471132856401071867358687200638320541179048296074882945411664474157308113874183763200469775985802906031999934356545932354932945475129644344782759659758587119586377699, 10811389778781749507848369001995006527965136627134898173336798777178617924322548317218123003648199959431162146218350234488676047952720517043381973357960494027353001493321216082118308994614655309535481054291078777020047697030175144901965025751169815034274454689657181813765988172412194436669592236745329922983348687, 302270795345262652787049603034608860428203534578338699389744017410286806560707153186173595970011317749221953776227374491075684575774328458397778789729965544452010822737225229627108698874874960910965283322537095645241316756015118860396297708799504427117968454341778975073542738740964812664233075630257595196115893498655587491091126391722042679460013562303363850840912825755508680428829444388842951146482726568654418889598972824414109879370032604627990857015975495697530048397401132619555923308480516678981072029040306410523264480829688927798146165580384683689546853438820269495274502502143436234210825345362323042888891473423488116618918996618482754420372481893339222050268599796400452566639228520072261554594477336671016198833620427171498256007475831231524217372147783123617237105584613811522861590112133798309937116024168109605161059186745904038968516182034441583819409524470833832445513001764653452246905494902592731421744692331296978104865554556383417129664683066891729999411036376957753554228948901872115141778394712481069999501808719302346670855531871069366050528261442730651167165455031776639195754458920584910014448480393554851269958179362536781346169282601003523441289868134223507188615919092337658908484201829621953970243126, 292884935929549246643624576832991010496540593142708150947518571090956754050658797955786741707549303442499542376031718493862827439931968289137063776270385766876597819025272388601563339731026897291119786098658019861515084557432779618732711248671531045529170282246847559014298960824095511448557742476351035447816620523706582563446012744989424367197536652910056457067991830630881476241325631891896455745762634189112349619740103725259844111996043190764424736601828139403024375351372351763169837210283497390177391509068689722596094161210899552103572279045474893618035695053640281885367691987326728488743356438444158731410968935525788220429173044772188634219137052045984284351149340419125628533953328666109489959225736888258255952666488686965689900369280599239198825803111830614815595803322570878359992207842211026468967074229662081167123002174445268278747577520774432781623852071789431202030569577689851124794177654088403580945598530502231516822280930459410373890257129917535480957183190120541342731664708767982764672591340622307503858396934095635519503588136203556304925670734741505400274178108097309035870578129722954864083937813328351751442713938490297629659866083082398939022316220801556516785394083566880368038684968532814902807429836]
   xp, xn = Hints[0], Hints[3]
   n = xn + 1
   p = GCD(n, xp)
   q = n // p
   PhiN = (p - 1) * (q - 1)
   d = inverse_mod(e, PhiN)
   pt = pow(ct, d, n)
   return long_to_bytes(pt)
```
### Part 2:
```python
def part2():
    e = getPrime(10)
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    # print(e)
    m1 = bytes_to_long(FLAG_PART2.encode())
    m2 = m1 >> 8

    c1, c2 = pow(m1, e, n), pow(m2, e, n)
    f.write(f"n = {n}\nc1 = {c1}\nc2 = {c2}\n")
```
Với $e$ nhỏ, thì ta nghĩ ngay tới `Low public exponent attack` và khi tìm hiểu thì ta thấy bài này tương đồng với kiểu [Franklin–Reiter related-message attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin%E2%80%93Reiter_related-message_attack)

Cụ thể hơn, $m_2 = m _1 >> 8 \Leftrightarrow m_1 = m_2 * (1 >> 8) + k$.
Mặt khác, ta biết rằng $m_1$ là Part2 của flag tức là phần tử cuối trong 8 bit của nó khi quy về bảng mã ASCII sẽ là `}` tương đương với giá trị `125`

=> $m_1=256*m_2+125$

Sau đó, ta viết lại dưới dạng đa thức $f(x)$ và $g(x)$ là:
$$
\begin{cases}
    f(x) = x^e-c_1, f(m_1) =0 \\
    g(x) = x^e-c_2, f(m_2) =0
\end{cases}
\Leftrightarrow
\begin{cases}
    f(x) = (256*x+125)^e-c_1, f(m_2) =0 \\
    g(x) = x^e-c_2, g(m_2) =0
\end{cases}
$$

Hai đa thức này có nghiệm chung là $m_2$ nên khi lấy GCD của chúng và nếu nó tuyến tính thì ta sẽ lấy được $m_2$, tính $m_1$ và lấy được Part2 của flag.
```python
def Part2():
   n = 3942322022657678598973964668297464188690492529227912763243818849286024502988170927049337618748813366973108404930787214396933140242919629931061653981563183
   c1 = 711628464933911477721875076362382562533209928505813633932265201230108117662370018036520970813120568151605229871541865330790006742825947411425842775387464
   c2 = 199593868713063917388131306750677766968978918100656918000052209242691143624414286755644005020481267183225454134184719235765273635594459821952870709463733

   def my_gcd(a, b): 
      return a.monic() if b == 0 else my_gcd(b, a % b)

   x = PolynomialRing(Zmod(n), 'x').gen()

   for e in trange(2**9, 2**10):
      if not is_prime(e) or e.bit_length() != 10:
         continue
      
      fx = (256 * x + 125) ** e - c1
      gx = x ** e - c2
      sol = my_gcd(fx, gx)
      
      if sol.degree() == 1:
         m2 = int(-sol.coefficients()[0])
         m1 = 256 * m2 + 125
         return long_to_bytes(m1)
```
Script:
```python
# solution.py
from sage.all import *
from Crypto.Util.number import long_to_bytes
from tqdm import trange


# Part 1
def Part1():
   e = 0x10001
   ct = 239991743627005761506047553716973180857493049128968395824678613535924041735819278721655197652704368009118731671080782572692443257002266295841054097811995343407149181564647568019524547331554506022380795516159222363510661688595308307174873885160951837722610012918052195448795081291878933355634383798002056753336540546915811592763747343189324926404600658482137848658910189331650916354541907427173491308413908173314104508974384232290785538938623142120477030045742266779693627293755590884412082209151425384896460777577066084111556036719259982254175935197376972307183776259868229411302259648873045160120795060467866459055693698198316577983136619062944244317116994863470942099523485902299419458583301056211340627830237050622364646501838811516544340499168319955128200158195905283972429746772105746244910156671549456233908152186037286726530314472293814226978595268877619521165090870514287104577960355240428728213124348138646047728851553209042359051265045752603864312856768918350064549850618348693037041311112677351368226231458377933846664981185928405481697006968220556167073996713389716367133156065980195285148700027809062253416860922839857907535460170132744912543758918516134641462581544039400881675553681819294266618981791250077585566821053
   Hints = [1659380349228980310793195740551091998951133377142727433181233112954301485314646349955561783455759149036476737520702967988760310760312391176774501840210477308343796277178701715703164651184747756453236376960884981254635386807663657355175214655034193946682205904113897156938926175413312324159809831274187894029251371896829385517428693915588566248998565348483747234270329027561433356156355227738138379418717200316600111392671357267757409316691191187929104999221832963378673907868493499459459256894553552195468110517716115678897171373484791903085022119845347228569870830569321957438966030560930098761455953418479618027428739560761186901956751224602703471828674970337530768801203531827467185690264637238603523292728974955840936711823826949100349569805942227432262275344597592991937770320032450419910426614638156263968483514069904464463402987714698220412063100772910040673056263954301063853666792319306234733964442731206579494701823, 2473062479389297534384652365580702456631745761133091301459488546735676124432184165907268360691972078275036508838070797476235444908532100862886958054816201240359777405719375503276188588243722655521225159899315126844306119104997283731460041142142861614319514182297180409656236066011186834375282437648078334082114411988739789392926471318552017202390239258487258487037639778148532362214152519137264282830808294108610004403460587358629486534247288993860831438267841520573973916758902637404855712721811250301202405252158590233975917681798839166192235032424495289048875626437256513981936177292903742966118351026329401662519672777610159422234703124064225710846129876359778079390437505753932101501472252131924073957349012610362952003934494293369977045255000415066563914471132856401071867358687200638320541179048296074882945411664474157308113874183763200469775985802906031999934356545932354932945475129644344782759659758587119586377699, 10811389778781749507848369001995006527965136627134898173336798777178617924322548317218123003648199959431162146218350234488676047952720517043381973357960494027353001493321216082118308994614655309535481054291078777020047697030175144901965025751169815034274454689657181813765988172412194436669592236745329922983348687, 302270795345262652787049603034608860428203534578338699389744017410286806560707153186173595970011317749221953776227374491075684575774328458397778789729965544452010822737225229627108698874874960910965283322537095645241316756015118860396297708799504427117968454341778975073542738740964812664233075630257595196115893498655587491091126391722042679460013562303363850840912825755508680428829444388842951146482726568654418889598972824414109879370032604627990857015975495697530048397401132619555923308480516678981072029040306410523264480829688927798146165580384683689546853438820269495274502502143436234210825345362323042888891473423488116618918996618482754420372481893339222050268599796400452566639228520072261554594477336671016198833620427171498256007475831231524217372147783123617237105584613811522861590112133798309937116024168109605161059186745904038968516182034441583819409524470833832445513001764653452246905494902592731421744692331296978104865554556383417129664683066891729999411036376957753554228948901872115141778394712481069999501808719302346670855531871069366050528261442730651167165455031776639195754458920584910014448480393554851269958179362536781346169282601003523441289868134223507188615919092337658908484201829621953970243126, 292884935929549246643624576832991010496540593142708150947518571090956754050658797955786741707549303442499542376031718493862827439931968289137063776270385766876597819025272388601563339731026897291119786098658019861515084557432779618732711248671531045529170282246847559014298960824095511448557742476351035447816620523706582563446012744989424367197536652910056457067991830630881476241325631891896455745762634189112349619740103725259844111996043190764424736601828139403024375351372351763169837210283497390177391509068689722596094161210899552103572279045474893618035695053640281885367691987326728488743356438444158731410968935525788220429173044772188634219137052045984284351149340419125628533953328666109489959225736888258255952666488686965689900369280599239198825803111830614815595803322570878359992207842211026468967074229662081167123002174445268278747577520774432781623852071789431202030569577689851124794177654088403580945598530502231516822280930459410373890257129917535480957183190120541342731664708767982764672591340622307503858396934095635519503588136203556304925670734741505400274178108097309035870578129722954864083937813328351751442713938490297629659866083082398939022316220801556516785394083566880368038684968532814902807429836]
   xp, xn = Hints[0], Hints[3]
   n = xn + 1
   p = GCD(n, xp)
   q = n // p
   PhiN = (p - 1) * (q - 1)
   d = inverse_mod(e, PhiN)
   pt = pow(ct, d, n)
   return long_to_bytes(pt)

#Part 2
def Part2():
   n = 3942322022657678598973964668297464188690492529227912763243818849286024502988170927049337618748813366973108404930787214396933140242919629931061653981563183
   c1 = 711628464933911477721875076362382562533209928505813633932265201230108117662370018036520970813120568151605229871541865330790006742825947411425842775387464
   c2 = 199593868713063917388131306750677766968978918100656918000052209242691143624414286755644005020481267183225454134184719235765273635594459821952870709463733

   def my_gcd(a, b): 
      return a.monic() if b == 0 else my_gcd(b, a % b)

   x = PolynomialRing(Zmod(n), 'x').gen()

   for e in trange(2**9, 2**10):
      if not is_prime(e) or e.bit_length() != 10:
         continue
      
      fx = (256 * x + 125) ** e - c1
      gx = x ** e - c2
      sol = my_gcd(fx, gx)
      
      if sol.degree() == 1:
         m2 = int(-sol.coefficients()[0])
         m1 = 256 * m2 + 125
         return long_to_bytes(m1)

if __name__ == "__main__":
   PART1 = Part1()
   PART2 = Part2()
flag = PART1 + PART2
print(flag.decode())
```
    Flag: W1{https://www.youtube.com/results?search_query=p0lyn0m1als+9c4+is+good+isn%27t+it+?flag=tru4}
    