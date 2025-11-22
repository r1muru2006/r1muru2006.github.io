---
title: "picoCTF 2025"
description: "Blog đầu nên mình sẽ lấy giải lần đầu mình chơi cùng team aespaFanClub :3"
date: 2025-03-22T13:52:19+07:00
cover: /images/picoCTF.png
license:
math: true
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
categories:
    - CTF Write-up
---
> Theo cá nhân mình thấy các challenge về crypto của giải phân hóa rõ ràng các mức độ khác nhau
## General
### FANTASY CTF
Bài này mình nghĩ là chọn hướng nào cũng ra được vì đến cuối cùng sẽ đẩy ra flag :))
```javascript
FANTASY CTF SIMULATION

The simulation begins in the private room of Eibhilin, a bright, young student.
The room is dimly lit, with the glow of her multiple monitors casting an
electric blue hue on the walls. Around the room are posters of vintage movies
from the MCU — ancient guardians from another age staring down like digital
sentinels.

---
(Press Enter to continue...)
---


Eibhilin stretches back in her chair, adjusting the holo-display of her
keyboard. A soft hum of a nearby server fills the air as her AI companion,
`Nyx`, comes to life.

---
(Press Enter to continue...)
---
"Good evening, Ei," Nyx chirps, "The 3025 edition of picoCTF registration is
open. You asked me to remind so you could try out the competition for the first
time. Do you wish to proceed?"

---
(Press Enter to continue...)
---

Outside, the city of Nexalus glimmers under the stars, but Eibhilin's focus
remains entirely on the screen in front of her.

---
(Press Enter to continue...)
---

"Yes, Nyx. Let's do it!"

---
(Press Enter to continue...)
---


Nyx brings up the registration page.

Options:
A) *Register multiple accounts*
B) *Share an account with a friend*
C) *Register a single, private account*
[a/b/c] > A

Nyx chimes in, "Eibhilin, don't do that! That's been grounds for
disqualification for the past 1,000 years!"

---
(Press Enter to continue...)
---

"Oh, thanks Nyx, that was close!"

---
(Press Enter to continue...)
---

"Ok," Nyx says, "Registering you for the competition... There's an introductory
audio message, piping to your speakers."

---
(Press Enter to continue...)
---

"Welcome hacker! You're about to embark on a journey that will teach you many
esoteric and valuable skills. Our mission is to guide you in the right path,
that you may use these skills to protect and defend and never for selfish gain
or deceit. We hope you enjoy the challenges that our authors have devised this
year. Always remember: 'With great power, comes great responsibility!'"

---
(Press Enter to continue...)
---

Nyx continues, "I've gleaned from the Ether that in CTF competitions, it's
always good to start with the 'sanity' challenge. It should be the challenge
worth the least amount of points. I'll pull it up. You're looking for something
called the flag. You should know it when you see it."

---
(Press Enter to continue...)
---

"Oh interesting," Eibhilin says, "It seems like the sanity challenge is an old
school interactive fiction game."

---
(Press Enter to continue...)
---

Options:
A) *Play the game*
B) *Search the Ether for the flag*
[a/b] > A

"Good choice, Ei," Nyx says, "You never want to share flags or artifact
downloads."

---
(Press Enter to continue...)
---

 Playing the Game
Playing the Game:   0%|                                           [time left: ?]
Playing the Game: 100%|██████████████████████████████████████ [time left: 00:00]
Playing the Game completed successfully!

---
(Press Enter to continue...)
---
"That was fun!" Eibhilin exclaims, "I found the flag!"

---
(Press Enter to continue...)
---

Nyx says, "Great job, Ei! I've read that a lot of players create writeups of
interesting challenges they solve during the competition. Just be sure to wait
to publish them until after the winners have been announced. We can work on
that together if you'd like."

---
(Press Enter to continue...)
---

"Thanks, Nyx! Here's the flag I found: picoCTF{m1113n1um_3d1710n_76b680a5}"

---
(Press Enter to continue...)
---

"Great, you just got 10 points!" Nyx exclaims.

---
(Press Enter to continue...)
---

Eibhilin smiles, "I'm off to a good start!"

---
(Press Enter to continue...)
---

Nyx says, "Let's keep going!"

---
(Press Enter to continue...)
---

END OF FANTASY CTF SIMULATION
Thank you for playing! To reemphasize some rules for this year:
1. Register only one account.
2. Do not share accounts, flags or artifact downloads.
3. Wait to publish writeups publicly until after the organizers announce the
winners.
4. picoCTF{m1113n1um_3d1710n_76b680a5} is a real flag! Submit it for some
points in picoCTF 2025!

---
(Press Enter to continue...)
---
```
    FLag: picoCTF{m1113n1um_3d1710n_76b680a5}
## Crypto
### hashcrack
Ở bài này mình dựa vào số bytes của hash và các tools online để tìm ra password, như là: [MD5](https://10015.io/tools/md5-encrypt-decrypt), [SHA1](https://10015.io/tools/sha1-encrypt-decrypt), [SHA256](https://10015.io/tools/sha256-encrypt-decrypt)
```javascript
Welcome!! Looking For the Secret?

We have identified a hash: 482c811da5d5b4bc6d497ffa98491e38 //md5
Enter the password for identified hash: password123
Correct! You've cracked the MD5 hash with no secret found!

Flag is yet to be revealed!! Crack this hash: b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3 //sha1
Enter the password for the identified hash: letmein
Correct! You've cracked the SHA-1 hash with no secret found!

Almost there!! Crack this hash: 916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745 //sha256
Enter the password for the identified hash: qwerty098
Correct! You've cracked the SHA-256 hash with a secret found.
The flag is: picoCTF{UseStr0nG_h@shEs_&PaSswDs!_eff9dbe0}
```
    Flag: picoCTF{UseStr0nG_h@shEs_&PaSswDs!_eff9dbe0}
### EVEN RSA CAN BE BROKEN???
```python
# source.py
from sys import exit
from Crypto.Util.number import bytes_to_long, inverse
from setup import get_primes

e = 65537

def gen_key(k):
    """
    Generates RSA key with k bits
    """
    p,q = get_primes(k//2)
    N = p*q
    d = inverse(e, (p-1)*(q-1))

    return ((N,e), d)

def encrypt(pubkey, m):
    N,e = pubkey
    return pow(bytes_to_long(m.encode('utf-8')), e, N)

def main(flag):
    pubkey, _privkey = gen_key(1024)
    encrypted = encrypt(pubkey, flag) 
    return (pubkey[0], encrypted)

if __name__ == "__main__":
    flag = open('flag.txt', 'r').read()
    flag = flag.strip()
    N, cypher  = main(flag)
    print("N:", N)
    print("e:", e)
    print("cyphertext:", cypher)
    exit()
```
Mở kênh kết nối thì ta nhận được `N, e, cipher`
```python
N = 14971332928931600258070222525511394212054658902871612141186429243227295047197174853004285765481866838784351475089613251384629214373054886098787783629288854
e = 65537
cipher = 9685487452310081650666414304396053822632884035194331224959800780976444606689190315693089108703603608391361578584998640257817456167504699460118188426557775
```
Đoạn này mình thấy sai sai vì N chẵn làm mình nghĩ sao bài này nó dễ vậy được và đúng là nó dễ thật @@
```python
from Crypto.Util.number import long_to_bytes

# Lấy từ (nc verbal-sleep.picoctf.net 51510)
N = 14971332928931600258070222525511394212054658902871612141186429243227295047197174853004285765481866838784351475089613251384629214373054886098787783629288854
e = 65537
cipher = 9685487452310081650666414304396053822632884035194331224959800780976444606689190315693089108703603608391361578584998640257817456167504699460118188426557775

p = 2
q = N // p

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
flag = long_to_bytes(pow(cipher, d, N))

print(flag.decode("utf-8"))
```
    Flag: picoCTF{tw0_1$_pr!m3625a858b}
### Guess My Cheese (Part 1)
```javascript
*******************************************
***             Part 1                  ***
***    The Mystery of the CLONED RAT    ***
*******************************************

The super evil Dr. Lacktoes Inn Tolerant told me he kidnapped my best friend, Squeexy, and replaced him with an evil clone! You look JUST LIKE SQUEEXY, but I'm not sure if you're him or THE CLONE. I've devised a plan to find out if YOU'RE the REAL SQUEEXY! If you're Squeexy, I'll give you the key to the cloning room so you can maul the imposter...

Here's my secret cheese -- if you're Squeexy, you'll be able to guess it:  LRGGHOZMFOVPB
Hint: The cheeses are top secret and limited edition, so they might look different from cheeses you're used to!
Commands: (g)uess my cheese or (e)ncrypt a cheese
What would you like to do?
```
    Hint: Remember that cipher we devised together Squeexy? The one that incorporates your affinity for linear equations
Thử thách nhắc tới phương trình tuyến tính và `affinity` nên mình đã google xem thử nó nói về cái gì và đây là kết quả: [Affine transformation](https://en.wikipedia.org/wiki/Affine_transformation)

Bản đồ affine $f$ tác dụng lên $x$ được biểu diển dưới dạng: $y \equiv f(x)=ax+b$ (mod m).

Khi áp dụng vào mã hóa thì $y$ là bản mã (Ciphertext), còn $x$ là bản rõ (Plaintext). Nghĩa là:

- Khi mã hóa: $C\equiv aP+b$ (mod m)
- Khi giải mã: $P=a^{-1}(C-b)$ (mod m)

Ở đây, ta thấy nó được mã hóa theo từng chữ cái trên bảng Latinh nên $m$ sẽ là số lượng chữ cái và hơn nữa để giải mã được thì phải tồn tại nghịch đảo modulo $m$ của $a$.

Và để làm được điều đó thì $m, a$ phải đôi một nguyên tố cùng nhau. Xem thêm ở [đây](https://wiki.vnoi.info/algo/math/modular-inverse)
```python
possible_a = [a for a in range(1, M) if gcd(a, M) == 1]
```
Vì chỉ xét tới chữ cái in hoa nên ta sẽ lấy $M=26$.
Ở đây, thử thách cho mình 2 quyền đoán cheese đưa ra và mã hóa 1 cheese nào đó.
Để mà đoán được cheese thì ta cần hệ số $a, b$ và từ đó giải mã ra bản rõ. Do đó, mình sẽ mã hóa 1 cheese nào đó trước rồi đối chiếu và lấy $a, b$ và giải mã để lấy flag.
```javascript
What would you like to do?
e

What cheese would you like to encrypt? Cottage cheese
Here's your encrypted cheese:  JFMMBZRMJQRRVR
Not sure why you want it though...*squeak* - oh well!
```
```python
# solution.py
from string import ascii_uppercase
from Crypto.Util.number import inverse, GCD

# Bảng chữ cái
ALPHABET = ascii_uppercase
M = len(ALPHABET)  # M = 26
possible_a = [a for a in range(1, M) if GCD(a, M) == 1]

def affine_decrypt(ciphertext, a, b):
    a_inv = inverse(a, M)
    plaintext = ""
    for char in ciphertext:
        C = ALPHABET.index(char)
        P = (a_inv * (C - b)) % M
        plaintext += ALPHABET[P]
    return plaintext

# Mẫu ban đầu với Cottage Cheese
cipher_pattern = "JFMMBZRMJQRRVR"
cipher = "LRGGHOZMFOVPB"

found = False
for a in possible_a:
    for b in range(M):
        decrypted = affine_decrypt(cipher_pattern, a, b)
        if 'COTTAGE' in decrypted:
            found = True
            break
    if found:
        break

cheese = affine_decrypt(cipher, a, b)
print(cheese)
# WELLINGTONSKA
```
Nhập cheese vào guess và ta lấy được flag
```javascript
I don't wanna talk to you too much if you're some suspicious character and not my BFF Squeexy!
You have 2 more chances to prove yourself to me!

Commands: (g)uess my cheese or (e)ncrypt a cheese
What would you like to do?
g


   _   _
  (q\_/p)
   /. .\.-.....-.     ___,
  =\_t_/=     /  `\  (
    )\ ))__ __\   |___)
   (/-(/`  `nn---'

SQUEAK SQUEAK SQUEAK

         _   _
        (q\_/p)
         /. .\
  ,__   =\_t_/=
     )   /   \
    (   ((   ))
     \  /\) (/\
      `-\  Y  /
         nn^nn


Is that you, Squeexy? Are you ready to GUESS...MY...CHEEEEEEESE?
Remember, this is my encrypted cheese:  LRGGHOZMFOVPB
So...what's my cheese?
WELLINGTONSKA

         _   _
        (q\_/p)
         /. .\         __
  ,__   =\_t_/=      .'o O'-.
     )   /   \      / O o_.-`|
    (   ((   ))    /O_.-'  O |
     \  /\) (/\    | o   o  o|
      `-\  Y  /    |o   o O.-`
         nn^nn     | O _.-'
                   '--`

munch...

         _   _
        (q\_/p)
         /. .\         __
  ,__   =\_t_/=      .'o O'-.
     )   /   \      / O o_.-`|
    (   ((   ))      ).-'  O |
     \  /\) (/\      )   o  o|
      `-\  Y  /    |o   o O.-`
         nn^nn     | O _.-'
                   '--`

munch...

         _   _
        (q\_/p)
         /. .\         __
  ,__   =\_t_/=      .'o O'-.
     )   /   \      / O o_.-`|
    (   ((   ))        )'  O |
     \  /\) (/\          )  o|
      `-\  Y  /         ) O.-`
         nn^nn        ) _.-'
                   '--`

MUNCH.............

YUM! MMMMmmmmMMMMmmmMMM!!! Yes...yesssss! That's my cheese!
Here's the password to the cloning room:  picoCTF{ChEeSy033d0004}
```
    Flag: picoCTF{ChEeSy033d0004}
### ChaCha Slide
```python
# challenge.py
import secrets
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305

flag = open("flag.txt").read().strip()

def shasum(x):
    return hashlib.sha256(x).digest()

key = shasum(shasum(secrets.token_bytes(32) + flag.encode()))

# Generate a random nonce to be extra safe
nonce = secrets.token_bytes(12)

messages = [
    "Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?",
    "That means it protects both the confidentiality and integrity of data!"
]

goal = "But it's only secure if used correctly!"

def encrypt(message):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return ciphertext + tag + nonce

def decrypt(message_enc):
    ciphertext = message_enc[:-28]
    tag = message_enc[-28:-12]
    nonce = message_enc[-12:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

for message in messages:
    print("Plaintext: " + repr(message))
    message = message.encode()
    print("Plaintext (hex): " + message.hex())
    ciphertext = encrypt(message)
    print("Ciphertext (hex): " + ciphertext.hex())
    print()
    print()

user = bytes.fromhex(input("What is your message? "))
user_message = decrypt(user)
print("User message (decrypted): " + repr(user_message))

if goal in repr(user_message):
    print(flag)
```
Kết nối với kênh, ta được đoạn tin sau:
```javascript
Plaintext: 'Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?'
Plaintext (hex): 44696420796f75206b6e6f7720746861742043686143686132302d506f6c793133303520697320616e2061757468656e7469636174656420656e6372797074696f6e20616c676f726974686d3f
Ciphertext (hex): 7cb5f2e754caea3d3d98048ee7d747c1b677b5ac33a000d74c86b68f7f25a955db62e0a8fd17b0235cfc0541a7f8edf105a5d1ab6a6489cfacb7e4061f5b1c8f4f04e9624220e4cb450bae1e13da93a564ed04959dbde00eb0e72b772fb4a5a47457ad46b48a03432d


Plaintext: 'That means it protects both the confidentiality and integrity of data!'
Plaintext (hex): 54686174206d65616e732069742070726f746563747320626f74682074686520636f6e666964656e7469616c69747920616e6420696e74656772697479206f66206461746121
Ciphertext (hex): 6cb4f7b30dc8fa7c38854b90b3835fd2ad2393a7269048d411c2f3ff6421b5448b3dbbeefd00f52c46b50558bae4f1bf10a2d6ea776f998aaeabee001f0b0780000ea8774f66f3102a46013366d9ab4b0cf5b4320020b4a5a47457ad46b48a03432d


What is your message?
```
Sơ lược lại thì thử thách nói về hệ mã dòng có xác thực ChaCha20 - Poly1305.
Rõ hơn thì đề cho ta hai đoạn tin nhắn và bản mã của chúng, yêu cầu ta gửi tới bản mã của goal được cho để nhận về flag của chall.

Để gửi được đúng bản mã của goal, ta phải tìm được 3 phần gồm: `ciphertext, tag, nonce`. Đơn giản với `nonce` vì nó đã trùng với cái của 2 ciphertext mẫu có sẵn. Còn `ciphertext` thì liên quan tới phần mã hóa của Chacha20, `tag`  liên quan tới phần xác thực của Poly1305

Vì vậy, ta chia ChaCha20 - Poly1305 thành hai phần để phân tích và tấn công:
1. Về Chacha20:

Phương thức này sử dụng mã hóa XOR với `keystream` là XOR key.

Nghĩa là: Ciphertext = Plaintext $\oplus$ Keystream

$\Leftrightarrow$ Ciphertext $\oplus$ Plaintext = Plaintext $\oplus$ Keystream $\oplus$ Plaintext = Keystream

Và khi mà ta đã biết cái plaintext ở goal rồi thì việc giải mã sẽ đơn giản bằng **known-plaintext attack** như sau: goal_ct = goal $\oplus$ Keystream = goal $\oplus$ Ciphertext $\oplus$ Plaintext
```python
ciphertext = bytes(
    [
        c1 ^ p1 ^ p2
        for c1, p1, p2 in zip(ciphertext1, plaintext1, goal)
    ]
)  # vì độ dài goal nhỏ hơn ciphertext1 nên keystream sẽ chạy hết được goal
```
2. Poly1305:

Phần này mới thực sự là phức tạp của thử thách, với mục đích chính là tìm cái `tag` để server check xem có đúng không.
Sau khi google thì ta biết được rằng Poly1305 được dùng như mã xác thực một lần với:

$$
    tag \equiv Poly1305_r(m)+s \mod 2^{128}
$$

Đề cho ta 2 tag của 2 tin nhắn phân biệt mà ta đã biết và được dùng cùng 1 Poly1305 key bí mật (r,s). Bây giờ, chúng ta phải tìm lại key này để giải mã được cấu trúc tạo tag.

Và ở [đây](https://en.wikipedia.org/wiki/Poly1305#Use_as_a_one-time_authenticator) cũng có để cách attack nếu sử dụng 2 lần để mã hóa tin nhắn bằng 1 key.

$$
    tag_1 = (Poly1305_r(m_1) + s )\mod 2^{128} \ (1)
$$

$$
    tag_2 = (Poly1305_r(mg_2) + s )\mod 2^{128} \ (2)
$$

Từ (1) và (2), ta có:

$$
    tag_1 - tag_2 \equiv Poly1305_r(m_1)- Poly1305_r(m_2) \mod 2^{128}
$$

Mình xem ở [đây](https://en.wikipedia.org/wiki/Poly1305#Definition_of_Poly1305) để phân tích cái Poly1305 ra:
$$
    tag_1 - tag_2 \equiv (c_1^1r^q+c_1^2r^{q-1}+...+c_1^qr^1\mod 2^{130} -5)
$$

$$
  -(c_2^1r^q+c_2^2r^{q-1}+...+c_2^qr^1\mod 2^{130} -5) \mod 2^{128}
$$

$$
\Leftrightarrow tag_1 - tag_2 + 2^{128}(i-j) \equiv (((c_1^1-c_2^1)r^q+(c_1^2-c_2^2)r^{q-1}+...+(c_1^q-c_2^q)r^1) \mod 2^{130} -5)
$$

Vì `tag` ban đầu mod 1 giá trị bằng $2^{130} - 5$, gần bằng 130 bits rồi mod  $2^{128}$ nghĩa là `tag` mất 2 bits nên $i,j \in \overline{0,4} \Rightarrow (i-j)\in \overline{-4,4}$.

Đặt $k = i-j$ thì với mỗi k, ta sẽ dựng  1 phương trình trên GF($2^{130}-5$), tìm nghiệm của phương trình này và nó là `r` rồi thế lại vào 1 trong hai phương trình trên là ta ra được `s`

Khi đã có được `r, s` đối với cặp `(key, nonce)` này rồi thì ta hoàn toàn có thể tạo 1 cái `tag` xác thực được cho ciphertext của goal và đây cũng là cách mình thực hiện thử thách này.
```python
# solution.py
from pwn import *
from Crypto.Util.Padding import pad, unpad
import sage.all as sage

io = remote("activist-birds.picoctf.net", 59584)

plaintext1 = (
    b"Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?"
)
def data():
    io.recvuntil("Ciphertext (hex): ")
    message_enc = io.recvline().decode().split("\n")[0]
    # lấy từ ciphertext của plaintext từ server
    message_enc = bytes.fromhex(message_enc)
    ciphertext = message_enc[:-28]
    tag = message_enc[-28:-12]
    nonce = message_enc[-12:]
    return ciphertext, tag, nonce
ciphertext1, tag1, nonce = data()
ciphertext2, tag2, nonce = data()

goal = b"But it's only secure if used correctly!"
ciphertext = bytes(
    [
        c1 ^ p1 ^ p2
        for c1, p1, p2 in zip(ciphertext1, plaintext1, goal)
    ]
)  # vì độ dài goal nhỏ hơn ciphertext1 nên keystream sẽ chạy hết được goal

def make_poly(ct):
    data = b""
    mac_data = data + pad(data, 16)
    mac_data += ct + pad(ct, 16)
    mac_data += struct.pack("<Q", len(data))
    mac_data += struct.pack("<Q", len(ct))
    f = 0
    for i in range(0, round(len(mac_data) / 16)):
        n = mac_data[i * 16 : (i + 1) * 16] + b"\x01"
        n += (17 - len(n)) * b"\x00"
        f = (f + int.from_bytes(n, "little")) * x
    return f


tag1_int = int.from_bytes(tag1, "little")
tag2_int = int.from_bytes(tag2, "little")

Pr = sage.PolynomialRing(sage.GF(2**130 - 5), "x")
x = Pr.gen()

f1 = make_poly(ciphertext1)
f2 = make_poly(ciphertext2)
print(f1)
print(f2)
# 597196402248105951626966011877782631804*x^6 + 454145005287357688070972442197395601334*x^5 + 661861931549384550481074575939827950299*x^4 + 530509202787700791233082061683076211973*x^3 + 340282368435768507855198875253190755407*x^2 + 340282366920938464883773901107403685888*x
# 619916185459487913787536860817282020460*x^6 + 431610353687254081499753564988673041325*x^5 + 595420896811833730416722478289825512843*x^4 + 510460122022284652188488210929459569168*x^3 + 340282366920938463463374719923264163328*x^2 + 340282366920938464754646692591436824576*x

res = []

for k in range(-4, 5):
    rhs = tag1_int - tag2_int + 2**128 * k
    print(rhs, k)
    f = rhs - (f1 - f2)
    for r, _ in f.roots():
        if int(r).bit_length() <= 124:
            s = (tag1_int - int(f1(r))) % (2**128)
            res.append((r, s))
print(res)
# [(20320015409774457323517351832911875936, 340179677694136160511250274535902749702)]

for r, s in res:
    f = make_poly(ciphertext)
    tag = (int(f(r)) + s) % 2**128
    print(tag)
    # 314525754662942930020042292487713459951
    tag = int(tag).to_bytes(16, "little")

message = (ciphertext + tag + nonce).hex()
print(message)
# 7aa9e2e744d1b86e76990595be835cc5a12284a1728a0e960bc5febb302abf169a37b6fcf81db1ef0ee4d59f089de8f06ea49ef8749fecb4a5a47457ad46b48a03432d

io.recvuntil("What is your message? ")
io.sendline(message)
io.recvline()
flag = io.recvline().decode()
print(flag)
```
Trong lúc làm bài thì mình nhập trực tiếp tới server nên được như sau:
```javascript
Plaintext: 'Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?'
Plaintext (hex): 44696420796f75206b6e6f7720746861742043686143686132302d506f6c793133303520697320616e2061757468656e7469636174656420656e6372797074696f6e20616c676f726974686d3f
Ciphertext (hex): 7cb5f2e754caea3d3d98048ee7d747c1b677b5ac33a000d74c86b68f7f25a955db62e0a8fd17b0235cfc0541a7f8edf105a5d1ab6a6489cfacb7e4061f5b1c8f4f04e9624220e4cb450bae1e13da93a564ed04959dbde00eb0e72b772fb4a5a47457ad46b48a03432d


Plaintext: 'That means it protects both the confidentiality and integrity of data!'
Plaintext (hex): 54686174206d65616e732069742070726f746563747320626f74682074686520636f6e666964656e7469616c69747920616e6420696e74656772697479206f66206461746121
Ciphertext (hex): 6cb4f7b30dc8fa7c38854b90b3835fd2ad2393a7269048d411c2f3ff6421b5448b3dbbeefd00f52c46b50558bae4f1bf10a2d6ea776f998aaeabee001f0b0780000ea8774f66f3102a46013366d9ab4b0cf5b4320020b4a5a47457ad46b48a03432d


What is your message? 7aa9e2e744d1b86e76990595be835cc5a12284a1728a0e960bc5febb302abf169a37b6fcf81db1ef0ee4d59f089de8f06ea49ef8749fecb4a5a47457ad46b48a03432d
User message (decrypted): b"But it's only secure if used correctly!"
picoCTF{7urn_17_84ck_n0w_77243c82}
```
    Flag: picoCTF{7urn_17_84ck_n0w_77243c82}
### Guess My Cheese (Part 2)
> Mình để bài này sau cùng vì thực sự thì nó khá là tricky và xém nữa thì mình có thể làm ra nó sớm hơn trong quá trình giải bài nhưng không được.

Thử thách cho ta một cái `cheese_list.txt` chứa 599 loại cheese cùng với đó là server được kết nối như Part 1 chỉ khác 1 chỗ là không được mã hóa một loại cheese mà ta cho trước.

Ở đây thì hint có nhắc tới [Salt](https://en.wikipedia.org/wiki/Salt_(cryptography)) là 2 ký tự thập lục phân và gợi ý cho ta dùng [Rainbow table](https://en.wikipedia.org/wiki/Rainbow_table)

Đầu tiên, mình cũng brute-force băm SHA256 hết các cheese cộng với việc thêm salt vào cuối $\rightarrow$ không ra. Sau đó, mình nghĩ tới việc băm trước rồi thêm salt sau đó băm tiếp $\rightarrow$ cũng không ra. Rồi mình nghĩ tới việc thêm salt vào từng ký tự xen giữa của cheese rồi băm và tất nhiên $\rightarrow$ không ra. Tiếp theo, mình nghĩ là ồ Part 1 đã cho ta chữ cái in hoa rồi thì có thể phải in hoa hết các cheese xong mới thực hiện $\rightarrow$ không ra.

Lúc đó mình cũng không nghĩ tới việc là phải ngược lại là in thường hết các cheese và nó đúng thật là như vậy...
```python
# solution.py
from hashlib import sha256

with open(
    "cheese_list.txt",
    "r",
) as f:
    data = f.readlines()

cheeses = [line.strip().lower() for line in data]
chall = "9b71b2b23fa26641a0096848f97b78718975832f37ab770c60398949cd991a14"

rainbow_table = {}

for cheese in cheeses:
    for salt in range(256):
        x = cheese.encode() + salt.to_bytes(1, byteorder='big')
        new_cheese_hash = sha256(x).hexdigest()
        rainbow_table[new_cheese_hash] = x
        
if chall in rainbow_table:
    x = rainbow_table[chall]
    print(x)
    # b'pyramide\xa9'
```
Gửi cheese rồi sau đó là salt vào server thì ta nhận được flag...