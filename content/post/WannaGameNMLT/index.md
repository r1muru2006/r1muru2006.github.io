---
title: "WannaGame NMLT"
description: "Đây là Write-up giành cho cuộc thi CTFs để lấy điểm Nhập môn lập trình của mình vào năm nhất."
date: 2025-04-08T10:07:31+07:00
cover: /images/WannaW1n.png
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
    - Reverse Engineering
categories:
    - CTF Write-up
    - WannaGame
---
## Pwn
### 1. Hello pwner

 ![image](https://hackmd.io/_uploads/SyPcemLL1g.png)
 
    Flag: W1{welcome_to_assembly}
## Crypto
### 2. Substitution

Tải file, giải nén và mở chall lên:
```python
KEY = {
    'A': 'Q', 'B': 'W', 'C': 'E', 'D': 'R', 'E': 'T', 'F': 'Y', 'G': 'U', 'H': 'I', 'I': 'O',
    'J': 'P', 'K': 'A', 'L': 'S', 'M': 'D', 'N': 'F', 'O': 'G', 'P': 'H', 'Q': 'J', 'R': 'K',
    'S': 'L', 'T': 'Z', 'U': 'X', 'V': 'C', 'W': 'V', 'X': 'B', 'Y': 'N', 'Z': 'M',
    'a': 'q', 'b': 'w', 'c': 'e', 'd': 'r', 'e': 't', 'f': 'y', 'g': 'u', 'h': 'i', 'i': 'o',
    'j': 'p', 'k': 'a', 'l': 's', 'm': 'd', 'n': 'f', 'o': 'g', 'p': 'h', 'q': 'j', 'r': 'k',
    's': 'l', 't': 'z', 'u': 'x', 'v': 'c', 'w': 'v', 'x': 'b', 'y': 'n', 'z': 'm',
}

def hehe(data, key):
    return ''.join(key.get(char, char) for char in data)

def encrypt(plaintext):
    substituted = hehe(plaintext, KEY)
    return substituted

if __name__ == "__main__":
    plaintext = "W1{???????????????}"
    encrypted = encrypt(plaintext)
    with open("encrypted.txt", "w") as f:
        f.write(encrypted)
```

#### Phân tích:
```python
def hehe(data, key):
    return ''.join(key.get(char, char) for char in data)
```

Hàm `hehe` lấy `data` và chuyển đổi từng ký tự trong dữ liệu đó sang ký tự tương ứng bằng danh sách của `KEY`.
```python
def encrypt(plaintext):
    substituted = hehe(plaintext, KEY)
    return substituted
```

Hàm `encrypt` có mục đich là sử dụng hàm hehe để mã hóa dữ liệu.
 
#### Giải:
Để lấy được `plaintext` thì ta cần giải mã `encrypted`, nghĩa là phải đảo ngược lại quá trình chuyển đổi ký tự trong danh sách của `KEY`
```python
KEY_rev = {i : v for v, i in KEY.items()}
```

  Rồi sử dụng hàm `hehe` chuyển đổi tiếp 1 lần nữa để được `data` ban đầu.
```python
def hehe(data, key):
    return ''.join(key.get(char, char) for char in data)
```

  Script:
  ```python
KEY = {
    'A': 'Q', 'B': 'W', 'C': 'E', 'D': 'R', 'E': 'T', 'F': 'Y', 'G': 'U', 'H': 'I', 'I': 'O',
    'J': 'P', 'K': 'A', 'L': 'S', 'M': 'D', 'N': 'F', 'O': 'G', 'P': 'H', 'Q': 'J', 'R': 'K',
    'S': 'L', 'T': 'Z', 'U': 'X', 'V': 'C', 'W': 'V', 'X': 'B', 'Y': 'N', 'Z': 'M',
    'a': 'q', 'b': 'w', 'c': 'e', 'd': 'r', 'e': 't', 'f': 'y', 'g': 'u', 'h': 'i', 'i': 'o',
    'j': 'p', 'k': 'a', 'l': 's', 'm': 'd', 'n': 'f', 'o': 'g', 'p': 'h', 'q': 'j', 'r': 'k',
    's': 'l', 't': 'z', 'u': 'x', 'v': 'c', 'w': 'v', 'x': 'b', 'y': 'n', 'z': 'm',
}
KEY_rev = {i : v for v, i in KEY.items()}
def hehe(data, key):
    return "".join(key.get(char, char) for char in data)

def decrypt(plaintext):
    substituted = hehe(plaintext, KEY_rev)
    return substituted

if __name__ == "__main__":
    encrypted = "V1{lxwlzozxzogf}"
    decrypted = decrypt(encrypted)
    print(decrypted)
```

    Flag: W1{substitution}
 
### 3. Hix
Tải file, giải nén và mở chall lên:
```python
import hashlib
import random

methods = ['md5', 'sha256', 'sha3_256', 'sha3_512', 'sha3_384', 'sha1', 'sha384', 'sha3_224', 'sha512', 'sha224']

def random_encrypt(x) :
    method = random.choice(methods)
    hash_obj = hashlib.new(method)
    hash_obj.update(x.encode())
    return hash_obj.hexdigest()

def main() :
    message = open("./../private/flag.txt", "r").read()
    enc = []

    for char in message :
        x = (ord(char) + 20) % 130
        x = hashlib.sha512(str(x).encode()).hexdigest()
        x = random_encrypt(x)
        enc.append(x)

    with open('encrypted_memory.txt', 'w') as f :
        f.write("ct = " + str(enc))

if __name__ == "__main__" :
    main()
```
#### Phân tích:
```python
methods = ['md5', 'sha256', 'sha3_256', 'sha3_512', 'sha3_384', 'sha1', 'sha384', 'sha3_224', 'sha512', 'sha224']
```

Đây là các thuật toán được sử dụng cho hàm băm.
```python
def random_encrypt(x) :
    method = random.choice(methods)
    hash_obj = hashlib.new(method)
    hash_obj.update(x.encode())
    return hash_obj.hexdigest()
```

Hàm `random_encrypt` dùng để mã hóa một chuỗi x bằng cách sử dụng một thuật toán băm bất kì có sẵn trong `methods`.
```python
for char in message :
        x = (ord(char) + 20) % 130
        x = hashlib.sha512(str(x).encode()).hexdigest()
        x = random_encrypt(x)
        enc.append(x)
```

Lấy từng kí tự trong `message`, sau đó lấy giá trị của ký tự đó trong ASCII rồi cộng 20 và lấy modulo 130. Tiếp theo, chuyển nó về một chuỗi rồi băm bằng SHA-512. Đến cuối thì sử dụng hàm `random_encrypt`.
 
#### Giải:
Ý tưởng: Vì x nằm trong đoạn từ 0 đến 129 (là một số nhỏ) nên ta có thể brute-force từng giá trị x khi thử với mỗi phương pháp băm để tìm ra các x tương ứng với từng giá trị của `ct` một cách dễ dàng.
```python
def reverse_encrypt(enc_hash):
    for method in methods:
        try:
            for x in range(130):
                test_input = hashlib.sha512(str(x).encode()).hexdigest()
                hash_obj = hashlib.new(method)
                hash_obj.update(test_input.encode())
                if hash_obj.hexdigest() == enc_hash:
                    return x
        except:
            continue
```

Sau đó, với từng giá trị trong `ct`, ta dùng hàm `reverse_encrypt` và truy ngược lại giá trị x ban đầu bằng các phép toán và đổi sang dạng ASCII để giải mã nó bằng hàm sau:
```python
def decrypt():
    decrypted_message = ""
    for ct_hash in ct:
        x = reverse_encrypt(ct_hash)
        original_ascii = (x - 20) % 130
        decrypted_message += chr(original_ascii)
    return decrypted_message
```

Script:
```python
ct = ['f189636f8eef640b55d03387864fd17efd324453cc9276be5ff6bd4da88b13fca72438daaab00830a6d14330d37c0f7bee1e7c32d5dda0541a171f66a2343dc1', '1388cafa58065fa0c04372ce57f303cc4ec9fe62', 'f6266e2849bf8b8575701814cc3f3eb5369e887db54b34e85b1e4608b4fbf5e5', '31f33ac191e818db784cf8321d70f84763db2b2e599f90cf65868eec85a10f20ae0e23aa1cd48c2f13eec355b2975089490761a291ac2a1bcf33f5fbecead431', '981e4bce5dede3faa51a936f650e2c1d64169493860c67d68a1ffbbfa32f58598e7869f3f11aefc1620ee8d3ebe4e5f5', 'f06ffaaa6290bf47d26ba2c09c28dddd8f5bcad6ac464ec17fea48040acf1214d10bc109b7c47cffddb6bccd6b61b61a9e629a8f47ab26b80593f29c8c297489', 'a7d95b3bbde885b4eaa76afc6572e18e4483351005f637fe1f5a7bc0b000fe1f', '85245de371c327440a5f343f27d6df361225806e679950bab3a5a336', 'ea1923e909de3c3c3384ad9ae7696d73', '21df20aab35967470aada32375f535d4a735789bf0789fd421f85163c4d75c6e', 'b9491ae1a9de40d30a86c00139bd7d6f496f5bf4ce013bc2d5a43a97', '03f061f60f3527b15ff31d31dcce0761', '981e4bce5dede3faa51a936f650e2c1d64169493860c67d68a1ffbbfa32f58598e7869f3f11aefc1620ee8d3ebe4e5f5', 'f2a1a7e9dd5e6363050b0cdb0579ebfebdc5e348ab538bdcf47616139351cf2b9f92cb4d14446b3ad8bf182875b81e75', '24aaafc58a2b897aed5829b2e96d73b1de7cd680d76a1143cdc8baef', '6d80d11e5f1161ef86619dcdb186852b5218d6ac224b81b63555fe73741631c36ae0bcb5b3228fbed796c22dedeed587c9d65ddb825aee4fae92b6619e7ffd8f', '6f8b39550106044625102ee0cabf9fe1393f0013388633d5742fcc7e8df7708793a96885b9d18b795a2b0d9014704b9f', 'ddf3c543be9cac44f3af078583fe5fddb64104d93308c146c23f52ff25b2a6e23606c42dc0060a4dd9b11b446759cb5de1844471eb3d6d25c43c6fcc0d8d60c4', '95f2739053cf64555b0c0662b5e2d63822433f7fcac6960de6d57efda427461a58c6e2ffac6da6f4caa9407df10cc0be', 'a1bd4e0efc7ce8bd1d63433a0baa87e3a486fbfe2729d73d1dbf7d2822d201ee8726c6d94da1f09f1a53554e440ad6041ecab545b2085dc28c6f6849f0fcea23', 'a7d95b3bbde885b4eaa76afc6572e18e4483351005f637fe1f5a7bc0b000fe1f', '2b4561a521a82af6a26dfb76078ca97ba53a720f7ee67d923a6d3a13', 'b21ed1f3d501a8a842ef1b26ed3863cf10cf8231ee23a079f749cfa322702c8e', 'd798a32b52384219f8779dccf8b2173f4b73f075cbeb4507ee83c94e', 'b863fa3492fb87edcdef766f38a508ed', '9f876db4b58c1b7e499f35cdbd533a810060a0c8250bfc5421e0f42b2715b027', '4b14748ba0f3da581ddd7ec49dac41d34ea1ee6dae90818333b11501', '85153b2a5f8dea7f5488906cb65d61e9ac0666057636ff6b356dd4d8d0fc5d20', '6b91d6259827176bcb3f312a8faca297e56c7e627235b930cf8163b3e7a5328b', 'b21ed1f3d501a8a842ef1b26ed3863cf10cf8231ee23a079f749cfa322702c8e', '4c8740f90af1055f194a4c8e1b69522da228812465eb72b82b35c927bc48bf9d', 'b248b6b2f2c9365aa9a0e9b37a8057effd29bb2f34c79ec0b40124d08986832b5d227db95cb97b176541589985762d9a', '7260f9b5d1c58d0609523114ed324f396335d940f852dba558461b34c5a53630', 'a1bd4e0efc7ce8bd1d63433a0baa87e3a486fbfe2729d73d1dbf7d2822d201ee8726c6d94da1f09f1a53554e440ad6041ecab545b2085dc28c6f6849f0fcea23', '1077caf3ed754ed8fbd49c76134906e8', 'f3565219d115ec74a85056997cc25e98e3e4912a31c858c1e45b841047698e93', '83315b8fa07a35b12e3f47ebb365268b4a4a8ef2', '64c008d6460c2b98aba616b1d0d11a06b9df564b87d3aeedda83b36aacd3d0c160465109eb06c62e86e360cf026faa27a616dbbf2bec269be9ad128af96073bb', '60bbd94b3ac3ea7149fc6cd850d72d4f1750601275832815dd9a23d4c3757d84aca29d716da5dd72a0045f15ff969925', '94327e8c8321421e72f52cd726336e824630ec7dda31b07ce83f11b8234aea7a', 'a69ef62254280226cc4223a2341c727afcd7ce4e3ffd3f2f1c57d9d3cd30659b52b1c2b56f911a7157041b5f0ff8176f', '3c904622c8d8d79c6704d50ae0175b049b3a5708705ecdce932fe426b9f46f1bd6585b8288c1d38f6301c31af5feac02', 'a3939bf491ffd9824056e249d6e355d8423855f0']
import hashlib

methods = ['md5', 'sha256', 'sha3_256', 'sha3_512', 'sha3_384', 'sha1', 'sha384', 'sha3_224', 'sha512', 'sha224']

def reverse_encrypt(enc_hash):
    for method in methods:
        try:
            for x in range(130):
                test_input = hashlib.sha512(str(x).encode()).hexdigest()
                hash_obj = hashlib.new(method)
                hash_obj.update(test_input.encode())
                if hash_obj.hexdigest() == enc_hash:
                    return x
        except:
            continue

def decrypt():
    decrypted_message = ""
    for ct_hash in ct:
        x = reverse_encrypt(ct_hash)
        original_ascii = (x - 20) % 130
        decrypted_message += chr(original_ascii)
    return decrypted_message

if __name__ == "__main__":
    flag = decrypt()
    print(flag)
```

    Flag: W1{are_you_trying_to_predict_randomness@_@}
 
### 4. DH
Tải file, giải nén và mở chall lên:
```python
from Crypto.Util.number import isPrime, long_to_bytes, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randint
from hashlib import sha256


FLAG = b"W1{fake-flag}"

class DH:   

    def __init__(self):
        self.gen_params()

    def gen_params(self):
        self.r = getPrime(512)

        while True:
            self.q = getPrime(42)
            self.p = (2 * self.q * self.r) + 1
            if isPrime(self.p):
                break

        while True:
            self.h = getPrime(42)
            self.g = pow(self.h, 2 * self.r, self.p)
            if self.g != 1:
                break   

        self.a = randint(2, self.p - 2)
        self.b = randint(2, self.p - 2)

        self.A, self.B = pow(self.g, self.a, self.p), pow(self.g, self.b, self.p)
        self.ss = pow(self.A, self.b, self.p)

    def encrypt(self, flag_part):
        key = sha256(long_to_bytes(self.ss)).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(flag_part, 16)).hex()
        return f"encrypted = {ct}"

    def get_params(self):
        return f"p = {self.p}\ng = {self.g}\nA = {self.A}\nB = {self.B}"

def main():

    dh = DH()
    print(dh.get_params())
    print(dh.encrypt(FLAG))

if __name__ == "__main__":
    main()

p = 85013941328859365232686230728938372320812319905627686919070637645614632817039920673725615375841158719310596592903101914818137738460649589340349796188816568005092757847
g = 20033344683527080232439150682925185454003164954955126339094967675384779782733210350757021743656898625398860187361281262413493941502725149445995471514781822892886669776
A = 76548721461171533747911417838852759206858825205673491250696441734297318615226024320798706656529038703728631231084155790148283919370554345818139818854112841655270107839
B = 2103083080159597422706551446020625757109756570951674830166998494220734179439318911618156966499109201221652320384817270671579741987575328177442670242481963924501204498
encrypted = "240e7b7678aaaa0dcbe06de7c5598a1ca0be7e2ae584bc7dfd2388cdb1d4fb6a37ceb94556757afc293999cbe5a5a2dbb4071ebf6cfd4332088555f9b2de1922"
```

 
#### Phân tích:
Trong class DH, có:
```python
def gen_params(self):
        self.r = getPrime(512)

        while True:
            self.q = getPrime(42)
            self.p = (2 * self.q * self.r) + 1
            if isPrime(self.p):
                break

        while True:
            self.h = getPrime(42)
            self.g = pow(self.h, 2 * self.r, self.p)
            if self.g != 1:
                break   

        self.a = randint(2, self.p - 2)
        self.b = randint(2, self.p - 2)

        self.A, self.B = pow(self.g, self.a, self.p), pow(self.g, self.b, self.p)
        self.ss = pow(self.A, self.b, self.p)
```

Hàm `gen_params` tạo một bộ khóa Diffie-Hellman.
```python
def get_params(self):
        return f"p = {self.p}\ng = {self.g}\nA = {self.A}\nB = {self.B}"
```

Khi lấy hàm `get_params` thì sẽ trả về các giá trị p, g, A, B.
```python
def encrypt(self, flag_part):
        key = sha256(long_to_bytes(self.ss)).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(flag_part, 16)).hex()
        return f"encrypted = {ct}"
```
Ngoài ra, còn có hàm `encrypt` lấy giá trị `ss` từ hàm `gen_params` để tạo key cho thuật toán mã hóa AES chế độ ECB, cuối cùng dùng nó để mã hóa `FLAG`.

#### Giải:
Để tìm ra `FLAG` thì ta cần lấy được `key` để giải mã `cipher`
```python
key = sha256(long_to_bytes(ss)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(encrypted)
```
Do đó, ta phải tìm ra giá trị `ss` để tạo được `key`.
Ta có các phương trình sau:

$A≡g^a$ (mod p); $B≡g^b$ $⇒ss≡A^b≡(g^a )^b≡g^{ab}≡(g^b )^a≡B^a$ (mod p)

Ta đã có p, g, A, vậy ta chỉ cần có thêm b là có thể tìm ra `ss`. Tới đây, tôi sử dụng thuật toán Pohlig-Hellman để tìm b qua công thức $B≡g^b$ (mod p) bằng công cụ Alpetron.

 ![image](https://hackmd.io/_uploads/B1qrVPIIJg.png)

Set k = 0, lấy được b = exp và tính được `ss`. Sau đây là script cho thử thách:
 ```python
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from hashlib import sha256

p = 85013941328859365232686230728938372320812319905627686919070637645614632817039920673725615375841158719310596592903101914818137738460649589340349796188816568005092757847
g = 20033344683527080232439150682925185454003164954955126339094967675384779782733210350757021743656898625398860187361281262413493941502725149445995471514781822892886669776
A = 76548721461171533747911417838852759206858825205673491250696441734297318615226024320798706656529038703728631231084155790148283919370554345818139818854112841655270107839
B = 2103083080159597422706551446020625757109756570951674830166998494220734179439318911618156966499109201221652320384817270671579741987575328177442670242481963924501204498
encrypted = "240e7b7678aaaa0dcbe06de7c5598a1ca0be7e2ae584bc7dfd2388cdb1d4fb6a37ceb94556757afc293999cbe5a5a2dbb4071ebf6cfd4332088555f9b2de1922"
encrypted = bytes.fromhex(encrypted)
b = 2891401095038
ss = pow(A, b, p)

key = sha256(long_to_bytes(ss)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(encrypted)
print(flag.decode())
```
    Flag: W1{so_you_know_about_the_Diffie-Hellman-key_exchange}
   
## Reverse
### 5. GiacMoTrua2
Tải file về và phiên dịch mã giả bằng IDA, ta có:

 ![image](https://hackmd.io/_uploads/rymjEDIIJl.png)

Chương trình yêu cầu ta nhập một chuỗi bí mật và đem chuỗi đó so sánh với flag sau khi qua hàm `Lookthis` được mã hóa thành: "W1{live_speels_a5_NoOn_4v4ry_emit!}"

![image](https://hackmd.io/_uploads/BJY7rwIIkx.png)
![image](https://hackmd.io/_uploads/BJ37rvI81e.png)

Hàm `swap` dùng để đổi hai kí tự cho nhau. Hàm `Lookthis` có 3 vòng lặp riêng biệt trên từng khoảng với nhiệm vụ đổi ký tự tương ứng. Như vậy, ta chỉ cần viết script đảo ngược lại và đổi ký tự thì sẽ cho ra được `flag` ban đầu:
 ```python
def reverse_lookthis(flag):

    for k in range(32, 28, -1):
        if k < (61 - k):
            flag[k], flag[61 - k] = flag[61 - k], flag[k]

    for j in range(13, 7, -1):
        if j < (21 - j):
            flag[j], flag[21 - j] = flag[21 - j], flag[j]

    for i in range(6, 2, -1):
        if i < (9 - i):
            flag[i], flag[9 - i] = flag[9 - i], flag[i]

    return flag


fake_flag = [ord(c) for c in "W1{live_speels_a5_NoOn_4v4ry_emit!}"]
real_flag = reverse_lookthis(fake_flag)

flag = "".join(chr(c) for c in real_flag)
print(flag)

```
    Flag: W1{evil_sleeps_a5_NoOn_4v4ry_time!}
 
### 6. Easy Flag Checker
Tải file và phiên dịch mã giả bằng IDA, có:

 ![image](https://hackmd.io/_uploads/S1iYSwI8kg.png)

Qua hàm main, chương trình yêu cầu ta nhập một chuỗi 20 ký tự, sau đó thực hiện vòng lặp kiểm tra với mỗi ký tự thứ 4*i+32 XOR với 0x38. Sau đó lấy ký tự đó so sánh ngay với `dword_4020` thứ i. Chúng ta sẽ truy cập thử vào `dword_4020`:

 ![image](https://hackmd.io/_uploads/rkrcrvULJx.png)

Ở đây, các giá trị trong `unk_4020` là các byte đã được mã hóa. Do đó, ta sẽ lấy các giá trị khác 0 để thực hiện phép XOR và nối lại tạo thành flag.

Sau đây là script cho thử thách:
 ```python
def reverse_lookthis(flag):

    for k in range(32, 28, -1):
        if k < (61 - k):
            flag[k], flag[61 - k] = flag[61 - k], flag[k]

    for j in range(13, 7, -1):
        if j < (21 - j):
            flag[j], flag[21 - j] = flag[21 - j], flag[j]

    for i in range(6, 2, -1):
        if i < (9 - i):
            flag[i], flag[9 - i] = flag[9 - i], flag[i]

    return flag


fake_flag = [ord(c) for c in "W1{live_speels_a5_NoOn_4v4ry_emit!}"]
real_flag = reverse_lookthis(fake_flag)

flag = "".join(chr(c) for c in real_flag)
print(flag)
```

    Flag: W1{v3ry_34sy_r1gh7?}
 
### 7. GiacMoTrua1
Ta thấy tệp thử thách có định dạng .pyc. Sau khi thử tìm kiếm thì tôi biết được đây là một tệp đầu ra được biên dịch được tạo từ mã nguồn được viết bằng ngôn ngữ lập trình Python. Do đó tôi sử dụng PyLingual – một công cụ online để dịch ngược và khôi phục mã nguồn Python:
 
 ![image](https://hackmd.io/_uploads/S1zzUDULkg.png)

Tải file python này về, ta nhận được thử thách như sau:
 ```python
dic = [0] * 85
dic[0] = 33
dic[1] = 35
dic[2] = 36
dic[3] = 37
dic[4] = 38
dic[5] = 40
dic[6] = 41
dic[7] = 42
dic[8] = 43
dic[9] = 44
dic[10] = 45
dic[11] = 46
dic[12] = 47
dic[13] = 48
dic[14] = 49
dic[15] = 50
dic[16] = 51
dic[17] = 52
dic[18] = 53
dic[19] = 54
dic[20] = 55
dic[21] = 56
dic[22] = 57
dic[23] = 58
dic[24] = 59
dic[25] = 60
dic[26] = 61
dic[27] = 62
dic[28] = 63
dic[29] = 64
dic[30] = 65
dic[31] = 66
dic[32] = 67
dic[33] = 68
dic[34] = 69
dic[35] = 70
dic[36] = 71
dic[37] = 72
dic[38] = 73
dic[39] = 74
dic[40] = 75
dic[41] = 76
dic[42] = 77
dic[43] = 78
dic[44] = 79
dic[45] = 80
dic[46] = 81
dic[47] = 82
dic[48] = 83
dic[49] = 84
dic[50] = 85
dic[51] = 86
dic[52] = 87
dic[53] = 88
dic[54] = 89
dic[55] = 90
dic[56] = 91
dic[57] = 97
dic[58] = 98
dic[59] = 99
dic[60] = 100
dic[61] = 101
dic[62] = 102
dic[63] = 103
dic[64] = 104
dic[65] = 105
dic[66] = 106
dic[67] = 107
dic[68] = 108
dic[69] = 109
dic[70] = 110
dic[71] = 111
dic[72] = 112
dic[73] = 113
dic[74] = 114
dic[75] = 115
dic[76] = 116
dic[77] = 117
dic[78] = 118
dic[79] = 119
dic[80] = 120
dic[81] = 121
dic[82] = 122
dic[83] = 123
dic[84] = 125
flag = input("Let me help you check your flag: ")
length = len(flag)
ans = [0] * length * 2
for i in range(length):
    ans[i] = dic[ord(flag[i]) ^ 112]
for i in range(length, length * 2):
    ans[i] = ans[i - length]
fin = ""
for i in range((23 * length + 16) % length, (23 * length + 16) % length + length):
    fin += chr(ans[i])
if fin == "R8Abq,R&;j%R6;kiiR%hR@k6iy0Ji.[k!8R,kHR*i??":
    print("Rightttt!")
    print("Heyy you are really lovely, i promise!")
else:
    print("Think more....")
```
#### Phân tích:
Flag được nhập vào và qua một số bước biến đổi trở thành một đoạn mã hóa cho trước là: `“R8Abq,R&;j%R6;kiiR%hR@k6iy0Ji.[k!8R,kHR*i??”`
Đầu tiên, chúng ta lấy từng giá trị của `flag` dạng thập phân ở hệ Unicode để XOR với 112 rồi lấy đó làm chỉ số để tra bảng `dic` và gán vào dãy `ans`, tiếp theo lấy `ans` thêm vào sau để tạo thành 1 dãy có độ dài gấp đôi `flag`.
 ```python
for i in range(length):
    ans[i] = dic[ord(flag[i]) ^ 112]
for i in range(length, length * 2):
    ans[i] = ans[i - length]
```
Sau đó lập thành dãy `fin` mà ta đã biết trước bằng cách lấy i trong khoảng từ `(23*length+16)  % length` tới `(23*length+16)  % length + length` và lấy đó làm chỉ số với `ans` để chuyển nó về dạng Unicode và thêm vào `fin`.
```python
fin = ""
for i in range((23 * length + 16) % length, (23 * length + 16) % length + length):
    fin += chr(ans[i])
```
 
#### Giải:
Nhận thấy, `fin` có độ dài bằng length và lớn hơn 16 nên:
$23×length+16≡16$ (mod length)

Do đó, `ans` sẽ được tính từ chỉ số 16 của `fin` tăng dần và quay ngược lên 15.
Sau đó, ta phải đảo ngược bảng giá trị `dic` cùng với việc thực hiện phép XOR với 112 để truy ngược lại giá trị ban đầu của flag.

Đây là script cho thử thách:
 ```python
dic = [0] * 85
dic[0] = 33
dic[1] = 35
dic[2] = 36
dic[3] = 37
dic[4] = 38
dic[5] = 40
dic[6] = 41
dic[7] = 42
dic[8] = 43
dic[9] = 44
dic[10] = 45
dic[11] = 46
dic[12] = 47
dic[13] = 48
dic[14] = 49
dic[15] = 50
dic[16] = 51
dic[17] = 52
dic[18] = 53
dic[19] = 54
dic[20] = 55
dic[21] = 56
dic[22] = 57
dic[23] = 58
dic[24] = 59
dic[25] = 60
dic[26] = 61
dic[27] = 62
dic[28] = 63
dic[29] = 64
dic[30] = 65
dic[31] = 66
dic[32] = 67
dic[33] = 68
dic[34] = 69
dic[35] = 70
dic[36] = 71
dic[37] = 72
dic[38] = 73
dic[39] = 74
dic[40] = 75
dic[41] = 76
dic[42] = 77
dic[43] = 78
dic[44] = 79
dic[45] = 80
dic[46] = 81
dic[47] = 82
dic[48] = 83
dic[49] = 84
dic[50] = 85
dic[51] = 86
dic[52] = 87
dic[53] = 88
dic[54] = 89
dic[55] = 90
dic[56] = 91
dic[57] = 97
dic[58] = 98
dic[59] = 99
dic[60] = 100
dic[61] = 101
dic[62] = 102
dic[63] = 103
dic[64] = 104
dic[65] = 105
dic[66] = 106
dic[67] = 107
dic[68] = 108
dic[69] = 109
dic[70] = 110
dic[71] = 111
dic[72] = 112
dic[73] = 113
dic[74] = 114
dic[75] = 115
dic[76] = 116
dic[77] = 117
dic[78] = 118
dic[79] = 119
dic[80] = 120
dic[81] = 121
dic[82] = 122
dic[83] = 123
dic[84] = 125
fin = "R8Abq,R&;j%R6;kiiR%hR@k6iy0Ji.[k!8R,kHR*i??"

length = len(fin)

ans = [ord(fin[i - 16]) for i in range(length)]

reverse_dic = {v: i for i, v in enumerate(dic)}
flag = "".join(chr(reverse_dic[ans[i]] ^ 112) for i in range(length))

print(flag)
```
    Flag: W1{H3pe_y3U_w1ll_enJ9y_th2s_ch311_s0_m3c1!}
