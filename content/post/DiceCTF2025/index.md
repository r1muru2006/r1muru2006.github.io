---
title: "DiceCTF 2025"
description: "Giải này mình làm được 2 bài misc và 1 bài crypto ngay phút chót @@ nên viết writeup để tổng kết lại cuối tuần này."
date: 2025-03-26T09:31:43+07:00
cover: /images/dicectf.png
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
    - Miscellaneous
categories:
    - CTF Write-up
---

## Misc
### bcu-binding
![image](https://hackmd.io/_uploads/BJ2tcJv61e.png)

Tải file về thì ta search thử 'dice{' để tìm flag và nó ra thật @@
Có vẻ như nó được giấu trong phần nền trắng để không thể nhìn thấy...

![Screenshot 2025-03-29 213449](https://hackmd.io/_uploads/HyXwoyPTJx.png)
    
    Flag: dice{r3ad1ng_th4_d0cs_71ccd}
### dicecap
![image](https://hackmd.io/_uploads/SJIsi1wake.png)

Đề cho ta 1 file pcap nên ta mở nó lên bằng wireshark và xem thử:
![Screenshot 2025-03-29 215831](https://hackmd.io/_uploads/HJg7hyDTkx.png)

Thử tìm theo từ khóa thì ta ra được 2 kênh khả nghi chứa flag theo protocol FTP-DATA.
Export file ra thì ta được 1 file main theo định dạng ELF cùng 1 tệp zip cần mật khẩu mà trong đó chứa flag.txt có thể lấy flag.

File main được định dạng ELF nên ta mở IDA để đọc code của nó
![Screenshot 2025-03-29 223714](https://hackmd.io/_uploads/rkmmR1Dpkg.png)

Ở đây file main khởi tạo mật khẩu và nó có thể được dùng để giải nén file zip. Đọc rõ hơn:
1. Lấy thời gian hiện tại và làm tròn theo phút là được s
2. Lấy 5 ký tự đầu tiên của locale (dest)
3. Ghép username (v3)
4. Kết hợp tất cả thành mật khẩu (v6)

Đầu tiên, khi ta xem lại thì gói main nằm ở No.168 và khi tra lại thì ta lấy được thời gian v1 rồi sau đó tính theo công thức để lấy s.
![image](https://hackmd.io/_uploads/HkktlxD61x.png)

```python
v1 = 1743126530
s = v1 - v1 % 60
# 1743126480
```
Thứ hai về locate thì ta lấy mặc định là `en_US.UTF-8` nhưng chỉ lấy 5 kí tự đầu cho dest là: `en_US`

Cuối cùng, username ta sẽ có được bằng cách tìm kiếm những request được gửi lên thông qua gói tin mà ta có thể xem được và đây là kết quả:
![image](https://hackmd.io/_uploads/r1dCpyvTke.png)
```python
# solution.py
v1 = 1743126530
s = v1 - v1 % 60
locale_str = "en_US"
username = "hacker"
password = f"{s}{locale_str}{username}"
print(password) #1743126480en_UShacker
```
Giải nén file zip và lấy flag thôi:

![image](https://hackmd.io/_uploads/Bkm0GxDTyl.png)

    Flag: dice{5k1d_y0ur_w@y_t0_v1ct0ry_t0d4y!!!}
## Crypto
### vorpal-sword
![image](https://hackmd.io/_uploads/SkrisLv6yx.png)
```python
# server.py
#!/usr/local/bin/python

import secrets
from Crypto.PublicKey import RSA

DEATH_CAUSES = [
    "a fever",
    "dysentery",
    "measles",
    "cholera",
    "typhoid",
    "exhaustion",
    "a snakebite",
    "a broken leg",
    "a broken arm",
    "drowning",
]


def run_ot(key, msg0, msg1):
    """
    https://en.wikipedia.org/wiki/Oblivious_transfer#1–2_oblivious_transfer
    """
    x0 = secrets.randbelow(key.n)
    x1 = secrets.randbelow(key.n)
    print(f"n: {key.n}")
    print(f"e: {key.e}")
    print(f"x0: {x0}")
    print(f"x1: {x1}")
    v = int(input("v: "))
    assert 0 <= v < key.n, "invalid value"
    k0 = pow(v - x0, key.d, key.n)
    k1 = pow(v - x1, key.d, key.n)
    m0 = int.from_bytes(msg0.encode(), "big")
    m1 = int.from_bytes(msg1.encode(), "big")
    c0 = (m0 + k0) % key.n
    c1 = (m1 + k1) % key.n
    print(f"c0: {c0}")
    print(f"c1: {c1}")


if __name__ == "__main__":
    with open("flag.txt") as f:
        flag = f.read().strip()

    print("=== CHOOSE YOUR OWN ADVENTURE: Vorpal Sword Edition ===")
    print("you enter a cave.")

    for _ in range(64):
        print("the tunnel forks ahead. do you take the left or right path?")
        key = RSA.generate(1024)
        msgs = [None, None]
        page = secrets.randbits(32)
        live = f"you continue walking. turn to page {page}."
        die = f"you die of {secrets.choice(DEATH_CAUSES)}."
        msgs = (live, die) if secrets.randbits(1) else (die, live)
        run_ot(key, *msgs)
        page_guess = int(input("turn to page: "))
        if page_guess != page:
            exit()

    print(f"you find a chest containing {flag}")
```

Theo thử thách, bài này nói về [1-2 oblivious transfer](https://en.wikipedia.org/wiki/Oblivious_transfer#1%E2%80%932_oblivious_transfer) nên mình cũng lên mạng tìm hiểu và đây là các bước mà giao thức này thực hiện:
1. Alice có tin nhắn $m_0, m_1$ và 1 cặp khóa RSA $(e, d, N)$.
Bob biết được khóa công khai $(e, N)$ của Alice và muốn tin nhắn $m_c$ , với $c \in \{0, 1\}$.
2. Alice tạo ngẫu nhiên 2 số $x_0, x_1$ và gửi cho Bob.
3. Bob tạo ngẫu nhiên 1 số $k$ và gửi $v = b+k^e \mod N$ cho Alice.
4. Alice tính $k_0 = (v-x_0)^d\mod N$ và $k_1 = (v-x_1)^d\mod N$ rồi gửi $m_0'=m_0+k_0\mod N$ và $m_1'=m_1+k_1\mod N$ cho Bob.
5. Bob tính và lấy được $m_c=m_c'-k\mod N$ và không lấy được thông tin gì từ $m_{1-c}$

Đọc file server thì ta thấy là hàm `run_ot` đúng là đang thực hiện giống như 4 bước đầu trong giao thức trên. Và khi ta truy ngược lại thì ta cần biết được `page` mà được giấu trong tin nhắn `live`
```python
live = f"you continue walking. turn to page {page}."
die = f"you die of {secrets.choice(DEATH_CAUSES)}."
msgs = (live, die) if secrets.randbits(1) else (die, live)
run_ot(key, *msgs)
page_guess = int(input("turn to page: "))
if page_guess != page:
    exit()
```
Tuy nhiên vì `msgs` được random giữa `(live,die)` và `(die, live)`, cùng với việc ta phải nhập đúng `page` trong 64 lần liên tiếp thì rõ ràng việc làm như Bob là lấy được 1 trong 2 tin nhắn không khả thi(vì xác suất trúng được hết chỉ là $\dfrac{1}{2^{64}}$)
Hơn nữa, ta đã biết được list của các `DEATH_CAUSES` nên ta cũng có thể tính được hết tất cả các `die` của chall, tức là ta có thể phân biệt được đâu là `live` và đâu là `die`.

Nhận thấy, ta đã biết $c_0, c_1$, 1 trong hai giá trị $m_0, m_1$ thì việc tìm ra được giá trị còn lại phải dựa vào 1 biểu thức tuyến tính giữa 4 biến này xảy ra.
Nói rõ hơn:
$$
c_0\equiv m_0+k_0\mod n
$$

$$
c_1\equiv m_1+k_1\mod n
$$

$$
\Leftrightarrow a c_0 -bc_1\equiv am_0-bm_1 +(ak_0 -bk_1)\mod n \ \ \ \ \ (*)
$$

Có nghĩa là ta phải tìm v làm sao mà $ak_0-bk_1 \equiv 0 \mod n$, với a,b bất kỳ

Điều này tương đương với: $(v-x_0)^d\equiv k(v-x_1)^d \mod n$
$$
\Leftrightarrow (v-x_0)^{de}\equiv k^e(v-x_1)^{de}\mod n
$$

Chọn v có điều kiện $\gcd(v-x_0, n) = 1$ và sử dụng định lý Euler cùng $de\equiv 1\mod \phi(n)$
$$
\Leftrightarrow v-x_0\equiv k^e(v-x_1)\mod n
$$

$$
\Leftrightarrow (k^e - 1)(v-x_1)\equiv x_1-x_0\mod n
$$

Thử $k=1,-1$ đều không thỏa nên ta thử $k = 2$

Lúc này, $k^e-1=2^{65537}-1$ là 1 số Mersenne nên các ước nguyên tố của nó có [tính chất](https://vi.wikipedia.org/wiki/S%E1%BB%91_nguy%C3%AAn_t%E1%BB%91_Mersenne#C%C3%A1c_%C4%91%E1%BB%8Bnh_l%C3%BD_v%E1%BB%81_s%E1%BB%91_nguy%C3%AAn_t%E1%BB%91_Mersenne): Nếu q là một số nguyên tố của 1 số Mersenne: $q\equiv 1\mod 65537, q\equiv \pm1\mod 8$

Mặt khác, $n$ là một số nguyên tố 1024 bit nằm trong khoảng $2^{1023}$ đến $2^{1024}-1$ và là rất lớn so với ước nguyên tố điển hình của $2^{65537}-1$.

Hơn nữa, theo [Định lý số nguyên tố](https://vi.wikipedia.org/wiki/%C4%90%E1%BB%8Bnh_l%C3%BD_s%E1%BB%91_nguy%C3%AAn_t%E1%BB%91) thì có thể có khoảng $\dfrac{2^{1023}}{ln(2^{1023})} \approx  \dfrac{2^{1023}}{709}$ số nguyên tố 1024 bit. Do đó với 1 số nguyên tố 1024 bit ngẫu nhiên, gần như chắc chắn là số đó không có khả năng là ước của $2^{65537}-1$

Vì vậy, $\gcd(k^e-1,n)=1$ tương đương với  tồn tại nghịch đảo modulo n của $2^{65537}-1$
$$
\Leftrightarrow v-x_1\equiv (k^e - 1)^{-1}(x_1-x_0)\mod n
$$

$$
\Leftrightarrow v\equiv (k^e - 1)^{-1}(x_1-x_0) + x_1\mod n
$$
```python
e = 65537
k = 2**e - 1
def sol_v(n, k, x0, x1):
    d = inverse(k, n)
    return (x1 + d*(x1-x0)) % n
```

Bây giờ trở lại với $(*)$ thì ta được biểu thức tuyến tính sau:
$$
\Leftrightarrow c_0 -2c_1\equiv m_0-2m_1\mod n \ \ \ \ \ (**)
$$

Lúc này, ta chia 2 trường hợp rõ ràng:
1.  nếu `page` nằm trong `live` của $m_0$:
$$
(**)\Leftrightarrow m_0\equiv c_0 -2c_1+2m_1\mod n
$$
```python
def case_m0(n, c0, c1, lst):
    page = -1
    for i in lst:
        k = (c0 - 2*c1 + 2*i) % n
        try:
            res = long_to_bytes(k)
        except ValueError:
            continue
        if res.startswith(b"you continue walking. turn to page "):
            page = res[35:-1]
            if page.isdigit():
                break
    return page
```
2. nếu `page` nằm trong `live` của $m_1$:
$$
(**)\Leftrightarrow m_1\equiv (m_0-c_0+2c_1)\times 2^{-1}\mod n
$$
```python
def case_m1(n, c0, c1, lst):
    page = -1
    inv = inverse(2, n)
    for j in lst:
        k = (j - c0 + 2*c1)*inv % n
        try:
            res = long_to_bytes(k)
        except ValueError:
            continue
        if res.startswith(b"you continue walking. turn to page "):
            page = res[35:-1]
            if page.isdigit():
                break
    return page
```
Đến đây rồi thì, ta brute-force hết cái list của `die` thì ta sẽ biết được trường hợp nào là thỏa và tìm được `page`. Remote tới server và nhận flag thôi :333
```python
# solution.py
from pwn import *
from Crypto.Util.number import *

import sys
sys.set_int_max_str_digits(0)


DEATH_CAUSES = [
    'a fever',
    'dysentery',
    'measles',
    'cholera',
    'typhoid',
    'exhaustion',
    'a snakebite',
    'a broken leg',
    'a broken arm',
    'drowning',
]
lst = []
for i in DEATH_CAUSES:
    die = f'you die of {i}.'
    s = int.from_bytes(die.encode(), 'big')
    lst.append(s)

def rev_data():
    return int(io.recvline().strip().decode())

def take_data1():
    io.recvuntil("n: ")
    n = rev_data()
    io.recvuntil("x0: ")
    x0 = rev_data()
    io.recvuntil("x1: ")
    x1 = rev_data()
    return n, x0, x1

e = 65537
k = 2**e - 1
def sol_v(n, k, x0, x1):
    d = inverse(k, n)
    return (x1 + d*(x1-x0)) % n

def take_data2():
    io.recvuntil("c0: ")
    c0 = rev_data()
    io.recvuntil("c1: ")
    c1 = rev_data()
    return c0, c1

def case_m0(n, c0, c1, lst):
    page = -1
    for i in lst:
        k = (c0 - 2*c1 + 2*i) % n
        try:
            res = long_to_bytes(k)
        except ValueError:
            continue
        if res.startswith(b"you continue walking. turn to page "):
            page = res[35:-1]
            if page.isdigit():
                break
    return page

def case_m1(n, c0, c1, lst):
    page = -1
    inv = inverse(2, n)
    for j in lst:
        k = (j - c0 + 2*c1)*inv % n
        try:
            res = long_to_bytes(k)
        except ValueError:
            continue
        if res.startswith(b"you continue walking. turn to page "):
            page = res[35:-1]
            if page.isdigit():
                break
    return page

io = remote("dicec.tf", 31001)

for _ in range(64):
    n, x0, x1 = take_data1()
    v = sol_v(n, k, x0, x1)
    
    io.recvuntil("v: ")
    io.sendline(str(v))
    c0, c1 = take_data2()
    
    page = case_m0(n, c0, c1, lst)
    if page == -1:
        page = case_m1(n, c0, c1, lst)

    io.recvuntil("turn to page: ")
    io.sendline(page)

data = io.recvall()
print(data)
io.close()
```
    Flag: dice{gl3am1ng_g0ld_doubl00n}