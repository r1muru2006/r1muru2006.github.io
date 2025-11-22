---
title: "NahamCon CTF 2025"
description: "Ở giải này thì mình cùng team aespaFanClub đã tham gia và dành được vị trí thứ 68 chung cuộc. Sau đây là một số chall mình giải được trong quá trình thi..."
date: 2025-06-05T08:19:28+07:00
cover: /images/Certificate.png
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
    - Web
    - Osint
categories:
    - CTF Write-up
---

## 1. Readtherules
![Screenshot 2025-05-24 063727](https://hackmd.io/_uploads/Bkc2_0AGel.png)
    
    Flag: flag{90bc54705794a62015369fd8e86e557b}
## 2. FreeFlag
Thử thách cho ta một file `free_flags.txt` chứa 1000 flag nên ta nghĩ ngay tới việc sử dụng định dạng mẫu và lọc flag phù hợp.
```python
# solution.py
import re

def is_flag(s):
    pattern = r'^flag\{[0-9a-f]{32}\}$'
    return re.match(pattern, s)

with open("free_flags.txt", 'r') as f:
    data = f.readlines()
    lst = []
    for line in data:
        flag = line.strip().split("  ")
        for i in flag:
            lst.append(i)
            
for i in lst:
    if is_flag(i):
        print(i)
```
    Flag: flag{ae6b6fb0686ec594652afe9eb6088167}
    
## 3. Naham Commencement2025
Thử thách cho ta một đường dẫn vào 1 trang đăng nhập, có vẻ như mục đích là ta phải sử dụng đúng tài khoản để truy cập vào và lấy flag. Khi `f12`, thì ta có source sau:
```javascript
// main.js
function a(t) {
    let r = '';
    for (let i = 0; i < t.length; i++) {
        const c = t[i];
        if (/[a-zA-Z]/.test(c)) {
            const d = c.charCodeAt(0);
            const o = (d >= 97) ? 97 : 65;
            const x = (d - o + 16) % 26 + o;
            r += String.fromCharCode(x);
        } else {
            r += c;
        }
    }
    return r;
}

function b(t, k) {
    let r = '';
    let j = 0;
    for (let i = 0; i < t.length; i++) {
        const c = t[i];
        if (/[a-zA-Z]/.test(c)) {
            const u = c === c.toUpperCase();
            const l = c.toLowerCase();
            const d = l.charCodeAt(0) - 97;
            const m = k[j % k.length].toLowerCase();
            const n = m.charCodeAt(0) - 97;
            const e = (d + n) % 26;
            let f = String.fromCharCode(e + 97);
            if (u) {
                f = f.toUpperCase();
            }
            r += f;
            j++;
        } else {
            r += c;
        }
    }
    return r;
}

function c(s) {
    return btoa(s);
}

document.addEventListener('DOMContentLoaded', function () {
    const x1 = "dqxqcius";
    const x2 = "YeaTtgUnzezBqiwa2025";
    const x3 = "ZHF4cWNpdXM=";
    const k = "nahamcon";


    const f = document.getElementById('loginForm');
    const u = document.getElementById('username');
    const p = document.getElementById('password');
    const s = document.getElementById('spinner');
    const d = document.getElementById('result');

    f.addEventListener('submit', function (e) {
        e.preventDefault();

        const q = u.value;
        const w = p.value;


        const q1 = a(q);

        const w1 = b(w, k);

        if (q1 !== x1 || w1 !== x2) {
            d.textContent = "Access denied. Client-side validation failed. Try again.";
            d.className = "error";
            d.style.display = "block";
            return;
        }

        s.style.display = "block";
        d.style.display = "none";

        const g = new FormData();
        g.append('username', q);
        g.append('password', w);

        fetch('/login', {
            method: 'POST',
            body: g
        })
            .then(h => h.json())
            .then(z => {
                s.style.display = "none";
                d.style.display = "block";

                if (z.success) {
                    console.log("🎉 Server authentication successful!");
                    d.innerHTML = `
                    <p>${z.message}</p>
                    <p class="flag">🙌🎉${z.flag}🎉🙌</p>
                `;
                    d.className = "success";
                } else {
                    console.log("❌ Server authentication failed");
                    d.textContent = z.message;
                    d.className = "error";
                }
            })
            .catch(err => {
                console.error("🚨 Network error:", err);
                s.style.display = "none";
                d.style.display = "block";
                d.textContent = "An error occurred while processing your request.";
                d.className = "error";
            });
    });

});
```
Phân tích thì hàm `a()` là Ceasar Cipher dịch 16 và `b()` là Vigenere Cipher với key là 
`k = nahamcon`. Chương trình sử dụng hàm `a(), b()` để chuyển `username` và `password` rồi so sánh với `x1 = "dqxqcius"`,`x2 = "YeaTtgUnzezBqiwa2025"`. Thỏa thì pass và ta lấy được key.
```python
# solution.py
def rev_caesar(s):
    r = ''
    for c in s:
        if c.isalpha():
            o = ord('a') if c.islower() else ord('A')
            r += chr((ord(c) - o - 16) % 26 + o)
        else:
            r += c
    return r

def rev_vigenere(cipher, key):
    r = ''
    j = 0
    for c in cipher:
        if c.isalpha():
            u = c.isupper()
            l = c.lower()
            d = ord(l) - 97
            m = key[j % len(key)].lower()
            n = ord(m) - 97
            e = (d - n + 26) % 26
            f = chr(e + 97)
            r += f.upper() if u else f
            j += 1
        else:
            r += c
    return r

print(rev_caesar("dqxqcius"))
print(rev_vigenere("YeaTtgUnzezBqiwa2025", "nahamcon"))
```
![image](https://hackmd.io/_uploads/HJSVcRCfeg.png)
    
    Flag: flag{c419dfe3a0a621edc0150a133bb7a34c}

## 4. Cryptoclock
```python
# server.py
#!/usr/bin/env python3
import socket
import threading
import time
import random
import os
from typing import Optional

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using XOR with the given key."""
    return bytes(a ^ b for a, b in zip(data, key))

def generate_key(length: int, seed: Optional[float] = None) -> bytes:
    """Generate a random key of given length using the provided seed."""
    if seed is not None:
        random.seed(int(seed))
    return bytes(random.randint(0, 255) for _ in range(length))

def handle_client(client_socket: socket.socket):
    """Handle individual client connections."""
    try:
        with open('flag.txt', 'rb') as f:
            flag = f.read().strip()
        
        current_time = int(time.time())
        key = generate_key(len(flag), current_time)
        
        encrypted_flag = encrypt(flag, key)
        
        welcome_msg = b"Welcome to Cryptoclock!\n"
        welcome_msg += b"The encrypted flag is: " + encrypted_flag.hex().encode() + b"\n"
        welcome_msg += b"Enter text to encrypt (or 'quit' to exit):\n"
        client_socket.send(welcome_msg)
        
        while True:
            data = client_socket.recv(1024).strip()
            if not data:
                break
                
            if data.lower() == b'quit':
                break
                
            key = generate_key(len(data), current_time)
            encrypted_data = encrypt(data, key)
            
            response = b"Encrypted: " + encrypted_data.hex().encode() + b"\n"
            client_socket.send(response)
            
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server.bind(('0.0.0.0', 1337))
    server.listen(5)
    
    print("Server started on port 1337...")
    
    try:
        while True:
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.close()

if __name__ == "__main__":
    main() 
```
Thử thách đơn giản là mã hóa đoạn tin bằng phép XOR và cho ta nhập 1 đoạn text để mã hóa với cùng 1 key, vì thế ta có thể lấy flag dễ dàng qua các phép biển đổi.
```python
# solution.py
from pwn import *

io = remote("challenge.nahamcon.com", 31453, level = 'debug')
io.recvuntil(b': ')

flagenc = io.recvline().strip().decode()
io.recvline()

data = b'a' * 38 # flag.hex() có 76 bytes
io.sendline(data)
dataenc = io.recvline().strip().decode().split(" ")[1]

flagenc = bytes.fromhex(flagenc)
dataenc = bytes.fromhex(dataenc)
flagxordata = bytes(a ^ b for a, b in zip(flagenc, dataenc))
flag = bytes(a ^ b for a, b in zip(flagxordata, data))

print(flag)
```
    flag{0e42ba180089ce6e3bb50e52587d3724}
## 5. Deflation Gangster
Giải nén tệp `gangster.zip`, ta được thư mục `important_docs` có tệp `important_docs.lnk`. Tuy nhiên, tệp này lại là 1 tệp `shortcut` hướng tới `important_docs.zip` mà ta không có manh mối gì. Do đó, mình quay lại xem xét kỹ tệp zip của thử thách và phát hiện điều kỳ lạ.
![Screenshot 2025-06-05 162315](https://hackmd.io/_uploads/rkpR8k1Qxl.png)
Nó có chứa dữ liệu thô là dữ liệu hex dump chứa các phần tiêu chuẩn của ZIP (PK headers) và một chuỗi văn bản ở cuối khá đáng nghi. Và mình decode base64 ra được flag :)))
![Screenshot 2025-06-05 162740](https://hackmd.io/_uploads/rkhBP117ex.png)

    Flag: flag{af1150f07f900872e162e230d0ef8f94}
## 6. Method In The Madness
```javascript
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checkboxes</title>
    <style>
        body {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
        }
        .checkbox-container {
            display: flex;
            flex-wrap: wrap;
            gap: 1.5rem;
            margin-bottom: 2rem;
            justify-content: center;
            max-width: 800px;
        }
        .checkbox-wrapper input[type="checkbox"] {
            width: 2.5rem;
            height: 2.5rem;
            appearance: none;
            border: 2px solid #666;
            border-radius: 4px;
            background-color: #f0f0f0;
            cursor: not-allowed;
        }
        .checkbox-wrapper input[type="checkbox"]:checked {
            background-color: #4CAF50;
            border-color: #45a049;
        }
        .link-container {
            margin-top: 1rem;
        }
        .link-container a {
            color: #666;
            text-decoration: none;
            font-size: 1.2rem;
        }
        .link-container a:hover {
            text-decoration: underline;
        }
        .flag-container {
            display: none;
        }
        .flag-container h1 {
            color: #4CAF50;
            text-align: center;
        }
        .main-content {
            display: flex;
            flex-direction: column;
            align-items: center;
        }
    </style>
</head>
<body>
    <div class="main-content">
        <div class="checkbox-container">
                            <div class="checkbox-wrapper">
                    <input type="checkbox" id="box_1" disabled>
                </div>
                            <div class="checkbox-wrapper">
                    <input type="checkbox" id="box_2" disabled>
                </div>
                            <div class="checkbox-wrapper">
                    <input type="checkbox" id="box_3" disabled>
                </div>
                            <div class="checkbox-wrapper">
                    <input type="checkbox" id="box_4" disabled>
                </div>
                            <div class="checkbox-wrapper">
                    <input type="checkbox" id="box_5" disabled>
                </div>
                            <div class="checkbox-wrapper">
                    <input type="checkbox" id="box_6" disabled>
                </div>
                    </div>
        <div class="link-container">
            <a href="/interesting" target="_blank" rel="noopener noreferrer">checkout this page</a>
        </div>
    </div>
    <div class="flag-container">
        <h1></h1>
    </div>

    <script>
        function updateCheckboxes() {
            fetch('/poll')
                .then(response => response.json())
                .then(data => {
                    // Check if all boxes are true and flag exists
                    let allTrue = true;
                    for (let i = 1; i <= 6; i++) {
                        if (!data[box_${i}]) {
                            allTrue = false;
                            break;
                        }
                    }

                    if (allTrue && data.flag) {
                        // Hide main content and show flag
                        document.querySelector('.main-content').style.display = 'none';
                        document.querySelector('.flag-container').style.display = 'block';
                        document.querySelector('.flag-container h1').textContent = data.flag;
                    } else {
                        // Update checkboxes (only the first 6)
                        for (let i = 1; i <= 6; i++) {
                            const checkbox = document.getElementById(box_${i});
                            if (checkbox) {
                                checkbox.checked = data[box_${i}];
                            }
                        }
                    }
                })
                .catch(error => console.error('Error:', error));
        }

        // Initial update
        updateCheckboxes();

        // Poll every 3 seconds
        setInterval(updateCheckboxes, 3000);
    </script>
</body>
</html> %
```
Mục tiêu của bài là ta phải bật được cả 6 box thành True để lấy flag. Box 1 thì có thể click để bật, còn các box còn lại thì ta sẽ phải gửi đúng request tới các endpoint ẩn.

Đây là request và dữ liệu server gửi về:
```javascript
for m in HEAD POST PUT PATCH DELETE OPTIONS; do
    curl -X $m -s -b cookies.txt -c cookies.txt http://challenge.nahamcon.com:32614/interesting
    curl -s -b cookies.txt http://challenge.nahamcon.com:32614/poll
done
{
    "box_1": true,
    "box_2": false,
    "box_3": false,
    "box_4": false,
    "box_5": false,
    "box_6": false
}<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interesting</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
        }
    </style>
</head>
<body>
    hello
</body>
</html> {
    "box_1": true,
    "box_2": true,
    "box_3": false,
    "box_4": false,
    "box_5": false,
    "box_6": false
}<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interesting</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
        }
    </style>
</head>
<body>
    hello
</body>
</html> {
    "box_1": true,
    "box_2": true,
    "box_3": true,
    "box_4": false,
    "box_5": false,
    "box_6": false
}<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interesting</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
        }
    </style>
</head>
<body>
    hello
</body>
</html> {
    "box_1": true,
    "box_2": true,
    "box_3": true,
    "box_4": true,
    "box_5": false,
    "box_6": false
}<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interesting</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
        }
    </style>
</head>
<body>
    hello
</body>
</html> {
    "box_1": true,
    "box_2": true,
    "box_3": true,
    "box_4": true,
    "box_5": false,
    "box_6": true
}<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interesting</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
        }
    </style>
</head>
<body>
    hello
</body>
</html> {
    "box_1": true,
    "box_2": true,
    "box_3": true,
    "box_4": true,
    "box_5": true,
    "box_6": true,
    "flag": "flag{bd399cb9c3a8b857588d8e13f490b6fd}"
```
![Screenshot 2025-05-25 143003](https://hackmd.io/_uploads/rJc5FkJXeg.png)

    Flag: flag{bd399cb9c3a8b857588d8e13f490b6fd}
## 7. Taken To School
Thử thách cho ta file `network-log.cef` chứa các thông tin đăng nhập đáng nghi.
Vì nó cho có 500 dòng nên ta sẽ ~~brute-force~~ google các sự kiện vào ngày 22-12-2024 và mình tìm thấy website này: [Link](https://www.powerschool.com/security/sis-incident/).
Từ đây, mình tìm đuọc report của CrowdStrike, cụ thể là: [Link](https://www.powerschool.com/wp-content/uploads/2025/03/PowerSchool-CrowdStrike-Final-Report.pdf)
![image](https://hackmd.io/_uploads/HyDB6ky7lx.png)
Tìm `91.218.50[.]11` trong tệp logs và từ đó là eventHash mà mình cần:
![image](https://hackmd.io/_uploads/rkSYp11Xel.png)

    Flag: flag{5b16c7044a22ed3845a0ff408da8afa9}

## 8. Sending Mixed Signals
Sau khi vào thử thách thì ta tìm thấy nó là dạng trả lời câu hỏi và hoàn thành sẽ trả về flag.
![image](https://hackmd.io/_uploads/Sk_bJeyQxe.png)
Thử thách cho ta 1 đường dẫn tới [bài báo](https://www.theatlantic.com/politics/archive/2025/03/trump-administration-accidentally-texted-me-its-war-plans/682151/) về người đã báo cáo về vụ việc để lộ thông tin mật của Trump Administration và sử dụng ứng dụng nhắn tin đầy lỗ hổng bảo mật.
![Screenshot 2025-06-05 172227](https://hackmd.io/_uploads/rJRCllyXeg.png)

Ngoài ra mình còn google thêm một số bài viết khác và khai thác được [bài](https://micahflee.com/heres-the-source-code-for-the-unofficial-signal-app-used-by-trump-officials/) sau đây:
![image](https://hackmd.io/_uploads/rJ5NZxyXgl.png)

    Part 1: Find the hard-coded credential in the application used to encrypt log files. (format jUStHEdATA, no quotes)

Khi thấy bài báo là mình đã tìm được đáp án cho câu hỏi đầu: `enRR8UVVywXYbFkqU#QDPRkO`

    Part 2: Find the email address of the developer who added the hard-coded credential from question one to the code base (format name@email.site)

Tiếp đó mình kéo xuống để tìm thêm thông tin trả lời cho câu 2 thì tìm được email của những người đã lập trình nên phần mềm:

![image](https://hackmd.io/_uploads/HkWwMxymeg.png)
Dùng phép thử thì mình tìm được đáp án cho phần 2 là: `moti@telemessage.com`

    Find the first published version of the application that contained the hard-coded credential from question one (case sensitive, format Word_#.#.#......).

Để tìm được phiên bản đã sử dụng cái `hard-coded credential` thì mình đã truy về github của app được đề cập ngay trong bài báo
![image](https://hackmd.io/_uploads/rJdUmgJmgx.png)

Khi xem xét thì ta thấy là có đến 124 tags của phiên bản được release: [Link](https://github.com/micahflee/TM-SGNL-Android)

Truy ngược từ dưới thì mình tìm được phiên bản được công khai sớm nhất của ứng dụng là: `Release_5.4.11.20` và đó cũng là đáp án của Part 3.
    
    Flag: flag{96143e18131e48f4c937719992b742d7}