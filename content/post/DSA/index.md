---
title: "Digital Signature Algorithm"
description: "Các lược đồ chữ ký số là các giao thức mật mã (sử dụng RSA, DSA hoặc ECDSA) đảm bảo tính toàn vẹn, tính xác thực và tính không thể phủ nhận của thông điệp."
date: 2026-02-12T19:55:47+07:00
cover: /images/DSA/avatar.png
math: true
license: 
hidden: false
comments: true
tags: 
    - Cryptography
    - Research
categories:
    - Learning
---

# Chữ Ký Số (Digital Signature Algorithm)

Chữ ký số hoạt động tương tự như chữ ký ngoài đời thực, mang chức năng xác nhận danh tính của một cá nhân hay tổ chức đối với một đoạn văn bản. Sự khác biệt tất yếu là chữ ký số được áp dụng cho các biên bản đã được số hóa trên không gian mạng, thay vì biên bản giấy (analog).

Một thuật toán chữ ký số an toàn phải bảo đảm 2 nguyên tắc cốt lõi:
1. **Tính không thể giả mạo:** Chỉ có chủ sở hữu khóa bí mật mới có thể tạo ra chữ ký.
2. **Tính có thể xác thực:** Bất cứ ai cũng có thể sử dụng khóa công khai để xác nhận tính hợp lệ của chữ ký đó.

---

## 1. Tầm Quan Trọng & Ứng Dụng Thực Tiễn
Việc áp dụng chữ ký số, đặc biệt đối với các văn bản quan trọng của cá nhân, tổ chức hay chính phủ, là cực kỳ cần thiết. Chữ ký số giải quyết 3 bài toán lớn trong an toàn thông tin:

* **Bảo đảm tính toàn vẹn dữ liệu (Data Integrity):** Ngăn chặn và phát hiện mọi sự thay đổi, sửa đổi trái phép đối với dữ liệu trong quá trình truyền tải.
* **Xác thực (Authentication):** Khẳng định danh tính chính xác của người gửi và tác giả của văn bản.
* **Không thể phủ nhận (Non-Repudiation):** Cung cấp bằng chứng pháp lý rõ ràng, người ký không thể chối bỏ việc mình đã tham gia vào giao dịch số.

---

## 2. Cấu Trúc Chung Của Một Hệ Thống Chữ Ký Số
Mọi hệ thống chữ ký số đều bao gồm 3 thuật toán con:
1.  **Thuật toán tạo khóa (Key Generation):** Sinh ra một cặp khóa bất đối xứng gồm public key và private key.
2.  **Thuật toán ký (Signing):** Nhận đầu vào là message và private key để tạo ra chữ ký.
3.  **Thuật toán xác thực (Verification):** Nhận đầu vào là chữ ký, message và public key để trả về kết quả hợp lệ hoặc không.

**Lưu ý quan trọng về hàm băm:** Trong thực tế, message hiếm khi được ký trực tiếp. Thay vào đó, dữ liệu sẽ đi qua một hàm băm (như MD5, SHA-1, SHA-256). Việc ký trên giá trị Hash giúp giảm thiểu khối lượng tính toán khổng lồ.

---

## 3. Phân Tích Các Thuật Toán Tiêu Biểu

Các thuật toán phổ biến nhất hiện nay bao gồm RSA, DSA và ECDSA.

![images](/images/DSA/sign.png)

### 3.1. Thuật toán RSA
Bên cạnh khả năng mã hóa thông điệp, RSA còn đóng vai trò là một thuật toán chữ ký số mạnh mẽ.

* **Tạo khóa:**
    * Chọn 2 số nguyên tố lớn $p, q$.
    * Tính Modulus: $N = p \cdot q$.
    * Chọn số mũ xác thực (verifying exponent) $e$.
    * Tính số mũ ký (signing exponent) $d \equiv e^{-1} \pmod{(p-1)(q-1)}$.
    * Public Key: $(N, e)$ | Private Key: $d$.
* **Ký thông điệp (Sign):**
    $$S \equiv M^d \pmod{N}$$
* **Xác thực (Verify):**
    $$M \equiv S^e \pmod{N}$$

### 3.2. Thuật toán DSA (Digital Signature Algorithm)
DSA được xây dựng dựa trên nền tảng của thuật toán Schnorr và ElGamal. Điểm mấu chốt của DSA là tham số ngẫu nhiên $k$ (nonce) được tạo ra cho mỗi lần ký. 

* **Tạo khóa:**
    * Khóa công khai (Public key - pk): $y = g^{sk} \pmod{p}$
    * Khóa bí mật (Private key - sk): $x$ (hoặc $sk$)
* **Ký thông điệp (Sign):** Sử dụng tham số ngẫu nhiên $k$.
    $$r \equiv (g^k \pmod{p}) \pmod{q}$$
    $$s \equiv k^{-1} \cdot (H(m) + sk \cdot r) \pmod{q}$$
    Chữ ký sinh ra là một cặp giá trị: $(r, s)$.
* **Xác thực (Verify):**
    $$w \equiv s^{-1} \pmod{q}$$
    $$u_1 \equiv H(m) \cdot w \pmod{q}$$
    $$u_2 \equiv r \cdot w \pmod{q}$$
    $$v \equiv (g^{u_1} \cdot y^{u_2} \pmod{p}) \pmod{q}$$
    *Chữ ký hợp lệ nếu $v = r$*.

**Cảnh báo bảo mật:** Giá trị $k$ phải hoàn toàn ngẫu nhiên và **tuyệt đối không được trùng lặp** khi ký các văn bản khác nhau bằng cùng một private key. Nếu $k$ bị rò rỉ hoặc tái sử dụng, kẻ tấn công có thể dễ dàng đảo ngược phương trình để khôi phục hoàn toàn private key.

### 3.3. Thuật toán ECDSA (Elliptic Curve DSA)
ECDSA là biến thể của DSA áp dụng trên hệ mật mã đường cong Elliptic (ECC). Ưu điểm vượt trội của ECDSA là nhanh, gọn và nhẹ. Quá trình tính toán nhẹ hơn nhờ việc ECC sử dụng phép cộng điểm trên đường cong thay vì phép nhân số học khổng lồ.

* **Toán học cơ bản:**
    * Private Key ($d_A$): Một số nguyên ngẫu nhiên.
    * Public Key ($Q_A$): Sinh ra từ phép nhân vô hướng của điểm cơ sở $G$ trên đường cong: $Q_A = d_A \times G$.
    * Quá trình ký (Signed hash) sinh ra (r,s) tương tự DSA nhưng áp dụng tính toán hình học trên tọa độ đường cong.

**Cấp độ bảo mật (NIST Guidelines):**
ECDSA cung cấp độ an toàn tương đương RSA/DSA nhưng với kích thước khóa nhỏ hơn rất nhiều (tối ưu không gian lưu trữ và băng thông).

| Cấp độ bảo mật (Security Level) | Khóa DSA / RSA (bits) | Khóa ECC (bits) | Tỷ lệ RSA : ECC |
| :--- | :--- | :--- | :--- |
| 80 | 1024 | 160-223 | 1:6 |
| 112 | 2048 | 224-255 | 1:9 |
| 128 | 3072 | 256-383 | 1:12 |
| 192 | 7680 | 384-511 | 1:20 |
| 256 | 15380 | 512+ | 1:30 |
---

## 4. Các Biện Pháp Tấn Công Phổ Biến (Attack Vectors)

Hiểu được cách hoạt động đồng nghĩa với việc biết cách khai thác nó. Dưới đây là các kỹ thuật tấn công tiêu biểu đối với từng hệ mật:

* **Đối với RSA:**
    * [*Thường gặp*](https://www.youtube.com/watch?v=y35Xk-rUqiE)
    * [*Blinding attack* ](https://www.youtube.com/watch?v=D4O_y8ek6t0)

* **Đối với DSA / ECDSA:**
    * [*Reuse nonce / Nonce collision*](https://notsosecure.com/ecdsa-nonce-reuse-attack)
    * [*Related nonce / Biased nonce:*](https://sruthisekar.wordpress.com/wp-content/uploads/2024/11/ct13.pdf)
    * [*Lattice Attacks*](https://scispace.com/pdf/some-lattices-attacks-on-dsa-and-ecdsa-130e209wkq.pdf)

---

## 5. Tài Liệu Thực Hành & Luyện Tập

Để củng cố kiến thức thực chiến, làm các bài tập sau:
* **Cryptohack (RSA Signatures):** https://cryptohack.org/challenges/rsa/
* **Cryptohack (ECC Signatures):** https://cryptohack.org/challenges/ecc/
* **Hackropole (Bài tập El-Gamal fait 1 & 2):** https://hackropole.fr/en/crypto/