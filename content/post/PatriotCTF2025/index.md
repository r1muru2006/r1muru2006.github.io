---
title: "Patriot CTF 2025"
description: "Ranked 25th with ResetSec"
date: 2025-11-24T21:40:43+07:00
cover: /images/patriot/patriot.png
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
    - Reverse Engineering
    - Osint
categories:
    - CTF Write-up
---

# Osint
## Where's Legally Distinct Waldo One
![images](/images/patriot/osint1.png)

We have to find the building place where they take this picture. After using google lens, I got this:
![images](/images/patriot/osint1_1.png)

It looks exactly the same so I clicked in this article:
![images](/images/patriot/osint1_2.png)

So we know that it relates to `the campus of George Mason University in Fairfax, VA`. Therefore, I googled map it and scanned around:
![images](/images/patriot/osint1_3.png)

In the picture, I noticed an area with a similar patterned tile floor to the challenge in the lower right corner of the photo at the George Mason Statue. When I scanned this street, I saw a corner with the same pattern and the building name `Horizon Hall` had the same view.
![images](/images/patriot/osint1_4.png)

**Flag:** `pctf{Horizon_Hall}`

## Where's Legally Distinct Waldo Two
![images](/images/patriot/osint2.png)

I tried many ways with the google lens but this didn't work. Luckily, we know this is a place in the campus above. Therefore, I looked for some identifying features in this challenge. These are `a large road with a yellow line in the middle`, `a street-facing parking space` and `a pedestrian crossing` next to.

This didn't take up too much of my time and here it is:
![images](/images/patriot/osint2_1.png)

Zoomed in and I got the flag.

**Flag:** `pctf{Thompson_Hall}`

## Where's Legally Distinct Waldo Three
![images](/images/patriot/osint3.png)

Identifying features in this challenge are `a large lake with a small road on the right`, `a fork behind the lake` and `a roadside parking space`.

Quickly finding the lake satisfied is Mason Pond and the building is `Center for the Arts`.
![images](/images/patriot/osint3_1.png)

However, the server didn't take this as a flag @@. So I had to find another name of this building and this took me many attempts.

After googling, I have `College of Visual and Performing Arts`, `George Mason University's Center for the Arts`. Using Bing Maps, I got the name `Concert Hall`.
![images](/images/patriot/osint3_2.png)

Seems true but not, all of these is wrong :))))) With trial and error method, the flag appears finally.

**Flag:** `pctf{Center_for_the_Arts_Concert_Hall}`

## Where's Legally Distinct Waldo Four
![images](/images/patriot/osint4.png)

This time, it gave me a wall, a tree and two buildings far behind. Well, I just used my eyes to look closely at the two buildings to find its features.
![images](/images/patriot/osint4_1.png)

These two buildings have two opposite sides of orange walls and may be of equal height. In particular, the building on the left has an unusually tall gray column that seems to protrude from the wall. At that time, I used Bing Maps 3D mode to search all corners of all buildings on this campus (yeah went crazyyy)

Boom, I saw the corner of the Fenwick Gallery at the Fenwick Library that looked exactly like that.
![images](/images/patriot/osint4_2.png)

With the direction and angle from the challenge, I saw it heading towards this 4 block area.
![images](/images/patriot/osint4_3.png)

Well, you have 5 tries to submit the flag. But since I wanted to be sure, I calculated the most reasonable angle, direction and decided to take Krug Hall. Amazing that it was right.

**Flag:** `pctf{Krug_Hall}`

# Reverse Engineering
## Are_You_Pylingual

This challenge gave us a .pyc file and `output.txt`. After multiple times meeting this kind of files, I know that we have to convert it to python to read and somehow got the flag.

So I use [pylingual.io](https://pylingual.io/) to get the chall in python and here it is:
```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: pylinguese.py
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 2025-09-06 18:41:22 UTC (1757184082)

import pyfiglet
file = open('flag.txt', 'r')
flag = file.read()
font = 'slant'
words = 'MASONCC IS THE BEST CLUB EVER'
flag_track = 0
art = list(pyfiglet.figlet_format(words, font=font))
i = len(art) % 10
for ind in range(len(art)):
    if ind == i and flag_track < len(flag):
        art[ind] = flag[flag_track]
        i += 28
        flag_track += 1
art_str = ''.join(art)
first_val = 5
second_val = 6
first_half = art_str[:len(art_str) // 2]
second_half = art_str[len(art_str) // 2:]
first = [~ord(char) ^ first_val for char in first_half]
second = [~ord(char) ^ second_val for char in second_half]
output = second + first
print(output)
```

Reverse this code and we could receive the flag:
```python
output = [-90, -42, -39, -42, -39, -39, -39, -42, -39, -42, -39, -42, -39, -42, -39, -90, -90, -39, -48, -13, -52, -39, -42, -39, -42, -39, -42, -39, -42, -90, -42, -39, -42, -39, -90, -90, -42, -39, -39, -39, -39, -42, -39, -90, -90, -39, -39, -42, -105, -90, -90, -42, -39, -39, -91, -90, -90, -39, -91, -39, -42, -39, -42, -39, -39, -39, -39, -42, -39, -42, -39, -39, -39, -42, -39, -42, -34, -39, -39, -42, -39, -42, -39, -42, -39, -42, -39, -90, -90, -39, -39, -123, -13, -39, -42, -39, -42, -39, -42, -39, -90, -90, -39, -39, -115, -39, -42, -90, -90, -90, -39, -39, -39, -42, -39, -42, -90, -42, -39, -42, -39, -42, -90, -90, -90, -39, -90, -90, -90, -42, -39, -42, -90, -39, -42, -39, -39, -39, -39, -42, -39, -42, -90, -90, -90, -42, -39, -42, -90, -90, -90, -42, -39, -42, -90, -42, -39, -42, -39, -42, -68, -42, -39, -42, -39, -13, -42, -90, -42, -39, -42, -90, -42, -39, -42, -90, -42, -90, -90, -90, -90, -90, -42, -39, -39, -42, -90, -90, -105, -90, -90, -42, -90, -90, -90, -90, -90, -42, -42, -90, -90, -90, -90, -42, -42, -90, -42, -39, -39, -39, -39, -39, -91, -90, -90, -90, -102, -42, -90, -90, -90, -90, -90, -42, -91, -90, -90, -90, -90, -42, -90, -90, -90, -90, -90, -42, -39, -39, -13, -39, -39, -39, -39, -39, -85, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -128, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -119, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -13, -39, -39, -39, -39, -90, -90, -90, -90, -90, -90, -90, -39, -39, -39, -39, -90, -115, -90, -90, -90, -90, -90, -90, -90, -90, -90, -90, -39, -13, -39, -39, -39, -42, -39, -90, -90, -90, -90, -42, -39, -123, -39, -39, -42, -56, -42, -39, -90, -90, -90, -90, -42, -39, -90, -90, -39, -91, -13, -39, -39, -42, -39, -90, -90, -42, -39, -39, -123, -39, -123, -39, -42, -106, -42, -39, -90, -90, -42, -39, -42, -39, -42, -90, -42, -39, -42, -13, -39, -42, -39, -42, -90, -90, -90, -39, -39, -123, -39, -123, -42, -73, -42, -39, -42, -90, -90, -90, -42, -39, -90, -43, -39, -90, -42, -39, -13, -42, -90, -90, -90, -90, -90, -42, -39, -39, -123, -90, -90, -124, -42, -90, -90, -90, -90, -90, -42, -90, -42, -39, -123, -90, -123, -39, -39, -13, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -39, -13, -38, -38, -118, -38, -91, -91, -38, -38, -91, -91, -91, -91, -91, -91, -38, -38, -38, -91, -91, -91, -91, -91, -38, -91, -91, -91, -91, -38, -38, -91, -103, -38, -38, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -38, -38, -38, -91, -91, -91, -91, -91, -91, -91, -91, -114, -16, -38, -38, -38, -43, -38, -38, -122, -43, -38, -38, -43, -38, -38, -38, -122, -38, -43, -38, -91, -91, -91, -43, -43, -38, -91, -91, -100, -90, -43, -38, -122, -38, -43, -38, -43, -38, -91, -91, -91, -91, -43, -38, -91, -91, -91, -91, -43, -38, -38, -43, -38, -38, -91, -43, -127, -91, -91, -91, -43, -16, -38, -38, -43, -38, -43, -122, -91, -43, -38, -43, -38, -43, -122, -38, -122, -38, -90, -91, -91, -38, -90, -43, -107, -43, -38, -43, -38, -43, -38, -38, -122, -43, -38, -43, -38, -43, -38, -38, -38, -43, -38, -43, -38, -38, -38, -38, -38, -38, -38, -43, -104, -43, -38, -90, -91, -91, -38, -90, -38, -16, -38, -43, -38, -43, -38, -38, -43, -38, -43, -38, -91, -91, -91, -38, -122, -91, -91, -91, -68, -38, -43, -38, -43, -91, -43, -38, -43, -38, -43, -122, -38, -38, -43, -38, -43, -91, -91, -91, -43, -38, -43, -91, -91, -91, -38, -38, -113, -91, -43, -38, -43, -38, -91, -91, -91, -43, -38, -43, -38, -16, -43, -91, -43, -38, -38, -43, -91, -43, -91, -43, -38, -38, -122, -91, -119, -91, -91, -91, -91, -43, -90, -91, -91, -91, -91, -43, -91, -43, -38, -122, -91, -43, -90, -91, -91, -91, -91, -43, -90, -91, -91, -91, -103, -43, -38, -38, -43, -91, -91, -91, -43, -43, -91, -91, -91, -91, -43, -38, -38, -16, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -50, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -114, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -16, -38, -38, -91, -91, -91, -91, -109, -91, -91, -91, -38, -38, -91, -91, -91, -91, -91, -91, -91, -91, -38, -38, -38, -91, -91, -91, -91, -38, -38, -91, -91, -91, -91, -91, -54, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -38, -38, -38, -91, -91, -91, -91, -91, -91, -91, -91, -38, -38, -38, -38, -91, -108, -38, -38, -91, -91, -91, -91, -91, -91, -38, -16, -38, -43, -91, -38, -38, -91, -91, -43, -38, -43, -38, -43, -38, -43, -38, -91, -91, -91, -91, -43, -38, -38, -43, -38, -91, -91, -38, -45, -43, -38, -91, -91, -91, -91, -43, -38, -91, -91, -91, -43, -91, -38, -38, -91, -91, -109, -38, -38, -43, -38, -91, -91, -91]
second_vals = output[:len(output) // 2]
first_vals  = output[len(output) // 2:]

first_half  = ''.join(chr(~(v ^ 5))for v in first_vals)
second_half = ''.join(chr(~(v ^ 6)) for v in second_vals)

art_str = first_half + second_half

flag = ''
i = len(art_str) % 10
while i < len(art_str):
    flag += art_str[i]
    i += 28

print(flag)
```

**Flag:** `pctf{obFusc4ti0n_i5n't_EncRypt1oN}`

# Crypto
## Password Palooza

Give this hash of the password: `3a52fc83037bd2cb81c5a04e49c048a2`, find the password with hint that it has 2 number at the end.

I use `hashcat -m 0 -a 6 3a52fc83037bd2cb81c5a04e49c048a2 rockyou.txt '?d?d'` and receive the password.

**Flag:** `pctf{mr.krabbs57}`

## Cipher from Hell

We have an `encrypted` file and an `encryptor.py`:
```python
import math, sys

inp = input("Enter your flag... ").encode()

s = int.from_bytes(inp)

o = (
	(6, 0, 7),
	(8, 2, 1),
	(5, 4, 3)
)

c = math.floor(math.log(s, 3))

if not c % 2:
	sys.stderr.write("Error: flag length needs to be even (hint: but in what base system?)!\n")
	sys.exit(1)

ss = 0

while c > -1:
	ss *= 9
	ss += o[s//3**c][s%3]
	
	s -= s//3**c*3**c
	s //= 3
	c -= 2

open("encrypted", 'wb').write(ss.to_bytes(math.ceil(math.log(ss, 256)), byteorder='big'))
```
It performs the conversion of the flag's content (in string form) to a large integer, then transforms that number based on base-3 and saves the result to an encrypted file.
