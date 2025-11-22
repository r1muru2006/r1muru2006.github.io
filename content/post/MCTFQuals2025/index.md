---
title: "M*CTF Quals 2025"
description: "First Top 1 with Wanna.Win"
date: 2025-11-21T22:19:58+07:00
cover: /images/mctf/mctf.png
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
    - Research
categories:
    - Learning
---

# WELCOME
## W3lc0m3_ M7_Fr13nd$
![images](/images/mctf/Welcome.png)
This link leads to the main Telegram group for discussing the contest and here I found this post flag.

However, we must remove the * in `M*CTF` to get the correct flag.

**Flag:** `MCTF{ok3y_l3ts_g0}`
# SBER
## CRCL35
![images](/images/mctf/CRCL35.png)

This is the picture:

![images](/images/mctf/challCRC.png)

This is the description of the challenge after translation:
```
"Everything... is unreal?"

"What is reality? And how do you define it? The entire range of sensations: visual, tactile, olfactory—these are signals from receptors, electrical impulses received by the brain."

"So, it's all NULL?"

"No, it's all 0. Don't confuse it and don't forget the difference, otherwise, during the transformation, you'll end up in the wrong place."
```

In the description, I noticed the word "difference" so I quickly tested this method by python and it worked.

```python
s0 = [180, 78, 186, 89, 192, 69, 185]
s1 = [360, 256, 151, 266, 171, 286, 175]
s2 = [520, 425, 326, 215, 104, 212, 337]
for arr in (s0, s1, s2):
    for j in range(len(arr) - 1):
        print(chr(abs(arr[j+1] - arr[j])), end = '')
```
This give us `flag{this_so_cool}` so I replace `flag` with `MCTF` to get it.

**Flag:**`MCTF{this_so_cool}`

## BackPuckUp
![images](/images/mctf/BackPuckUp.png)

In the source, I found the main `app.py` which contains many of the site's secrets and inside there is also a flag: `flag{adm1n_artifact_rec0very_2025}`.
Here is the place I took this flag:
```python
# admin_task1/flask-app/app.py
@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if session["user"] == ADMIN_USER:
        return render_template("profile.html", 
                             username=session["user"],
                             flag="flag{adm1n_artifact_rec0very_2025}")
    
    return render_template("profile.html", 
                         username=session["user"],
                         flag="Обычный пользователь - флага нет")
```
I wondered if it was a fake flag, but I sent it with the alternate prefix and it worked.

**Flag:** `MCTF{adm1n_artifact_rec0very_2025}`

## Geo_What?
![images](/images/mctf/Geo_What.png)

This is the description of the challenge after translation:
```
In the world of cyberpunk, where technology and information rule, the story of the search for a great train that could change the course of history has become the stuff of legend.

This train, hidden in the depths of the digital world, was the key to solving many mysteries and riddles. Many adventurers tried to find it, but all their attempts ended in failure. All they had was the mysterious string "ucfwsz," which they found in the most unexpected places.

No one knew what it meant, but everyone believed it was part of a cipher leading to the train. One day, a young hacker named Alex decided to take on this task. He spent countless hours exploring cyberspace, breaking into secure servers, and deciphering complex codes.

And finally, he found it—the great train.

Alex realized that the string "ucfwsz" was the key to finding the train, but it was only part of the coordinates. The key was a string that allowed him to locate a sector on the map. But before he could use this knowledge, he faced his final challenge.

The train's defense system was intelligent and ruthless. It knew Alex was approaching, and it tried to stop him.

But Alex was ready. He used all his skills and knowledge to bypass the defenses and reach the heart of the system.

In the end, Alex disappeared. His story became the beginning of a journey for all enthusiasts interested in both Alex's story and the search for the mysterious train.
```
The keyword I found for this challenge is: `a great train that could change the course of history`, `ucfwsz` and `only part of the coordinates`.
In short, we need to find a great train that has some history, then it can become a monument. Next, the keyword `ucfwsz` made me google for a while and found out it is a geohash. Here is where `ucfwsz` is:
![images](/images/mctf/geohash.png)

Because they said it was `only part of the coordinates` so I scanned all within the square area. Luckily, I found something that looked like a tombstone and fit the square perfectly. Can you found out just by looking through this picture 😂😂?
![images](/images/mctf/geohash2.png)

Woww you have such sharp eyes, it's right here:
![images](/images/mctf/geohash3.png)

**Flag:**`mctf{ucfwszjc}`

Outside knowledge: The name of monument - ЭР21-7109 is a model of a train
![images](/images/mctf/geohash4.png)

# Hardware
## Display ception
![images](/images/mctf/hardware.png)
