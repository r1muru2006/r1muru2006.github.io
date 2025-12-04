from RC4 import *

secret = 'flag{learning_RC4_with_r1muru}'


print("Welcome to RC4 encryption service!")
while True:
    ct = bytes.fromhex(input(("Enter your ciphertext (hex): ")))
    nonce = bytes.fromhex(input(("Enter your nonce (hex): ")))

    ks = rc4_stream(nonce + secret.encode(), ct)
    pt = bytes([c ^ k for c, k in zip(ct, ks)])
    if pt == b"some_random_words":
        print(b'True!!!')
    else:
        print(f'Not True!!! Your plaintext is: {pt.hex()}')