from chacha20_poly1305 import *
import os

key = os.urandom(32)
nonce = os.urandom(12)
aad = ""

messages = [
    "ChaCha20-Poly1305 is an authenticated cipher with associated data (AEAD).",
    "It works with a 32 byte secret key and a nonce."
]

goal = "But it's only secure if used correctly!"

def encrypt(message):
    ciphertext, tag = aead_chacha20_poly1305_encrypt(key, nonce, aad, message)
    return ciphertext + tag + nonce

def decrypt(message_enc):
    ciphertext = message_enc[:-28]
    tag = message_enc[-28:-12]
    nonce = message_enc[-12:]
    plaintext = aead_chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, tag)
    return plaintext

for message in messages:
    print("Plaintext: " + repr(message))
    message = message.encode()
    print("Plaintext (hex): " + message.hex())
    ciphertext = encrypt(message)
    print("Ciphertext (hex): " + ciphertext.hex())

user = bytes.fromhex(input("What is your message? "))
user_message = decrypt(user)
print("User message (decrypted): " + repr(user_message))

if goal in repr(user_message):
    print("SUCCESSFULLY HACKING!!!")
else: print("Try again next time!")

