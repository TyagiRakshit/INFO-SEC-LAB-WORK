# 1. Encrypt the message "I am learning information security" using one of the following ciphers.
# Ignore the space between words. Decrypt the message to get the original plaintext:
# a) Additive cipher with key = 20
# b) Multiplicative cipher with key = 15
# c) Affine cipher with key = (15, 20)



def caesar(ch,key):
    if 'A' <= ch<='Z':
        return chr((ord(ch)-ord('A')+key)%26+ord('A'))
    elif 'a' <= ch<='z':
        return chr((ord(ch)-ord('a')+key)%26+ord('a'))
    else:
        return ch


text=input("Enter the plain text: ")
key_1=int(input("Enter the key for caesar encryption: "))

encrypted_text=""
for ch in text:
    encrypted_text += caesar(ch,key_1)
decrypted_text=""
for ch in encrypted_text:
    decrypted_text += caesar(ch,-key_1)
print(f"Plaintext is : {text}")
print(f"Encrypted text via caesar cipher is : {encrypted_text}")
print(f"Decrypted text via caesar cipher is : {decrypted_text}")
print()

#multiplicative cipher
#instead of adding we multiply
#to decrypt we can't simply divide we need multiplicative inverse
#not every key is valid ie must be coprime with 26

import math
def mmi(key):
    if math.gcd(key,26)!=1:
        raise ValueError("Key has no multiplicaitve inverse")
    return pow(key,-1,26)

def multiplicative(ch,key):
    if 'A' <= ch <= 'Z':
        return chr(((ord(ch)-ord('A'))*key)%26 +ord('A'))
    elif 'a' <= ch <= 'z':
            return chr(((ord(ch)-ord('a'))*key)%26 +ord('a'))
    else:
        return ch

def encrypt_decrypt(text,key):
    cipher=""
    for ch in text:
        cipher+=multiplicative(ch,key)
    return cipher

key_2=int(input("Enter the key for multiplicative cipher: "))
inverse=mmi(key_2)
m_cipher=encrypt_decrypt(text,key_2)
m_text=encrypt_decrypt(m_cipher,inverse)
print(f"Encrypted text via multiplicative cipher is : {m_cipher}")
print(f"Decrypted text via multiplicative cipher is : {m_text}")
print()

#affine cipher
import math
def mmi(key):
    if math.gcd(key,26)!=1:
        raise ValueError("Invalid key bcz no mmi")
    return pow(key,-1,26)

def affine_encrypt(ch,a,b):
    if 'A'<=ch<='Z':
        return chr(((ord(ch)-ord('A'))*a+b)%26+ord('A'))
    elif 'a'<=ch<='z':
            return chr(((ord(ch)-ord('a'))*a+b)%26+ord('a'))
    else:
        return ch
    
def affine_decrypt(ch, inverse, b):
    if 'A' <= ch <= 'Z':
        return chr((((ord(ch)-ord('A'))-b) * inverse) % 26 + ord('A'))

    elif 'a' <= ch <= 'z':
        return chr((((ord(ch)-ord('a'))-b) * inverse) % 26 + ord('a'))

    else:
        return ch

def encrypt(text,a,b):
    cipher="" 
    for ch in text:
        cipher+=affine_encrypt(ch,a,b)
    return cipher
def decrypt(text, a, b):
    inverse = mmi(a)
    plain = ""
    for ch in text:
        plain += affine_decrypt(ch, inverse, b)
    return plain

a=int(input("Enter the key_1 for affine encryption: "))
b=int(input("Enter the key_2 for affine encryption: "))
cipher=encrypt(text,a,b)
plain=decrypt(cipher,a,b)
print(f"Encrypted text via affine cipher is : {cipher}")
print(f"Decrypted text via affine cipher is : {plain}")
print()

