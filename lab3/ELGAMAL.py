# ============================================================
# ELGAMAL - LAB EXAM VERSION
# ============================================================

import random


# ------------------------------------------------------------
# MODULAR INVERSE
# ------------------------------------------------------------

def mod_inverse(a, p):
    return pow(a, -1, p)


# ------------------------------------------------------------
# KEY GENERATION
#
# y = g^x mod p
#
# Public Key  = (p, g, y)
# Private Key = x
# ------------------------------------------------------------

def generate_keys(p, g, x):

    y = pow(g, x, p)

    return (p, g, y), x


# ------------------------------------------------------------
# ENCRYPT ONE NUMBER
#
# c1 = g^k mod p
# s  = y^k mod p
# c2 = m*s mod p
#
# IMPORTANT:
# k is random and should change for every encryption.
# ------------------------------------------------------------

def encrypt(m, public_key):

    p, g, y = public_key

    if m >= p:
        raise ValueError("Message number must be smaller than p")

    k = random.randint(1, p - 2)

    c1 = pow(g, k, p)

    s = pow(y, k, p)

    c2 = (m * s) % p

    return c1, c2


# ------------------------------------------------------------
# DECRYPT ONE NUMBER
#
# s = c1^x mod p
# m = c2 * inverse(s) mod p
# ------------------------------------------------------------

def decrypt(ciphertext, private_key, p):

    c1, c2 = ciphertext

    x = private_key

    s = pow(c1, x, p)

    s_inverse = mod_inverse(s, p)

    m = (c2 * s_inverse) % p

    return m


# ------------------------------------------------------------
# ENCRYPT TEXT
# ------------------------------------------------------------

def encrypt_text(text, public_key):

    ciphertext = []

    for char in text:

        m = ord(char)

        ciphertext.append(
            encrypt(m, public_key)
        )

    return ciphertext


# ------------------------------------------------------------
# DECRYPT TEXT
# ------------------------------------------------------------

def decrypt_text(ciphertext, private_key, p):

    text = ""

    for block in ciphertext:

        m = decrypt(block, private_key, p)

        text += chr(m)

    return text


# ============================================================
# MAIN
# ============================================================

print("========== ELGAMAL ==========")

# ------------------------------------------------------------
# VARIATION 1:
# Question asks you to GENERATE keys
# ------------------------------------------------------------

p = int(input("Enter prime p: "))
g = int(input("Enter generator g: "))
x = int(input("Enter private key x: "))

public_key, private_key = generate_keys(p, g, x)

print("\nPublic Key :", public_key)
print("Private Key:", private_key)


# ------------------------------------------------------------
# VARIATION 2:
# Question ALREADY GIVES public/private keys
#
# Example from the lab:
#
# p = 7919
# g = 2
# y = 6465
# x = 2999
#
# Then DON'T generate new keys.
#
# Simply use:
#
# public_key = (7919, 2, 6465)
# private_key = 2999
# ------------------------------------------------------------


# ------------------------------------------------------------
# VARIATION 3:
# Different real-world message
#
# Examples:
#
# "Asymmetric Algorithms"
# "Confidential Data"
# "Patient Records"
# "Bank Transaction"
#
# The ElGamal functions do NOT change.
# Only the message changes.
# ------------------------------------------------------------

message = input("Enter message: ")


# ------------------------------------------------------------
# ENCRYPT
# ------------------------------------------------------------

ciphertext = encrypt_text(message, public_key)


# ------------------------------------------------------------
# DECRYPT
# ------------------------------------------------------------

decrypted = decrypt_text(
    ciphertext,
    private_key,
    p
)


# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

print("\nCiphertext:", ciphertext)

print("Decrypted :", decrypted)


# ------------------------------------------------------------
# VARIATION 4:
# Question asks you to VERIFY the original message.
# ------------------------------------------------------------

if message == decrypted:
    print("Verification: SUCCESS")
else:
    print("Verification: FAILED")
