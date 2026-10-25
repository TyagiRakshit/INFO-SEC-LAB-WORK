# ============================================================
# RSA ENCRYPTION AND DECRYPTION
# From First Principles - Standard Python Only
#
# RSA:
#   Public Key  = (n, e)
#   Private Key = (n, d)
#
# Encryption:
#   C = M^e mod n
#
# Decryption:
#   M = C^d mod n
#
# ============================================================

import math


# ============================================================
# 1. EXTENDED EUCLIDEAN ALGORITHM
# ============================================================
# Used to find the modular inverse of e.
#
# We need:
#
#       e * d ≡ 1 (mod phi)
#
# Therefore:
#
#       d = inverse of e modulo phi
#
# ============================================================

def egcd(a, b):

    if b == 0:
        return a, 1, 0

    gcd, x1, y1 = egcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return gcd, x, y


# ============================================================
# 2. MODULAR INVERSE
# ============================================================
# Finds d such that:
#
#       (e * d) % phi = 1
#
# This gives the RSA private exponent d.
# ============================================================

def mod_inverse(e, phi):

    gcd, x, _ = egcd(e, phi)

    if gcd != 1:
        raise ValueError("e and phi must be coprime")

    return x % phi


# ============================================================
# 3. RSA KEY GENERATION
# ============================================================
#
# Input:
#       p, q = prime numbers
#       e    = public exponent
#
# Calculate:
#
#       n   = p * q
#       phi = (p-1) * (q-1)
#       d   = e^-1 mod phi
#
# Public Key:
#       (n, e)
#
# Private Key:
#       (n, d)
# ============================================================

def generate_keys(p, q, e):

    n = p * q

    phi = (p - 1) * (q - 1)

    # e must be relatively prime to phi
    if math.gcd(e, phi) != 1:
        raise ValueError("e and phi(n) must be coprime")

    d = mod_inverse(e, phi)

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


# ============================================================
# 4. RSA ENCRYPTION
# ============================================================
#
# For every character:
#
#       M = ASCII value of character
#
#       C = M^e mod n
#
# ============================================================

def encrypt(text, public_key):

    n, e = public_key

    ciphertext = []

    for char in text:

        # Convert character → number
        m = ord(char)

        # RSA requires M < n
        if m >= n:
            raise ValueError(
                "n is too small for this character. "
                "Choose larger p and q."
            )

        # C = M^e mod n
        c = pow(m, e, n)

        ciphertext.append(c)

    return ciphertext


# ============================================================
# 5. RSA DECRYPTION
# ============================================================
#
# For every ciphertext number:
#
#       M = C^d mod n
#
# Then convert number → character.
#
# ============================================================

def decrypt(ciphertext, private_key):

    n, d = private_key

    plaintext = ""

    for c in ciphertext:

        # M = C^d mod n
        m = pow(c, d, n)

        # Convert number → character
        plaintext += chr(m)

    return plaintext


# ============================================================
# MAIN PROGRAM
# ============================================================

print("========== RSA ==========")

# ------------------------------------------------------------
# SCENARIO VARIATION 1:
#
# If the question says:
# "Generate RSA keys..."
#
# Then take p, q and e and call generate_keys().
# ------------------------------------------------------------

p = int(input("Enter prime p: "))
q = int(input("Enter prime q: "))

# Common classroom choice:
# e = 65537
#
# BUT:
# For small p and q, 65537 may be larger than phi(n).
# In such lab questions, use a suitable e given by the
# question or choose a valid small value.
#
# Example:
# p = 5, q = 11
# phi = 40
# e = 3 works because gcd(3,40) = 1.

e = int(input("Enter e: "))

public_key, private_key = generate_keys(p, q, e)

print("\nPublic Key :", public_key)
print("Private Key:", private_key)


# ------------------------------------------------------------
# SCENARIO VARIATION 2:
#
# If the question gives:
#
#       n, e, d
#
# directly,
#
# DO NOT generate new keys.
#
# Instead use:
#
# public_key = (n, e)
# private_key = (n, d)
#
# Example:
#
# n = 323
# e = 5
# d = 173
#
# public_key = (323, 5)
# private_key = (323, 173)
# ------------------------------------------------------------


# ------------------------------------------------------------
# MESSAGE
#
# This is the ONLY part that normally changes when the
# real-world scenario changes.
#
# Example lab message:
# "Asymmetric Encryption"
#
# Other possible exam scenarios:
#
# "Bank Transaction"
# "Patient Record"
# "Secure File"
# "Transaction ID"
#
# The RSA encryption/decryption functions remain the same.
# ------------------------------------------------------------

message = input("Enter message: ")


# ------------------------------------------------------------
# ENCRYPT
# ------------------------------------------------------------

ciphertext = encrypt(message, public_key)


# ------------------------------------------------------------
# DECRYPT
# ------------------------------------------------------------

decrypted_message = decrypt(ciphertext, private_key)


# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

print("\n========== RESULT ==========")

print("Plaintext :", message)

print("Ciphertext:", ciphertext)

print("Decrypted :", decrypted_message)


# ------------------------------------------------------------
# VERIFY
#
# Useful when the question says:
# "Verify that the original message is recovered."
# ------------------------------------------------------------

if message == decrypted_message:
    print("Verification: SUCCESS")
else:
    print("Verification: FAILED")
