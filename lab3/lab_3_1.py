# RSA Encryption and Decryption from First Principles
# Encrypts text using Public Key (n, e) and Decrypts using Private Key (n, d)
# Standard library only (no external packages required)

import math


def egcd(a, b):
    """Extended Euclidean Algorithm to find greatest common divisor."""
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def mod_inverse(e, phi):
    """Calculates modular multiplicative inverse d = e^-1 mod phi."""
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist; 'e' and 'phi' must be coprime.")
    return x % phi


def generate_keypair(p, q, e=65537):
    """Generates RSA Public (n, e) and Private (n, d) keys from primes p and q."""
    if p == q:
        raise ValueError("Primes p and q cannot be equal.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        for candidate in range(3, phi, 2):
            if math.gcd(candidate, phi) == 1:
                e = candidate
                break

    d = mod_inverse(e, phi)
    return (n, e), (n, d), phi


def rsa_encrypt(plaintext, public_key):
    """Encrypts characters by converting each letter to ASCII and computing C = M^e mod n."""
    n, e = public_key
    ciphertext_blocks = []

    for char in plaintext:
        m = ord(char)
        if m >= n:
            raise ValueError(
                f"Character '{char}' ASCII ({m}) is larger than modulus n ({n}). Use larger prime numbers.")
        c = pow(m, e, n)
        ciphertext_blocks.append(c)

    return ciphertext_blocks


def rsa_decrypt(ciphertext_blocks, private_key):
    n, d = private_key
    decrypted_chars = []

    for c in ciphertext_blocks:
        m = pow(c, d, n)  # Efficient modular exponentiation: (c^d) % n
        decrypted_chars.append(chr(m))

    return "".join(decrypted_chars)




print("=== RSA Encryption / Decryption ===")

plaintext_input = input("Enter plain text: ")

p = int(input("Enter prime number p : "))
q = int(input("Enter prime number q : "))
e_input = input("Enter public exponent e: ")

e = int(e_input) if e_input.strip() else 65537

public_key, private_key, phi = generate_keypair(p, q, e)
n, e = public_key
_, d = private_key

cipher_blocks = rsa_encrypt(plaintext_input, public_key)

decrypted_text = rsa_decrypt(cipher_blocks, private_key)

print("\n--- RSA PARAMETERS & KEYS ---")
print(f"p                : {p}")
print(f"q                : {q}")
print(f"Modulus (n)      : {n}")
print(f"Totient phi(n)   : {phi}")
print(f"Public Key (n,e) : ({n}, {e})")
print(f"Private Key(n,d) : ({n}, {d})")

print("\n--- RESULTS ---")
print(f"Plaintext        : {plaintext_input}")
print(f"Ciphertext Array : {cipher_blocks}")
print(f"Decrypted Text   : {decrypted_text}")


