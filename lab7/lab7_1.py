'''Implement the Paillier encryption scheme in Python. Encrypt two integers (e.g., 15 and 25)
using your implementation of the Paillier encryption scheme. Print the ciphertexts. Perform
an addition operation on the encrypted integers without decrypting them. Print the result of
the addition in encrypted form. Decrypt the result of the addition and verify that it matches
the sum of the original integers'''
import math
import random
from Crypto.Util import number


# 1. Key Generation (Dynamic Primes)
def generate_keys(bits=512):
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    n = p * q
    n_sq = n * n
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    g = n + 1
    # Compute mu = (L(g^lam mod n^2))^-1 mod n
    u = pow(g, lam, n_sq)
    l_val = (u - 1) // n
    mu = pow(l_val, -1, n)
    # Public key: (n, n_sq, g), Private key: (lam, mu)
    return (n, n_sq, g), (lam, mu)


# 2. Encryption
def encrypt(pub_key, plaintext):
    n, n_sq, g = pub_key
    # Choose random blinding factor r coprime to n
    while True:
        r = random.randint(1, n - 1)
        if math.gcd(r, n) == 1:
            break

    # c = (g^m * r^n) mod n^2
    term1 = pow(g, plaintext, n_sq)
    term2 = pow(r, n, n_sq)
    return (term1 * term2) % n_sq


# 3. Decryption
def decrypt(pub_key, priv_key, ciphertext):
    n, n_sq, _ = pub_key
    lam, mu = priv_key
    # m = L(c^lam mod n^2) * mu mod n
    u = pow(ciphertext, lam, n_sq)
    l_val = (u - 1) // n
    return (l_val * mu) % n


# --- Main Experiment ---
if __name__ == "__main__":
    # FIX: changed bit_length=512 to bits=512
    pub_key, priv_key = generate_keys(bits=512)
    n, n_sq, _ = pub_key

    # Values to test
    val1 = int(input("Enter the first integer: "))
    val2 = int(input("Enter the second integer: "))
    expected_sum = val1 + val2
    print(f"Adding numbers: {val1} + {val2} = {expected_sum}\n")

    # Step 1: Encrypt
    c1 = encrypt(pub_key, val1)
    c2 = encrypt(pub_key, val2)

    print(f"Ciphertext for {val1}:")
    print(f"{c1}\n")

    print(f"Ciphertext for {val2}:")
    print(f"{c2}\n")

    # Step 2: Add ciphertexts (Multiply them together)
    c_sum = (c1 * c2) % n_sq
    print(f"Resulting Encrypted Sum:\n{c_sum}\n")

    # Step 3: Decrypt
    decrypted_sum = decrypt(pub_key, priv_key, c_sum)
    print(f"Decrypted Sum Value: {decrypted_sum}")

    # Check
    if decrypted_sum == expected_sum:
        print("Success!")
    else:
        print("Failure.")