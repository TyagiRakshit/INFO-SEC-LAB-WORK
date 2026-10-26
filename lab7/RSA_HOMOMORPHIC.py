
# ============================================================
# LAB 7 - CODE 2
# RSA HOMOMORPHIC MULTIPLICATION
# ============================================================
#
# AIM:
# To encrypt two integers using RSA, multiply the
# encrypted values, decrypt the result and verify
# that it equals the product of the original numbers.
#
# WHAT IS RSA?
#
# RSA is an asymmetric cryptographic algorithm.
#
# It uses TWO keys:
#
# PUBLIC KEY  -> Used for encryption
# PRIVATE KEY -> Used for decryption
#
# WHAT IS HOMOMORPHIC MULTIPLICATION?
#
# It allows us to multiply encrypted numbers
# without decrypting them first.
#
# IMPORTANT PROPERTY OF TEXTBOOK RSA:
#
# E(a) * E(b) mod n = E(a * b)
#
# This means:
#
# Multiplication of ciphertexts
#           =
# Multiplication of plaintexts
#
# EXAMPLE:
#
# Original numbers: 7 and 3
#
# Encrypt 7 -> C1
# Encrypt 3 -> C2
#
# Multiply:
# (C1 * C2) mod n
#
# Decrypt result -> 21
#
# NOTE:
# This demonstrates textbook RSA.
# Real secure RSA encryption uses padding such as OAEP,
# which does not have this simple homomorphic property.
#
# ============================================================


# Import required library

# Used to generate large prime numbers
from Crypto.Util import number

import math   # Used to calculate GCD


# ============================================================
# STEP 1: GENERATE RSA PUBLIC AND PRIVATE KEYS
# ============================================================

def generate_rsa_keys():

    # Generate two random 256-bit prime numbers.
    #
    # Example of small primes: 3, 5, 7, 11
    #
    # We use large primes for the lab demonstration.

    p = number.getPrime(256)
    q = number.getPrime(256)

    # Ensure p and q are different
    while p == q:
        q = number.getPrime(256)


    # --------------------------------------------------------
    # CALCULATE n
    # --------------------------------------------------------

    # Formula:
    # n = p * q
    #
    # n is called the RSA modulus.

    n = p * q


    # --------------------------------------------------------
    # CALCULATE PHI(n)
    # --------------------------------------------------------

    # Euler's totient for n = p*q:
    #
    # phi(n) = (p-1) * (q-1)

    phi = (p - 1) * (q - 1)


    # --------------------------------------------------------
    # CHOOSE PUBLIC EXPONENT e
    # --------------------------------------------------------

    # 65537 is a commonly used RSA public exponent.

    e = 65537

    # RSA requires:
    #
    # GCD(e, phi) = 1
    #
    # Otherwise, the modular inverse does not exist.
    #
    # If the condition fails, generate new keys.

    while math.gcd(e, phi) != 1:

        p = number.getPrime(256)
        q = number.getPrime(256)

        while p == q:
            q = number.getPrime(256)

        n = p * q
        phi = (p - 1) * (q - 1)


    # --------------------------------------------------------
    # CALCULATE PRIVATE EXPONENT d
    # --------------------------------------------------------

    # Formula:
    #
    # d = inverse(e) mod phi
    #
    # This means:
    #
    # (e * d) % phi = 1
    #
    # pow(e, -1, phi) calculates the modular inverse.

    d = pow(e, -1, phi)


    # --------------------------------------------------------
    # RETURN THE KEYS
    # --------------------------------------------------------

    # Public key = (e, n)
    # Private key = (d, n)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


# ============================================================
# STEP 2: RSA ENCRYPTION
# ============================================================

def rsa_encrypt(public_key, message):

    # Extract public exponent and modulus
    e, n = public_key

    # RSA encryption formula:
    #
    # C = m^e mod n
    #
    # m = Original message
    # e = Public exponent
    # n = RSA modulus
    #
    # pow(message, e, n) calculates this efficiently.

    ciphertext = pow(message, e, n)

    # Return encrypted value
    return ciphertext


# ============================================================
# STEP 3: RSA DECRYPTION
# ============================================================

def rsa_decrypt(private_key, ciphertext):

    # Extract private exponent and modulus
    d, n = private_key

    # RSA decryption formula:
    #
    # m = C^d mod n
    #
    # d = Private exponent
    # C = Ciphertext
    # n = RSA modulus

    message = pow(ciphertext, d, n)

    # Return decrypted number
    return message


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    print("RSA HOMOMORPHIC MULTIPLICATION")


    # --------------------------------------------------------
    # STEP 1: GENERATE KEYS
    # --------------------------------------------------------

    # Generate public and private RSA keys

    public_key, private_key = generate_rsa_keys()

    # Extract public exponent and modulus
    e, n = public_key


    # --------------------------------------------------------
    # STEP 2: TAKE INPUT
    # --------------------------------------------------------

    # Take two integers from the user

    num1 = int(input("Enter first number: "))
    num2 = int(input("Enter second number: "))

    # Calculate expected product normally.
    #
    # This is only used for verification.

    expected_product = num1 * num2

    # This lab demonstration expects nonnegative values
    # whose product is smaller than n.

    if num1 < 0 or num2 < 0 or expected_product >= n:
        print("Enter nonnegative numbers with product less than n.")
        raise SystemExit

    print("\nExpected Product:", expected_product)


    # --------------------------------------------------------
    # STEP 3: ENCRYPT BOTH NUMBERS
    # --------------------------------------------------------

    # Encrypt first number using RSA public key

    c1 = rsa_encrypt(public_key, num1)

    # Encrypt second number using RSA public key

    c2 = rsa_encrypt(public_key, num2)

    print("\nEncrypted First Number:", c1)
    print("Encrypted Second Number:", c2)


    # --------------------------------------------------------
    # STEP 4: HOMOMORPHIC MULTIPLICATION
    # --------------------------------------------------------

    # IMPORTANT:
    #
    # We multiply both encrypted values.
    #
    # Formula:
    #
    # Encrypted Product = (C1 * C2) mod n
    #
    # This produces an encryption of the product.
    #
    # We do NOT decrypt C1 or C2 before multiplying.

    encrypted_product = (c1 * c2) % n

    print("\nEncrypted Product:", encrypted_product)


    # --------------------------------------------------------
    # STEP 5: DECRYPT THE RESULT
    # --------------------------------------------------------

    # Decrypt the encrypted product using private key.

    decrypted_product = rsa_decrypt(
        private_key,
        encrypted_product
    )

    print("\nDecrypted Product:", decrypted_product)


    # --------------------------------------------------------
    # STEP 6: VERIFY THE RESULT
    # --------------------------------------------------------

    # Compare the decrypted product with normal
    # multiplication of the original numbers.

    if decrypted_product == expected_product:
        print("SUCCESS: Homomorphic multiplication verified!")
    else:
        print("FAILED: Results do not match!")
