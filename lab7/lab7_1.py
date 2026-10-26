
# ============================================================
# LAB 7 - CODE 1
# PAILLIER HOMOMORPHIC ADDITION
# ============================================================
#
# AIM:
# To encrypt two integers using Paillier encryption,
# perform addition without decrypting them, and verify
# the result after decryption.
#
# WHAT IS HOMOMORPHIC ENCRYPTION?
#
# Homomorphic encryption allows us to perform certain
# mathematical operations directly on encrypted data.
#
# We do not need to decrypt the data before calculation.
#
# WHAT IS PAILLIER?
#
# Paillier is an asymmetric encryption algorithm.
# It supports ADDITIVE HOMOMORPHIC ENCRYPTION.
#
# IMPORTANT PROPERTY:
#
# E(a) * E(b) mod n^2 = E(a + b)
#
# This means:
#
# Multiplication of ciphertexts
#           =
# Addition of original plaintexts
#
# EXAMPLE:
#
# Original numbers: 15 and 25
#
# Step 1: Encrypt 15 -> C1
# Step 2: Encrypt 25 -> C2
# Step 3: Calculate (C1 * C2) mod n^2
# Step 4: Decrypt the result
#
# Final result = 40
#
# NOTE:
# Paillier arithmetic works modulo n.
# For this experiment, use small nonnegative integers
# whose sum is less than n.
#
# ============================================================


# Import required libraries

import math       # Used to calculate GCD and LCM
import secrets    # Generates secure random numbers

# Used to generate large prime numbers
from Crypto.Util import number


# ============================================================
# STEP 1: GENERATE PUBLIC AND PRIVATE KEYS
# ============================================================

def generate_keys():

    # Generate two random 256-bit prime numbers.
    #
    # A prime number is divisible only by 1 and itself.
    #
    # Example of small primes: 3, 5, 7, 11
    #
    # We use 256-bit primes so their product is
    # approximately 512 bits.
    #
    # NOTE: 512-bit keys are for lab demonstration only.
    # Real applications require larger secure parameters.

    p = number.getPrime(256)
    q = number.getPrime(256)

    # Make sure p and q are different.
    #
    # Paillier requires two distinct prime numbers.

    while p == q:
        q = number.getPrime(256)


    # --------------------------------------------------------
    # CALCULATE n AND n^2
    # --------------------------------------------------------

    # Formula:
    # n = p * q

    n = p * q

    # Calculate n squared.
    #
    # Paillier encryption calculations use modulo n^2.

    n_squared = n * n


    # --------------------------------------------------------
    # CALCULATE LAMBDA
    # --------------------------------------------------------

    # Lambda is calculated using:
    #
    # lambda = LCM(p-1, q-1)
    #
    # LCM means Least Common Multiple.
    #
    # Formula:
    #
    # LCM(a,b) = (a*b) / GCD(a,b)
    #
    # Example:
    # LCM(4,6) = 12

    lam = math.lcm(p - 1, q - 1)


    # --------------------------------------------------------
    # CALCULATE g
    # --------------------------------------------------------

    # Paillier uses a public parameter g.
    #
    # A common simple choice is:
    #
    # g = n + 1

    g = n + 1


    # --------------------------------------------------------
    # CALCULATE MU
    # --------------------------------------------------------

    # Mu is part of the private key.
    #
    # Formula:
    #
    # mu = inverse(L(g^lambda mod n^2)) mod n
    #
    # Where:
    #
    # L(u) = (u - 1) // n
    #
    # We first calculate g^lambda mod n^2.

    u = pow(g, lam, n_squared)

    # Apply the L function.
    #
    # // means integer division.

    L_value = (u - 1) // n

    # Calculate modular inverse.
    #
    # pow(a, -1, n) finds a number b such that:
    #
    # (a * b) % n = 1
    #
    # With g = n+1, L_value equals lambda mod n.
    # A valid key requires this inverse to exist.

    mu = pow(L_value, -1, n)


    # --------------------------------------------------------
    # RETURN THE KEYS
    # --------------------------------------------------------

    # Public key contains:
    # n, n^2 and g
    #
    # Private key contains:
    # lambda and mu

    public_key = (n, n_squared, g)
    private_key = (lam, mu)

    return public_key, private_key


# ============================================================
# STEP 2: ENCRYPT A NUMBER
# ============================================================

def encrypt(public_key, message):

    # Extract public key values.
    #
    # These values were returned by generate_keys().

    n, n_squared, g = public_key


    # --------------------------------------------------------
    # GENERATE RANDOM VALUE r
    # --------------------------------------------------------

    # Paillier uses a random number r during encryption.
    #
    # This makes encryption probabilistic.
    #
    # It means encrypting the same number twice can
    # produce different ciphertexts.
    #
    # We need:
    #
    # GCD(r, n) = 1
    #
    # This means r and n must be coprime.

    while True:

        # Generate a secure random integer from 1 to n-1

        r = secrets.randbelow(n - 1) + 1

        # Check whether r and n are coprime

        if math.gcd(r, n) == 1:
            break


    # --------------------------------------------------------
    # CALCULATE CIPHERTEXT
    # --------------------------------------------------------

    # Paillier encryption formula:
    #
    # C = (g^m * r^n) mod n^2
    #
    # Here:
    #
    # m = Original message
    # g = Public parameter
    # r = Random value
    # n = Public modulus
    #
    # pow(a, b, c) calculates (a^b) mod c.
    #
    # This is much more efficient than calculating
    # a^b first and then taking the remainder.

    # Calculate first part:
    # g^message mod n^2

    part1 = pow(g, message, n_squared)

    # Calculate second part:
    # r^n mod n^2

    part2 = pow(r, n, n_squared)

    # Multiply both parts and take modulo n^2

    ciphertext = (part1 * part2) % n_squared

    # Return the encrypted number
    return ciphertext


# ============================================================
# STEP 3: DECRYPT THE ENCRYPTED NUMBER
# ============================================================

def decrypt(public_key, private_key, ciphertext):

    # Extract public key values
    n, n_squared, g = public_key

    # Extract private key values
    lam, mu = private_key


    # --------------------------------------------------------
    # PAILLIER DECRYPTION FORMULA
    # --------------------------------------------------------

    # Formula:
    #
    # m = L(C^lambda mod n^2) * mu mod n
    #
    # Where:
    #
    # L(u) = (u - 1) // n
    #
    # STEP 1:
    # Calculate C^lambda mod n^2

    u = pow(ciphertext, lam, n_squared)

    # STEP 2:
    # Apply the L function

    L_value = (u - 1) // n

    # STEP 3:
    # Multiply by mu and take modulo n

    message = (L_value * mu) % n

    # Return the decrypted number
    return message


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    print("PAILLIER HOMOMORPHIC ADDITION")


    # --------------------------------------------------------
    # STEP 1: GENERATE KEYS
    # --------------------------------------------------------

    public_key, private_key = generate_keys()

    # Extract n and n^2 from the public key
    n, n_squared, g = public_key


    # --------------------------------------------------------
    # STEP 2: TAKE INPUT
    # --------------------------------------------------------

    # Take two integers from the user

    num1 = int(input("Enter first number: "))
    num2 = int(input("Enter second number: "))

    # Calculate expected result using normal addition.
    #
    # We use this only to verify the final result.

    expected_sum = num1 + num2

    # This demonstration uses nonnegative numbers
    # whose sum fits in the plaintext range.

    if num1 < 0 or num2 < 0 or expected_sum >= n:
        print("Enter nonnegative numbers with sum less than n.")
        raise SystemExit

    print("\nExpected Sum:", expected_sum)


    # --------------------------------------------------------
    # STEP 3: ENCRYPT BOTH NUMBERS
    # --------------------------------------------------------

    # Encrypt first number using public key

    c1 = encrypt(public_key, num1)

    # Encrypt second number using public key

    c2 = encrypt(public_key, num2)

    print("\nEncrypted First Number:", c1)
    print("Encrypted Second Number:", c2)


    # --------------------------------------------------------
    # STEP 4: HOMOMORPHIC ADDITION
    # --------------------------------------------------------

    # IMPORTANT:
    #
    # To ADD the original numbers, we MULTIPLY
    # their ciphertexts.
    #
    # Formula:
    #
    # Encrypted Sum = (C1 * C2) mod n^2
    #
    # We do NOT decrypt C1 or C2 here.

    encrypted_sum = (c1 * c2) % n_squared

    print("\nEncrypted Sum:", encrypted_sum)


    # --------------------------------------------------------
    # STEP 5: DECRYPT THE RESULT
    # --------------------------------------------------------

    # Decrypt only the final encrypted sum.

    decrypted_sum = decrypt(
        public_key,
        private_key,
        encrypted_sum
    )

    print("\nDecrypted Sum:", decrypted_sum)


    # --------------------------------------------------------
    # STEP 6: VERIFY THE RESULT
    # --------------------------------------------------------

    # Compare decrypted sum with normal addition.

    if decrypted_sum == expected_sum:
        print("SUCCESS: Homomorphic addition verified!")
    else:
        print("FAILED: Results do not match!")
