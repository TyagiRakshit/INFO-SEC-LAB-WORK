
# ============================================================
# LAB 6 - CODE 1
# ELGAMAL AND SCHNORR DIGITAL SIGNATURES
# ============================================================
#
# AIM:
# To generate and verify digital signatures using
# ElGamal and Schnorr algorithms.
#
# WHAT IS A DIGITAL SIGNATURE?
#
# A digital signature helps us verify:
#
# 1. AUTHENTICITY - Was the message signed by the owner
#                   of the private key?
#
# 2. INTEGRITY    - Has the signed message been modified?
#
# IMPORTANT:
#
# PRIVATE KEY -> Used to generate a signature.
# PUBLIC KEY  -> Used to verify a signature.
#
# Both algorithms use modular arithmetic.
#
# The % operator gives the remainder after division.
#
# Example:
# 17 % 5 = 2
#
# ============================================================


# Import required libraries

import hashlib    # Used to calculate SHA-256 hashes
import random     # Used to generate random numbers

# Provides functions for generating prime numbers
# and calculating GCD (Greatest Common Divisor)
from Crypto.Util import number


# ============================================================
# PART 1: GENERATE COMMON PARAMETERS
# ============================================================

def generate_parameters():

    # Generate a random 512-bit prime number.
    #
    # A prime number is divisible only by 1 and itself.
    #
    # We use a prime number because ElGamal and Schnorr
    # involve modular arithmetic.

    p = number.getPrime(512)

    # Choose a random number g between 2 and p-2.
    #
    # g is the base used in modular exponentiation.
    #
    # Example:
    # pow(g, x, p) means (g ** x) % p
    #
    # NOTE:
    # This simplified lab code chooses a random base.
    # It does not verify that g is a generator of a
    # subgroup with the required order.

    g = random.randint(2, p - 2)

    # Return the prime number and base
    return p, g


# ============================================================
# PART 2: ELGAMAL DIGITAL SIGNATURE
# ============================================================

def elgamal_sign_verify(message, p, g):

    # --------------------------------------------------------
    # STEP 1: GENERATE PRIVATE AND PUBLIC KEYS
    # --------------------------------------------------------

    # Choose a random private key x.
    #
    # The private key must be kept secret.

    x = random.randint(2, p - 2)

    # Calculate the public key y.
    #
    # Formula:
    # y = (g ** x) % p
    #
    # pow(g, x, p) efficiently calculates this.

    y = pow(g, x, p)


    # --------------------------------------------------------
    # STEP 2: HASH THE MESSAGE
    # --------------------------------------------------------

    # Convert the message into bytes.
    #
    # Example:
    # "HELLO" -> b'HELLO'

    message_bytes = message.encode("utf-8")

    # Calculate SHA-256 hash of the message.
    #
    # hexdigest() returns the hash in hexadecimal.

    hash_hex = hashlib.sha256(message_bytes).hexdigest()

    # Convert the hexadecimal hash into an integer.
    #
    # int(value, 16) converts hexadecimal to decimal.
    #
    # We take modulo (p-1) because ElGamal signature
    # calculations are performed modulo (p-1).

    message_hash = int(hash_hex, 16) % (p - 1)


    # --------------------------------------------------------
    # STEP 3: GENERATE A TEMPORARY KEY k
    # --------------------------------------------------------

    # k is a temporary random number used for signing.
    #
    # We need:
    #
    # GCD(k, p-1) = 1
    #
    # This ensures that k has a modular inverse
    # modulo (p-1).

    while True:

        # Choose a random temporary key
        k = random.randint(2, p - 2)

        # Check whether k and (p-1) are coprime.
        #
        # Coprime means their GCD is 1.

        if number.GCD(k, p - 1) == 1:

            # Valid k found, exit the loop
            break


    # --------------------------------------------------------
    # STEP 4: GENERATE ELGAMAL SIGNATURE
    # --------------------------------------------------------

    # ElGamal signature contains TWO values:
    #
    # Signature = (r, s)
    #
    # First calculate:
    #
    # r = (g ** k) % p

    r = pow(g, k, p)

    # Calculate modular inverse of k.
    #
    # k_inverse is a number such that:
    #
    # (k * k_inverse) % (p-1) = 1
    #
    # pow(k, -1, p-1) calculates this inverse.

    k_inverse = pow(k, -1, p - 1)

    # Calculate the second signature component.
    #
    # Formula:
    #
    # s = k_inverse * (message_hash - x*r) % (p-1)

    s = (k_inverse * (message_hash - x * r)) % (p - 1)


    # --------------------------------------------------------
    # STEP 5: VERIFY ELGAMAL SIGNATURE
    # --------------------------------------------------------

    # Verification formula:
    #
    # g^hash mod p = (y^r * r^s) mod p
    #
    # Calculate the LEFT side.

    left = pow(g, message_hash, p)

    # Calculate the RIGHT side.

    right = (pow(y, r, p) * pow(r, s, p)) % p

    # If both sides are equal, the signature is valid.

    is_valid = (left == right)


    # Return the public key, signature and result
    return {
        "public_key": y,
        "signature": (r, s),
        "is_valid": is_valid
    }


# ============================================================
# PART 3: SCHNORR DIGITAL SIGNATURE
# ============================================================

def schnorr_sign_verify(message, p, g):

    # --------------------------------------------------------
    # STEP 1: DEFINE ORDER AND GENERATE KEYS
    # --------------------------------------------------------

    # For this simplified example, we use p-1.
    #
    # In a standard Schnorr implementation, q is usually
    # a prime subgroup order, not simply p-1.

    q = p - 1

    # Generate private key x
    x = random.randint(2, q - 1)

    # Calculate public key y = g^x mod p
    y = pow(g, x, p)


    # --------------------------------------------------------
    # STEP 2: CREATE A COMMITMENT
    # --------------------------------------------------------

    # Choose a temporary random number r.
    #
    # This number must be fresh for each signature.

    r = random.randint(2, q - 1)

    # Calculate the commitment:
    #
    # commitment = g^r mod p

    commitment = pow(g, r, p)


    # --------------------------------------------------------
    # STEP 3: GENERATE CHALLENGE e
    # --------------------------------------------------------

    # Combine the commitment and message.
    #
    # Example:
    # commitment = 123
    # message = "HELLO"
    #
    # Combined input = "123HELLO"

    combined_data = f"{commitment}{message}".encode("utf-8")

    # Calculate SHA-256 hash of the combined data
    hash_hex = hashlib.sha256(combined_data).hexdigest()

    # Convert hash to integer and reduce modulo q
    e = int(hash_hex, 16) % q


    # --------------------------------------------------------
    # STEP 4: GENERATE SIGNATURE RESPONSE s
    # --------------------------------------------------------

    # Formula:
    #
    # s = (r + x*e) mod q
    #
    # The signature consists of:
    #
    # (e, s)

    s = (r + x * e) % q


    # --------------------------------------------------------
    # STEP 5: VERIFY SCHNORR SIGNATURE
    # --------------------------------------------------------

    # Reconstruct the original commitment.
    #
    # Formula:
    #
    # commitment' = (g^s * y^(-e)) mod p

    # Calculate modular inverse of public key y
    y_inverse = pow(y, -1, p)

    # Reconstruct the commitment
    new_commitment = (
        pow(g, s, p) * pow(y_inverse, e, p)
    ) % p


    # --------------------------------------------------------
    # STEP 6: RECOMPUTE CHALLENGE
    # --------------------------------------------------------

    # Combine reconstructed commitment with message
    new_data = f"{new_commitment}{message}".encode("utf-8")

    # Calculate hash again
    new_hash_hex = hashlib.sha256(new_data).hexdigest()

    # Calculate the new challenge e'
    new_e = int(new_hash_hex, 16) % q

    # Compare original challenge with recomputed challenge
    #
    # If e == new_e, signature verification succeeds.

    is_valid = (e == new_e)


    # Return the results
    return {
        "public_key": y,
        "signature": (e, s),
        "is_valid": is_valid
    }


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    # Take message from user
    message = input("Enter a message to sign: ")

    print("\nDIGITAL SIGNATURE EXPERIMENT")
    print("Message:", message)

    # Generate common parameters p and g
    p, g = generate_parameters()

    print("\nPrime Number (p):", p)
    print("Base (g):", g)


    # --------------------------------------------------------
    # RUN ELGAMAL
    # --------------------------------------------------------

    elgamal_result = elgamal_sign_verify(message, p, g)

    print("\nELGAMAL DIGITAL SIGNATURE")

    print("Public Key:", elgamal_result["public_key"])
    print("Signature (r, s):", elgamal_result["signature"])

    if elgamal_result["is_valid"]:
        print("Verification: SUCCESS")
    else:
        print("Verification: FAILED")


    # --------------------------------------------------------
    # RUN SCHNORR
    # --------------------------------------------------------

    schnorr_result = schnorr_sign_verify(message, p, g)

    print("\nSCHNORR DIGITAL SIGNATURE")

    print("Public Key:", schnorr_result["public_key"])
    print("Signature (e, s):", schnorr_result["signature"])

    if schnorr_result["is_valid"]:
        print("Verification: SUCCESS")
    else:
        print("Verification: FAILED")
