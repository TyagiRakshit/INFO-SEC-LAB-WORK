
# ============================================================
# LAB 6 - CODE 2
# DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================
#
# AIM:
# To demonstrate how two users (Alice and Bob) can
# generate the SAME shared secret using Diffie-Hellman.
#
# WHAT IS DIFFIE-HELLMAN?
#
# Diffie-Hellman is a KEY EXCHANGE algorithm.
#
# It allows two users to generate a common secret
# without directly sending that secret over the network.
#
# IMPORTANT:
#
# Private keys are NOT exchanged.
# Only public keys are exchanged.
#
# ALGORITHM:
#
# 1. Generate a prime number p and base g.
# 2. Alice generates private key a.
# 3. Bob generates private key b.
# 4. Alice calculates public key A = g^a mod p.
# 5. Bob calculates public key B = g^b mod p.
# 6. Alice calculates shared secret = B^a mod p.
# 7. Bob calculates shared secret = A^b mod p.
# 8. Both should obtain the same secret.
# 9. Apply SHA-256 to derive a 256-bit key.
#
# ============================================================


# Import required libraries

import hashlib    # Used for SHA-256 hashing
import random     # Used to generate random numbers

# Used to generate large prime numbers
from Crypto.Util import number


# ============================================================
# STEP 1: GENERATE DIFFIE-HELLMAN PARAMETERS
# ============================================================

def generate_parameters():

    # Generate a random 512-bit prime number.
    #
    # This number will be used by both Alice and Bob.

    p = number.getPrime(512)

    # Choose a random base g.
    #
    # Both Alice and Bob must use the SAME p and g.
    #
    # NOTE:
    # This simplified code does not verify that g has
    # the required group order for secure DH.

    g = random.randint(2, p - 2)

    # Return the public parameters
    return p, g


# ============================================================
# STEP 2: PERFORM DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================

def diffie_hellman(p, g):

    # --------------------------------------------------------
    # ALICE: GENERATE PRIVATE AND PUBLIC KEYS
    # --------------------------------------------------------

    # Alice chooses a random private key a.
    #
    # This value is kept secret.

    alice_private = random.randint(2, p - 2)

    # Alice calculates her public key.
    #
    # Formula:
    # A = (g ** a) % p
    #
    # pow(g, a, p) performs modular exponentiation.

    alice_public = pow(g, alice_private, p)


    # --------------------------------------------------------
    # BOB: GENERATE PRIVATE AND PUBLIC KEYS
    # --------------------------------------------------------

    # Bob chooses his own private key b.
    #
    # Alice does not know Bob's private key.

    bob_private = random.randint(2, p - 2)

    # Bob calculates his public key.
    #
    # Formula:
    # B = (g ** b) % p

    bob_public = pow(g, bob_private, p)


    # --------------------------------------------------------
    # STEP 3: EXCHANGE PUBLIC KEYS
    # --------------------------------------------------------

    # Alice shares alice_public with Bob.
    # Bob shares bob_public with Alice.
    #
    # Private keys are NEVER shared.
    #
    # This program simulates the exchange.
    # It does not actually use network sockets.


    # --------------------------------------------------------
    # STEP 4: ALICE CALCULATES SHARED SECRET
    # --------------------------------------------------------

    # Alice uses:
    #
    # 1. Bob's PUBLIC key
    # 2. Her own PRIVATE key
    #
    # Formula:
    # Alice Secret = B^a mod p

    alice_secret = pow(
        bob_public,
        alice_private,
        p
    )


    # --------------------------------------------------------
    # STEP 5: BOB CALCULATES SHARED SECRET
    # --------------------------------------------------------

    # Bob uses:
    #
    # 1. Alice's PUBLIC key
    # 2. His own PRIVATE key
    #
    # Formula:
    # Bob Secret = A^b mod p

    bob_secret = pow(
        alice_public,
        bob_private,
        p
    )


    # --------------------------------------------------------
    # STEP 6: DERIVE A 256-BIT KEY USING SHA-256
    # --------------------------------------------------------

    # The shared secret is currently an integer.
    #
    # We apply SHA-256 to derive a fixed-size 256-bit value.
    #
    # First:
    # str(secret) converts integer to string.
    #
    # Second:
    # encode() converts string to bytes.
    #
    # Third:
    # sha256() calculates the hash.
    #
    # Finally:
    # hexdigest() displays the hash in hexadecimal.
    #
    # NOTE:
    # This reproduces the lab's simplified derivation.
    # Real applications should use a proper KDF like HKDF.

    alice_key = hashlib.sha256(
        str(alice_secret).encode("utf-8")
    ).hexdigest()

    bob_key = hashlib.sha256(
        str(bob_secret).encode("utf-8")
    ).hexdigest()


    # --------------------------------------------------------
    # STEP 7: VERIFY SHARED SECRET
    # --------------------------------------------------------

    # Check whether both users generated:
    #
    # 1. The same raw shared secret.
    # 2. The same SHA-256 derived key.
    #
    # Both conditions should be True.

    is_valid = (
        alice_secret == bob_secret
        and alice_key == bob_key
    )


    # Return all important results
    return {
        "alice_public": alice_public,
        "bob_public": bob_public,
        "alice_key": alice_key,
        "bob_key": bob_key,
        "is_valid": is_valid
    }


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    print("DIFFIE-HELLMAN KEY EXCHANGE")

    # Generate common parameters
    p, g = generate_parameters()

    print("\nPrime Number (p):", p)
    print("Base (g):", g)


    # --------------------------------------------------------
    # PERFORM KEY EXCHANGE
    # --------------------------------------------------------

    result = diffie_hellman(p, g)


    # Display the public keys
    print("\nPUBLIC KEYS")

    print("Alice Public Key:", result["alice_public"])
    print("Bob Public Key:", result["bob_public"])


    # Display derived symmetric keys
    print("\nDERIVED KEYS")

    print("Alice Key:", result["alice_key"])
    print("Bob Key:", result["bob_key"])


    # Verify that both keys match
    print("\nVERIFICATION")

    if result["is_valid"]:
        print("SUCCESS: Both users generated the same key.")
    else:
        print("FAILED: Keys do not match.")
