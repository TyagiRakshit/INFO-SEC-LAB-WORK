
# ============================================================
# INFORMATION SECURITY EXAM TOOLKIT
# FILE: asymmetric.py
#
# TOPICS:
# 1. RSA Hybrid Encryption
# 2. ECC / ECDH Hybrid Encryption
# 3. Diffie-Hellman Key Exchange
# 4. ElGamal Encryption and Homomorphic Multiplication
# 5. Rabin Cryptosystem
#
# LABS: 3, 4 AND 7
# ============================================================
#
# WHAT IS ASYMMETRIC CRYPTOGRAPHY?
#
# Asymmetric cryptography uses TWO related keys:
#
# PUBLIC KEY:
#   Can be shared with others.
#   Used for encryption or signature verification,
#   depending on the algorithm.
#
# PRIVATE KEY:
#   Must be kept secret.
#   Used for decryption or signing,
#   depending on the algorithm.
#
# IMPORTANT:
#
# RSA and ECC are often combined with AES or DES
# to encrypt large messages and files efficiently.
#
# This is called HYBRID ENCRYPTION.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT LIBRARIES
# ============================================================

# secrets:
# Generates cryptographically secure random values.

import secrets

# hashlib:
# Provides SHA-256 and other hash algorithms.

import hashlib

# number:
# Generates prime numbers for mathematical cryptography.

from Crypto.Util import number

# RSA:
# Used for RSA public/private keys.

from Crypto.PublicKey import RSA

# PKCS1_OAEP:
# Secure RSA encryption padding scheme.
#
# In this file, RSA wrapping is handled by crypto_tools.

from Crypto.Cipher import PKCS1_OAEP

from Crypto.Hash import SHA256


# Elliptic Curve Cryptography library.
#
# Used to generate ECC keys and perform ECDH.

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# Import reusable functions from crypto_tools.py.
#
# symmetric_encrypt:
# Encrypts data using AES, DES or 3DES.
#
# symmetric_decrypt:
# Decrypts symmetric ciphertext.
#
# rsa_wrap:
# Encrypts a symmetric key using RSA public key.
#
# rsa_unwrap:
# Decrypts the symmetric key using RSA private key.

from crypto_tools import (
    symmetric_encrypt,
    symmetric_decrypt,
    rsa_wrap,
    rsa_unwrap
)


# ============================================================
# PART 1: RSA HYBRID ENCRYPTION
# ============================================================
#
# WHAT IS HYBRID ENCRYPTION?
#
# Hybrid encryption combines:
#
# 1. SYMMETRIC ENCRYPTION:
#    AES or DES encrypts the actual message/file.
#
# 2. ASYMMETRIC ENCRYPTION:
#    RSA encrypts the symmetric encryption key.
#
# WHY DO WE COMBINE THEM?
#
# RSA is not suitable for directly encrypting large files.
#
# AES is efficient for large amounts of data.
#
# Therefore:
#
# AES encrypts the DATA.
# RSA encrypts the AES KEY.
#
# SENDER:
#
# Original Data
#      |
#      v
# Generate AES Key
#      |
#      v
# Encrypt Data using AES
#      |
#      v
# Encrypt AES Key using RSA Public Key
#      |
#      v
# Send Encrypted Data + Encrypted AES Key
#
# RECEIVER:
#
# RSA Private Key -> Recover AES Key
#                         |
#                         v
#                  Decrypt Data using AES
#
# ============================================================


def rsa_hybrid_encrypt(
    data,
    public_key,
    algorithm="AES",
    bits=256,
    mode="GCM"
):

    # PARAMETERS:
    #
    # data:
    #   Original message/file bytes.
    #
    # public_key:
    #   Receiver's RSA public key.
    #
    # algorithm:
    #   Symmetric encryption algorithm.
    #   Default = AES.
    #
    # bits:
    #   Symmetric key size.
    #   Default = 256 bits.
    #
    # mode:
    #   Encryption mode.
    #   Default = GCM.


    # --------------------------------------------------------
    # STEP 1: ENCRYPT DATA USING SYMMETRIC ENCRYPTION
    # --------------------------------------------------------

    # symmetric_encrypt() is defined in crypto_tools.py.
    #
    # It returns TWO values:
    #
    # envelope:
    #   Contains encrypted data and required metadata
    #   such as nonce/IV and authentication information.
    #
    # key:
    #   The symmetric encryption key.
    #
    # Example:
    #
    # algorithm = "AES"
    # bits = 256
    # mode = "GCM"
    #
    # This encrypts data using AES-256-GCM.

    envelope, key = symmetric_encrypt(
        data,
        algorithm,
        bits,
        mode
    )


    # --------------------------------------------------------
    # STEP 2: ENCRYPT SYMMETRIC KEY USING RSA
    # --------------------------------------------------------

    # rsa_wrap() encrypts the symmetric key
    # using the receiver's RSA public key.
    #
    # The encrypted key is called a wrapped key.
    #
    # Only the matching RSA private key can unwrap it.

    wrapped_key = rsa_wrap(public_key, key)


    # --------------------------------------------------------
    # STEP 3: RETURN ENCRYPTED PACKAGE
    # --------------------------------------------------------

    # A dictionary stores both components:
    #
    # payload:
    #   Encrypted message/file.
    #
    # wrapped_key:
    #   RSA-encrypted symmetric key.
    #
    # Both are needed for decryption.

    return {
        "payload": envelope,
        "wrapped_key": wrapped_key
    }


# ============================================================
# RSA HYBRID DECRYPTION
# ============================================================

def rsa_hybrid_decrypt(package, private_key):

    # package:
    #   Dictionary returned by rsa_hybrid_encrypt().
    #
    # private_key:
    #   Receiver's RSA private key.


    # --------------------------------------------------------
    # STEP 1: RECOVER SYMMETRIC KEY
    # --------------------------------------------------------

    # rsa_unwrap() uses RSA private key to decrypt
    # the wrapped symmetric key.

    key = rsa_unwrap(
        private_key,
        package["wrapped_key"]
    )


    # --------------------------------------------------------
    # STEP 2: DECRYPT ORIGINAL DATA
    # --------------------------------------------------------

    # Use the recovered symmetric key to decrypt
    # the encrypted payload.

    plaintext = symmetric_decrypt(
        package["payload"],
        key
    )

    return plaintext


# ============================================================
# PART 2: ELLIPTIC CURVE CRYPTOGRAPHY (ECC)
# ============================================================
#
# WHAT IS ECC?
#
# ECC stands for Elliptic Curve Cryptography.
#
# It uses mathematical operations on elliptic curves
# to generate public/private key pairs.
#
# ECC is commonly used for:
#
# 1. Key agreement (ECDH).
# 2. Digital signatures (ECDSA).
#
# In this program:
#
# ECC establishes a shared secret.
# HKDF converts the secret into an AES key.
# AES-GCM encrypts the actual data.
#
# IMPORTANT:
#
# ECC itself is NOT directly encrypting the file.
#
# ============================================================


def ecc_keypair():

    # Generate a private ECC key.
    #
    # SECP256R1 is a commonly used elliptic curve,
    # also known as P-256.
    #
    # The private key is a secret number.

    private = ec.generate_private_key(
        ec.SECP256R1()
    )

    # Calculate the corresponding public key.

    public = private.public_key()

    # Return both keys.
    #
    # Public key first, private key second.

    return public, private


# ============================================================
# ECC HYBRID ENCRYPTION
# ============================================================

def ecc_encrypt(data, receiver_public):

    # PARAMETERS:
    #
    # data:
    #   Original message/file bytes.
    #
    # receiver_public:
    #   Receiver's ECC public key.


    # --------------------------------------------------------
    # STEP 1: GENERATE TEMPORARY ECC KEY
    # --------------------------------------------------------

    # Ephemeral means temporary.
    #
    # The sender creates a fresh ECC private key
    # for this encryption operation.

    ephemeral = ec.generate_private_key(
        ec.SECP256R1()
    )


    # --------------------------------------------------------
    # STEP 2: PERFORM ECDH KEY AGREEMENT
    # --------------------------------------------------------

    # ECDH = Elliptic Curve Diffie-Hellman.
    #
    # Sender uses:
    #
    # Sender's temporary private key
    #                +
    # Receiver's public key
    #
    # This generates shared secret material.

    secret = ephemeral.exchange(
        ec.ECDH(),
        receiver_public
    )


    # --------------------------------------------------------
    # STEP 3: GENERATE RANDOM SALT
    # --------------------------------------------------------

    # Generate 16 random bytes.
    #
    # Salt is used during HKDF key derivation.

    salt = secrets.token_bytes(16)


    # --------------------------------------------------------
    # STEP 4: DERIVE AES KEY USING HKDF
    # --------------------------------------------------------

    # HKDF takes the shared secret and derives
    # a fixed-length cryptographic key.
    #
    # algorithm = SHA-256
    #
    # length = 32 bytes
    #
    # 32 bytes * 8 = 256 bits
    #
    # Therefore, we derive an AES-256 key.
    #
    # info:
    #   Application-specific context value.
    #
    # Both sender and receiver must use the
    # same salt and info during key derivation.

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"IS-LAB-ECDH-v1"
    ).derive(secret)


    # --------------------------------------------------------
    # STEP 5: ENCRYPT DATA USING AES-256-GCM
    # --------------------------------------------------------

    # We already derived the AES key.
    #
    # Pass it to symmetric_encrypt().
    #
    # Since the key is supplied, the helper should
    # use this key rather than generating another one.
    #
    # env contains the encrypted payload.

    env, _ = symmetric_encrypt(
        data,
        "AES",
        256,
        "GCM",
        key
    )


    # --------------------------------------------------------
    # STEP 6: EXPORT TEMPORARY PUBLIC KEY
    # --------------------------------------------------------

    # The receiver needs the sender's temporary
    # PUBLIC key to calculate the same shared secret.
    #
    # We do NOT share the temporary private key.

    from cryptography.hazmat.primitives import serialization

    ephemeral_public = ephemeral.public_key().public_bytes(

        # X962 is a standard format for ECC points.
        serialization.Encoding.X962,

        # UncompressedPoint stores both curve coordinates.
        serialization.PublicFormat.UncompressedPoint
    )


    # --------------------------------------------------------
    # STEP 7: CONVERT BINARY VALUES FOR STORAGE
    # --------------------------------------------------------

    # b64() converts bytes into Base64 text.
    #
    # This makes binary values easy to store in JSON.
    #
    # Base64 is an encoding, NOT encryption.

    from crypto_tools import b64


    # --------------------------------------------------------
    # STEP 8: RETURN ENCRYPTED PACKAGE
    # --------------------------------------------------------

    return {

        # Sender's temporary ECC public key
        "ephemeral_public": b64(ephemeral_public),

        # Salt needed for HKDF
        "salt": b64(salt),

        # AES encrypted data
        "payload": env
    }


# ============================================================
# ECC HYBRID DECRYPTION
# ============================================================

def ecc_decrypt(package, receiver_private):

    # Receiver uses:
    #
    # 1. Their ECC private key.
    # 2. Sender's temporary public key.
    # 3. HKDF salt.
    # 4. Encrypted AES payload.


    # --------------------------------------------------------
    # STEP 1: DECODE TEMPORARY PUBLIC KEY
    # --------------------------------------------------------

    # unb64() converts Base64 text back into bytes.

    from crypto_tools import unb64

    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        unb64(package["ephemeral_public"])
    )


    # --------------------------------------------------------
    # STEP 2: CALCULATE SAME SHARED SECRET
    # --------------------------------------------------------

    # Receiver uses:
    #
    # Receiver's private key
    #           +
    # Sender's temporary public key
    #
    # ECDH mathematically produces the same secret
    # as the sender calculated.

    secret = receiver_private.exchange(
        ec.ECDH(),
        ephemeral_public
    )


    # --------------------------------------------------------
    # STEP 3: DERIVE THE SAME AES KEY
    # --------------------------------------------------------

    # Use the SAME:
    #
    # - Shared secret
    # - Salt
    # - SHA-256
    # - HKDF info
    # - Output length
    #
    # This produces the same 256-bit AES key.

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=unb64(package["salt"]),
        info=b"IS-LAB-ECDH-v1"
    ).derive(secret)


    # --------------------------------------------------------
    # STEP 4: DECRYPT AES PAYLOAD
    # --------------------------------------------------------

    return symmetric_decrypt(
        package["payload"],
        key
    )


# ============================================================
# PART 3: DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================
#
# WHAT IS DIFFIE-HELLMAN?
#
# Diffie-Hellman allows two users to establish
# a common shared secret without sending the secret.
#
# Alice and Bob publicly agree on:
#
# p = Prime modulus
# g = Base
#
# Alice:
# Private key = a
# Public key  = A = g^a mod p
#
# Bob:
# Private key = b
# Public key  = B = g^b mod p
#
# Alice calculates:
#
# K = B^a mod p
#
# Bob calculates:
#
# K = A^b mod p
#
# Both obtain:
#
# K = g^(ab) mod p
#
# ============================================================


def dh_demo(bits=2048):

    # --------------------------------------------------------
    # STEP 1: GENERATE PUBLIC PARAMETERS
    # --------------------------------------------------------

    # Generate a random prime of the requested bit size.
    #
    # NOTE:
    # Real DH should use validated group parameters.
    # This function is an educational demonstration.

    p = number.getPrime(bits)

    # Choose base g = 2.
    #
    # The code does not verify its exact group order.

    g = 2


    # --------------------------------------------------------
    # STEP 2: GENERATE PRIVATE KEYS
    # --------------------------------------------------------

    # Alice chooses private key a.
    #
    # secrets.randbelow(p-3) returns a random integer
    # from 0 to p-4.
    #
    # Adding 2 gives a value from 2 to p-2.

    a = secrets.randbelow(p - 3) + 2

    # Bob chooses private key b.

    b = secrets.randbelow(p - 3) + 2


    # --------------------------------------------------------
    # STEP 3: CALCULATE PUBLIC KEYS
    # --------------------------------------------------------

    # Alice's public key:
    # A = g^a mod p

    A = pow(g, a, p)

    # Bob's public key:
    # B = g^b mod p

    B = pow(g, b, p)


    # --------------------------------------------------------
    # STEP 4: CALCULATE SHARED SECRETS
    # --------------------------------------------------------

    # Alice uses Bob's public key and her private key.

    left = pow(B, a, p)

    # Bob uses Alice's public key and his private key.

    right = pow(A, b, p)


    # --------------------------------------------------------
    # STEP 5: VERIFY THE SHARED SECRET
    # --------------------------------------------------------

    # If both calculations are correct:
    #
    # left == right
    #
    # This should be True.

    is_match = (left == right)


    # --------------------------------------------------------
    # STEP 6: CONVERT SHARED SECRET INTO BYTES
    # --------------------------------------------------------

    # The shared secret is an integer.
    #
    # SHA-256 requires bytes.
    #
    # bit_length() gives the number of bits required
    # to represent the integer.
    #
    # (bit_length + 7) // 8 gives the number of bytes.
    #
    # "big" specifies big-endian byte order.

    secret_bytes = left.to_bytes(
        (left.bit_length() + 7) // 8,
        "big"
    )


    # --------------------------------------------------------
    # STEP 7: DERIVE A 256-BIT HASH
    # --------------------------------------------------------

    # SHA-256 generates a 256-bit digest.
    #
    # hexdigest() returns 64 hexadecimal characters.
    #
    # This is a simplified derivation for demonstration.
    # Real key exchange protocols should use a proper KDF
    # such as HKDF.

    derived_key = hashlib.sha256(
        secret_bytes
    ).hexdigest()


    # --------------------------------------------------------
    # STEP 8: RETURN RESULTS
    # --------------------------------------------------------

    return {
        "p": p,
        "g": g,
        "alice_public": A,
        "bob_public": B,
        "match": is_match,
        "derived_key": derived_key
    }


# ============================================================
# PART 4: ELGAMAL ENCRYPTION
# ============================================================
#
# WHAT IS ELGAMAL?
#
# ElGamal is an asymmetric encryption algorithm.
#
# It uses modular exponentiation.
#
# PUBLIC KEY:
# (p, g, y)
#
# PRIVATE KEY:
# x
#
# Where:
#
# y = g^x mod p
#
# ENCRYPTION:
#
# c1 = g^k mod p
# c2 = m * y^k mod p
#
# Ciphertext = (c1, c2)
#
# DECRYPTION:
#
# shared = c1^x mod p
#
# m = c2 * inverse(shared) mod p
#
# IMPORTANT:
# ElGamal also supports homomorphic multiplication.
#
# ============================================================


def elgamal_keys(bits=1024):

    # Generate a random prime p.
    #
    # NOTE:
    # 1024-bit parameters and unvalidated group selection
    # are not suitable for modern production security.

    p = number.getPrime(bits)

    # Choose base g = 2.
    #
    # This simplified example does not validate
    # that g generates the required group.

    g = 2

    # Generate private key x.
    x = secrets.randbelow(p - 3) + 2

    # Calculate public key component:
    #
    # y = g^x mod p

    y = pow(g, x, p)

    # Public key = (p, g, y)
    # Private key = x

    return (p, g, y), x


# ============================================================
# ELGAMAL ENCRYPTION
# ============================================================

def elgamal_encrypt(m, public):

    # m:
    #   Integer plaintext.
    #
    # public:
    #   ElGamal public key (p, g, y).


    # Extract public key values.
    p, g, y = public


    # --------------------------------------------------------
    # STEP 1: VALIDATE PLAINTEXT
    # --------------------------------------------------------

    # The message must be an integer in the range:
    #
    # 0 <= m < p
    #
    # Otherwise, raise an error.

    if not 0 <= m < p:
        raise ValueError(
            "Plaintext integer outside group range"
        )


    # --------------------------------------------------------
    # STEP 2: GENERATE TEMPORARY RANDOM KEY
    # --------------------------------------------------------

    # k is an ephemeral random value.
    #
    # A fresh k should be used for each encryption.

    k = secrets.randbelow(p - 3) + 2


    # --------------------------------------------------------
    # STEP 3: CALCULATE CIPHERTEXT COMPONENTS
    # --------------------------------------------------------

    # First component:
    #
    # c1 = g^k mod p

    c1 = pow(g, k, p)

    # Second component:
    #
    # c2 = m * y^k mod p

    c2 = (m * pow(y, k, p)) % p


    # --------------------------------------------------------
    # STEP 4: RETURN CIPHERTEXT
    # --------------------------------------------------------

    # ElGamal ciphertext contains two integers.

    return (c1, c2)


# ============================================================
# ELGAMAL DECRYPTION
# ============================================================

def elgamal_decrypt(cipher, public, private):

    # Extract modulus p.
    p, _, _ = public

    # Extract ciphertext components.
    a, b = cipher


    # --------------------------------------------------------
    # STEP 1: RECREATE SHARED VALUE
    # --------------------------------------------------------

    # Formula:
    #
    # shared = a^private mod p
    #
    # Here a = g^k mod p.
    #
    # Therefore:
    #
    # shared = g^(kx) mod p

    shared = pow(a, private, p)


    # --------------------------------------------------------
    # STEP 2: CALCULATE MODULAR INVERSE
    # --------------------------------------------------------

    # inverse(shared) mod p
    #
    # This reverses the multiplication by y^k
    # performed during encryption.

    inverse = pow(shared, -1, p)


    # --------------------------------------------------------
    # STEP 3: RECOVER PLAINTEXT
    # --------------------------------------------------------

    # Formula:
    #
    # m = b * inverse(shared) mod p

    message = (b * inverse) % p

    return message


# ============================================================
# ELGAMAL HOMOMORPHIC MULTIPLICATION
# ============================================================
#
# IMPORTANT PROPERTY:
#
# E(a) * E(b) = E(a*b)
#
# ElGamal ciphertext contains two components.
#
# Therefore, we multiply corresponding components.
#
# If:
#
# C1 = (a1, b1)
# C2 = (a2, b2)
#
# Then:
#
# C_product = (
#     a1*a2 mod p,
#     b1*b2 mod p
# )
#
# Decrypting gives:
#
# (a*b) mod p
#
# ============================================================


def elgamal_multiply(c1, c2, public):

    # Extract modulus.
    p = public[0]

    # Multiply first ciphertext components.
    first = (c1[0] * c2[0]) % p

    # Multiply second ciphertext components.
    second = (c1[1] * c2[1]) % p

    # Return encrypted product.
    return (first, second)


# ============================================================
# PART 5: RABIN CRYPTOSYSTEM
# ============================================================
#
# WHAT IS RABIN?
#
# Rabin is an asymmetric cryptographic algorithm.
#
# Its encryption formula is:
#
# C = m^2 mod n
#
# Where:
#
# n = p*q
#
# Public key = n
# Private key = (p, q)
#
# IMPORTANT:
#
# Rabin decryption generally produces FOUR possible
# plaintext values.
#
# We need extra information or redundancy to identify
# which one is the original message.
#
# ============================================================


def rabin_keys(bits=512):

    # --------------------------------------------------------
    # STEP 1: GENERATE SPECIAL PRIME NUMBERS
    # --------------------------------------------------------

    # Rabin uses primes p and q satisfying:
    #
    # p % 4 == 3
    # q % 4 == 3
    #
    # These are called Blum primes.
    #
    # This condition simplifies square-root calculations.

    def prime():

        # Generate a prime with half the requested bits.
        p = number.getPrime(bits // 2)

        # Continue generating until p % 4 == 3.
        while p % 4 != 3:
            p = number.getPrime(bits // 2)

        return p


    # Generate two special prime numbers.
    p = prime()
    q = prime()

    # Ensure both primes are different.
    while p == q:
        q = prime()


    # --------------------------------------------------------
    # STEP 2: CALCULATE MODULUS
    # --------------------------------------------------------

    # Formula:
    # n = p*q

    n = p * q


    # --------------------------------------------------------
    # STEP 3: RETURN KEYS
    # --------------------------------------------------------

    # Public key = n
    # Private key = (p, q)

    return n, (p, q)


# ============================================================
# RABIN ENCRYPTION
# ============================================================

def rabin_encrypt(m, n):

    # Check that plaintext integer is in the valid range.
    if not 0 <= m < n:
        raise ValueError(
            "m must be smaller than n"
        )

    # Rabin encryption formula:
    #
    # C = m^2 mod n

    ciphertext = pow(m, 2, n)

    return ciphertext


# ============================================================
# RABIN DECRYPTION
# ============================================================

def rabin_decrypt_roots(c, private):

    # Extract the two prime numbers.
    p, q = private

    # Calculate modulus.
    n = p * q


    # --------------------------------------------------------
    # STEP 1: CALCULATE SQUARE ROOTS MODULO p AND q
    # --------------------------------------------------------

    # Because p % 4 == 3:
    #
    # rp = c^((p+1)/4) mod p
    #
    # Similarly:
    #
    # rq = c^((q+1)/4) mod q

    rp = pow(c, (p + 1) // 4, p)

    rq = pow(c, (q + 1) // 4, q)


    # --------------------------------------------------------
    # STEP 2: RECONSTRUCT FOUR POSSIBLE ROOTS
    # --------------------------------------------------------

    # CRT = Chinese Remainder Theorem.
    #
    # CRT allows us to combine solutions modulo p
    # and modulo q into solutions modulo n.
    #
    # We consider:
    #
    # +rp and -rp
    # +rq and -rq
    #
    # This gives four combinations.

    roots = set()

    for a in (rp, -rp):

        for b in (rq, -rq):

            # pow(q, -1, p) calculates inverse(q) mod p.
            #
            # pow(p, -1, q) calculates inverse(p) mod q.
            #
            # These values are used in CRT.

            root = (
                a * q * pow(q, -1, p)
                +
                b * p * pow(p, -1, q)
            ) % n

            roots.add(root)


    # --------------------------------------------------------
    # STEP 3: RETURN POSSIBLE PLAINTEXT VALUES
    # --------------------------------------------------------

    # sorted() returns roots in ascending order.
    #
    # Usually, four possible plaintext values exist.
    #
    # The original plaintext is one of these roots.
    #
    # Additional encoding/redundancy is required
    # to identify the correct one.

    return sorted(roots)
