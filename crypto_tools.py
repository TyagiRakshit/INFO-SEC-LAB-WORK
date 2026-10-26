
# ============================================================
# INFORMATION SECURITY EXAM TOOLKIT
# FILE: crypto_tools.py
#
# TOPIC: REUSABLE CRYPTOGRAPHIC FUNCTIONS
#
# LABS COVERED:
#
# LAB 2 - AES, DES, 3DES ENCRYPTION
# LAB 3 - RSA ENCRYPTION
# LAB 5 - HASHING
# LAB 6 - DIGITAL SIGNATURES
# LAB 7 - PAILLIER HOMOMORPHIC ENCRYPTION
# LAB 8 - SEARCHABLE ENCRYPTION
#
# ============================================================
#
# AIM:
#
# To create reusable cryptographic functions that can
# be imported into different scenario-based programs.
#
# Instead of rewriting AES, RSA, hashing, digital
# signatures and Paillier for every exam question,
# we can simply import the required functions.
#
# EXAMPLE:
#
# from crypto_tools import symmetric_encrypt
#
# envelope, key = symmetric_encrypt(
#     b"Confidential Data",
#     "AES",
#     256,
#     "GCM"
# )
#
# IMPORTANT:
#
# DES, MD5, SHA-1 and textbook RSA are legacy or
# educational techniques.
#
# Do not use them for new real-world security systems.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT REQUIRED LIBRARIES
# ============================================================

# base64:
# Converts binary data into text for JSON storage.

import base64

# hashlib:
# Provides hashing algorithms such as MD5 and SHA-256.

import hashlib

# hmac:
# Used for keyed hashes and secure comparisons.

import hmac

# json:
# Used to save and load Python dictionaries as files.

import json

import secrets

from pathlib import Path


# ------------------------------------------------------------
# SYMMETRIC ENCRYPTION LIBRARIES
# ------------------------------------------------------------

# AES:
# Advanced Encryption Standard.
#
# DES:
# Data Encryption Standard (legacy).
#
# DES3:
# Triple DES (legacy).
#
# PKCS1_OAEP:
# RSA encryption padding scheme.

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP

# pad():
# Adds padding before CBC encryption.
#
# unpad():
# Removes padding after CBC decryption.

from Crypto.Util.Padding import pad, unpad


# ------------------------------------------------------------
# RSA LIBRARIES
# ------------------------------------------------------------

from Crypto.PublicKey import RSA

# SHA-256, SHA-512, MD5 and SHA-1 implementations
# used by RSA digital signature functions.

from Crypto.Hash import SHA256, SHA512, MD5, SHA1

# RSA-PSS digital signature scheme.

from Crypto.Signature import pss

# Secure random byte generator.

from Crypto.Random import get_random_bytes


# ------------------------------------------------------------
# PAILLIER LIBRARY
# ------------------------------------------------------------

# Paillier supports additive homomorphic encryption.
#
# Install using:
#
# pip install phe

from phe import paillier



def b64(data):

    # base64.b64encode() converts bytes into Base64 bytes.
    #
    # decode("ascii") converts those bytes into a string.
    #
    # Example:
    #
    # b"Hello" -> "SGVsbG8="

    encoded = base64.b64encode(data)

    return encoded.decode("ascii")


def unb64(text):

    # Convert Base64 text back into original bytes.
    #
    # validate=True rejects invalid Base64 characters.

    return base64.b64decode(
        text,
        validate=True
    )


# ============================================================
# PART 2: HASHING FUNCTIONS
# ============================================================
# Common algorithms:
#
# MD5    -> 128-bit digest
# SHA-1  -> 160-bit digest
# SHA256 -> 256-bit digest
# SHA512 -> 512-bit digest
#
# APPLICATIONS:
#
# 1. Data integrity checking
# 2. File integrity verification
# 3. Digital signatures
#
# ============================================================


# ------------------------------------------------------------
# HASH BINARY DATA
# ------------------------------------------------------------

def hash_bytes(data, algorithm="sha256"):

    # data:
    #   Input bytes to hash.
    #
    # algorithm:
    #   Hash algorithm name.
    #
    # Examples:
    # "md5", "sha1", "sha256", "sha512"
    #
    # lower():
    # Converts algorithm name to lowercase.
    #
    # replace("-", ""):
    # Removes hyphens.
    #
    # Example:
    # "SHA-256" -> "sha256"

    algorithm = algorithm.lower().replace("-", "")

    # hashlib.new() selects the requested algorithm.
    #
    # hexdigest() returns hexadecimal output.

    return hashlib.new(
        algorithm,
        data
    ).hexdigest()


# ------------------------------------------------------------
# HASH NORMAL TEXT
# ------------------------------------------------------------

def hash_text(text, algorithm="sha256"):

    # Hashing functions require bytes.
    #
    # encode() converts a string into bytes.
    #
    # Example:
    # "Hello" -> b"Hello"
    #
    # Then call hash_bytes().

    return hash_bytes(
        text.encode("utf-8"),
        algorithm
    )


# ------------------------------------------------------------
# HASH A FILE
# ------------------------------------------------------------

def file_hash(path, algorithm="sha256"):

    # Create a hash object using the requested algorithm.

    algorithm = algorithm.lower().replace("-", "")

    hasher = hashlib.new(algorithm)

    # Open file in binary read mode.
    #
    # "rb" = Read Binary
    #
    # This works for:
    #
    # .txt, .pdf, .jpg, .png, .docx, etc.

    with open(path, "rb") as file:

        # Read the file in chunks of 65536 bytes.
        #
        # 65536 bytes = 64 KiB.
        #
        # This avoids loading the entire file into memory.

        for block in iter(
            lambda: file.read(65536),
            b""
        ):

            # Add each block to the hash calculation.

            hasher.update(block)

    # Return final file hash.

    return hasher.hexdigest()


# ============================================================
# PART 3: SYMMETRIC ENCRYPTION
# ============================================================
#
# WHAT IS SYMMETRIC ENCRYPTION?
#
# Symmetric encryption uses the SAME secret key
# for encryption and decryption.
#
# ALGORITHMS:
#
# AES:
#   Supports 128, 192 and 256-bit keys.
#
# DES:
#   Uses an 8-byte key with 56 effective key bits.
#   DES is insecure for modern use.
#
# 3DES:
#   Applies DES multiple times.
#   Legacy algorithm.
#
# MODES:
#
# GCM:
#   Authenticated encryption.
#   Supported here only for AES.
#
# CBC:
#   Block encryption using an IV and padding.
#   This toolkit also adds HMAC authentication.
#
# CTR:
#   Counter mode encryption.
#   Does not require padding.
#   This toolkit also adds HMAC authentication.
#
# ============================================================


def symmetric_encrypt(
    data,
    algorithm="AES",
    bits=256,
    mode="GCM",
    key=None
):

    # PARAMETERS:
    #
    # data:
    #   Original plaintext BYTES.
    #
    # algorithm:
    #   "AES", "DES" or "3DES"
    #
    # bits:
    #   Requested AES key size.
    #
    # mode:
    #   "GCM", "CBC" or "CTR"
    #
    # key:
    #   Optional existing symmetric key.
    #
    # If no key is supplied, generate a random one.


    # --------------------------------------------------------
    # STEP 1: NORMALIZE ALGORITHM AND MODE
    # --------------------------------------------------------

    # Convert names into uppercase.
    #
    # Example:
    # "aes" -> "AES"

    algorithm = algorithm.upper()
    mode = mode.upper()


    # --------------------------------------------------------
    # STEP 2: SELECT ENCRYPTION ALGORITHM
    # --------------------------------------------------------

    if algorithm == "AES":

        # AES supports three key sizes.

        if bits not in (128, 192, 256):
            raise ValueError(
                "AES bits: 128, 192, 256"
            )

        # Generate AES key if not provided.
        #
        # bits // 8 converts bits into bytes.
        #
        # AES-128 -> 16 bytes
        # AES-192 -> 24 bytes
        # AES-256 -> 32 bytes

        key = key or get_random_bytes(bits // 8)

        # Select AES cipher module.

        module = AES

    elif algorithm == "DES":

        # DES uses an 8-byte key.
        #
        # Only 56 bits provide effective key strength.

        key = key or get_random_bytes(8)

        module = DES

    elif algorithm == "3DES":

        # Triple DES commonly uses a 24-byte key.
        #
        # adjust_key_parity() adjusts DES parity bits.

        key = key or DES3.adjust_key_parity(
            get_random_bytes(24)
        )

        module = DES3

    else:

        # Reject unsupported algorithms.

        raise ValueError(
            "Unknown symmetric algorithm"
        )


    # --------------------------------------------------------
    # STEP 3: VALIDATE KEY LENGTH
    # --------------------------------------------------------

    # Determine accepted key lengths.
    #
    # AES  -> 16, 24, 32 bytes
    # DES  -> 8 bytes
    # 3DES -> 16 or 24 bytes

    if algorithm == "AES":
        valid_lengths = (16, 24, 32)

    elif algorithm == "DES":
        valid_lengths = (8,)

    else:
        valid_lengths = (16, 24)

    if len(key) not in valid_lengths:
        raise ValueError(
            "Invalid key size"
        )


    # ========================================================
    # STEP 4: ENCRYPT USING SELECTED MODE
    # ========================================================

    # --------------------------------------------------------
    # OPTION A: GCM MODE
    # --------------------------------------------------------

    if mode == "GCM":

        # This toolkit supports GCM only with AES.

        if algorithm != "AES":
            raise ValueError(
                "GCM supported here only for AES"
            )

        # Create AES-GCM cipher.
        #
        # A fresh nonce is generated automatically.

        cipher = AES.new(
            key,
            AES.MODE_GCM
        )

        # Encrypt data and generate authentication tag.
        #
        # ct  = Ciphertext
        # tag = Authentication tag

        ct, tag = cipher.encrypt_and_digest(data)

        # Create JSON-compatible encrypted package.
        #
        # Nonce, tag and ciphertext are Base64 encoded.

        envelope = {
            "mode": mode,
            "nonce": b64(cipher.nonce),
            "tag": b64(tag),
            "ct": b64(ct)
        }


    # --------------------------------------------------------
    # OPTION B: CBC MODE
    # --------------------------------------------------------

    elif mode == "CBC":

        # Create cipher in CBC mode.
        #
        # CBC = Cipher Block Chaining.
        #
        # A random IV is generated automatically.
        #
        # IV = Initialization Vector.

        cipher = module.new(
            key,
            module.MODE_CBC
        )

        # CBC requires plaintext length to be a multiple
        # of the block size.
        #
        # pad() adds the required padding.

        padded_data = pad(
            data,
            module.block_size
        )

        # Encrypt padded plaintext.

        ct = cipher.encrypt(padded_data)


        # ----------------------------------------------------
        # GENERATE HMAC AUTHENTICATION TAG
        # ----------------------------------------------------

        # CBC encryption alone does not detect tampering.
        #
        # We derive a separate MAC key from the
        # encryption key for this classroom example.
        #
        # A production implementation should use
        # a proper KDF for key separation.

        mac_key = hashlib.sha256(
            b"cbc-auth-v1" + key
        ).digest()

        # Generate HMAC over IV + ciphertext.
        #
        # This allows us to detect modifications.

        tag = hmac.new(
            mac_key,
            cipher.iv + ct,
            hashlib.sha256
        ).digest()


        # Store encrypted data and metadata.

        envelope = {
            "mode": mode,
            "iv": b64(cipher.iv),
            "tag": b64(tag),
            "ct": b64(ct)
        }


    # --------------------------------------------------------
    # OPTION C: CTR MODE
    # --------------------------------------------------------

    elif mode == "CTR":

        # CTR = Counter Mode.
        #
        # CTR transforms a block cipher into a
        # stream-like encryption operation.
        #
        # It does not require padding.

        cipher = module.new(
            key,
            module.MODE_CTR
        )

        # Encrypt plaintext bytes directly.

        ct = cipher.encrypt(data)


        # ----------------------------------------------------
        # GENERATE HMAC AUTHENTICATION TAG
        # ----------------------------------------------------

        # CTR alone does not provide integrity.
        #
        # We use HMAC to authenticate nonce + ciphertext.

        mac_key = hashlib.sha256(
            b"ctr-auth-v1" + key
        ).digest()

        tag = hmac.new(
            mac_key,
            cipher.nonce + ct,
            hashlib.sha256
        ).digest()


        # Store ciphertext and metadata.

        envelope = {
            "mode": mode,
            "nonce": b64(cipher.nonce),
            "tag": b64(tag),
            "ct": b64(ct)
        }


    else:

        raise ValueError(
            "Mode must be GCM, CBC, CTR"
        )


    # --------------------------------------------------------
    # STEP 5: ADD ALGORITHM INFORMATION
    # --------------------------------------------------------

    # Store algorithm name and actual key size.
    #
    # len(key) gives number of bytes.
    #
    # Multiplying by 8 gives number of bits.

    envelope.update(
        algorithm=algorithm,
        bits=len(key) * 8
    )


    # --------------------------------------------------------
    # STEP 6: RETURN ENCRYPTED PACKAGE AND KEY
    # --------------------------------------------------------

    # envelope:
    #   Contains encrypted data and metadata.
    #
    # key:
    #   Symmetric encryption key.
    #
    # Keep the key secret.

    return envelope, key


# ============================================================
# PART 4: SYMMETRIC DECRYPTION
# ============================================================

def symmetric_decrypt(envelope, key):

    # Extract algorithm and mode from encrypted package.

    algorithm = envelope["algorithm"]
    mode = envelope["mode"]


    # --------------------------------------------------------
    # STEP 1: SELECT CIPHER MODULE
    # --------------------------------------------------------

    modules = {
        "AES": AES,
        "DES": DES,
        "3DES": DES3
    }

    module = modules[algorithm]


    # --------------------------------------------------------
    # STEP 2: DECODE CIPHERTEXT
    # --------------------------------------------------------

    # Convert Base64 ciphertext into bytes.

    ct = unb64(envelope["ct"])


    # --------------------------------------------------------
    # OPTION A: GCM DECRYPTION
    # --------------------------------------------------------

    if mode == "GCM":

        # Recover the original nonce.

        nonce = unb64(envelope["nonce"])

        # Create AES-GCM cipher with same key and nonce.

        cipher = AES.new(
            key,
            AES.MODE_GCM,
            nonce=nonce
        )

        # Decrypt and verify authentication tag.
        #
        # If ciphertext/tag has been modified,
        # verification raises an exception.

        return cipher.decrypt_and_verify(
            ct,
            unb64(envelope["tag"])
        )


    # --------------------------------------------------------
    # OPTION B: CBC OR CTR DECRYPTION
    # --------------------------------------------------------

    if mode in ("CBC", "CTR"):

        # CBC uses IV.
        # CTR uses nonce.

        if mode == "CBC":
            iv = unb64(envelope["iv"])
            label = b"cbc-auth-v1"

        else:
            iv = unb64(envelope["nonce"])
            label = b"ctr-auth-v1"


        # ----------------------------------------------------
        # VERIFY AUTHENTICATION TAG
        # ----------------------------------------------------

        # Recreate the MAC key using the same label
        # and symmetric encryption key.

        mac_key = hashlib.sha256(
            label + key
        ).digest()

        # Recalculate expected HMAC.

        expected = hmac.new(
            mac_key,
            iv + ct,
            hashlib.sha256
        ).digest()

        # Compare calculated tag with stored tag.
        #
        # compare_digest() reduces timing-based
        # information leakage during comparison.

        if not hmac.compare_digest(
            expected,
            unb64(envelope["tag"])
        ):
            raise ValueError(
                "Authentication failed: encrypted data was modified"
            )


        # ----------------------------------------------------
        # CBC DECRYPTION
        # ----------------------------------------------------

        if mode == "CBC":

            # Create CBC cipher using original IV.

            cipher = module.new(
                key,
                module.MODE_CBC,
                iv=iv
            )

            # Decrypt ciphertext.
            padded_plaintext = cipher.decrypt(ct)

            # Remove padding and return original bytes.

            return unpad(
                padded_plaintext,
                module.block_size
            )


        # ----------------------------------------------------
        # CTR DECRYPTION
        # ----------------------------------------------------

        # CTR uses the same counter-mode operation
        # for encryption and decryption.

        cipher = module.new(
            key,
            module.MODE_CTR,
            nonce=iv
        )

        return cipher.decrypt(ct)


    # Reject unknown modes.

    raise ValueError("Unknown mode")


# ============================================================
# PART 5: RSA KEY GENERATION
# ============================================================
#
# WHAT IS RSA?
#
# RSA is an asymmetric cryptographic algorithm.
#
# It uses:
#
# PUBLIC KEY  -> Encryption / Signature Verification
# PRIVATE KEY -> Decryption / Signing
#
# ============================================================


def rsa_keys(bits=2048):

    # Generate RSA private key.
    #
    # bits determines RSA modulus size.
    #
    # Common sizes:
    # 2048 bits
    # 3072 bits
    # 4096 bits

    private = RSA.generate(bits)

    # Extract corresponding public key.

    public = private.publickey()

    # Return public key first and private key second.

    return public, private


# ============================================================
# PART 6: RSA KEY WRAPPING
# ============================================================
#
# WHAT IS KEY WRAPPING?
#
# Key wrapping means encrypting a symmetric key
# using an asymmetric public key.
#
# EXAMPLE:
#
# 1. Generate AES key.
# 2. Encrypt file using AES.
# 3. Encrypt AES key using RSA public key.
# 4. Receiver decrypts AES key using RSA private key.
# 5. Receiver decrypts file using AES.
#
# This is called HYBRID ENCRYPTION.
#
# ============================================================


def rsa_wrap(public_key, key):

    # Create RSA-OAEP cipher.
    #
    # OAEP is a padding scheme for RSA encryption.
    #
    # SHA-256 is used inside OAEP.

    cipher = PKCS1_OAEP.new(
        public_key,
        hashAlgo=SHA256
    )

    # Encrypt symmetric key using RSA public key.

    encrypted_key = cipher.encrypt(key)

    # Convert encrypted bytes into Base64 text.
    #
    # This makes storage in JSON easier.

    return b64(encrypted_key)


def rsa_unwrap(private_key, wrapped):

    # Convert Base64 text back into encrypted bytes.

    encrypted_key = unb64(wrapped)

    # Create RSA-OAEP cipher using private key.

    cipher = PKCS1_OAEP.new(
        private_key,
        hashAlgo=SHA256
    )

    # Decrypt and recover original symmetric key.

    return cipher.decrypt(encrypted_key)


# ============================================================
# PART 7: RSA DIGITAL SIGNATURES
# ============================================================
#
# WHAT IS A DIGITAL SIGNATURE?
#
# A digital signature helps verify:
#
# 1. AUTHENTICITY:
#    Was the data signed by the private-key holder?
#
# 2. INTEGRITY:
#    Has the signed data been modified?
#
# RSA SIGNATURE:
#
# Private key -> Sign
# Public key  -> Verify
#
# This toolkit uses RSA-PSS.
#
# PSS = Probabilistic Signature Scheme.
#
# ============================================================


def rsa_sign(
    data,
    private_key,
    algorithm="sha256"
):

    # Select hashing algorithm.
    #
    # The dictionary maps names to hash modules.

    hash_algorithms = {
        "md5": MD5,
        "sha1": SHA1,
        "sha256": SHA256,
        "sha512": SHA512
    }

    hash_module = hash_algorithms[algorithm.lower()]


    # --------------------------------------------------------
    # STEP 1: HASH THE DATA
    # --------------------------------------------------------

    # Hash the original data using the selected algorithm.

    message_hash = hash_module.new(data)


    # --------------------------------------------------------
    # STEP 2: SIGN THE HASH
    # --------------------------------------------------------

    # pss.new() creates an RSA-PSS signer.
    #
    # The private key is used to generate the signature.

    signer = pss.new(private_key)

    signature = signer.sign(message_hash)


    # --------------------------------------------------------
    # STEP 3: RETURN SIGNATURE
    # --------------------------------------------------------

    # Convert signature bytes into Base64 text.

    return b64(signature)


# ============================================================
# RSA SIGNATURE VERIFICATION
# ============================================================

def rsa_verify(
    data,
    signature,
    public_key,
    algorithm="sha256"
):

    # Select hashing algorithm.

    hash_algorithms = {
        "md5": MD5,
        "sha1": SHA1,
        "sha256": SHA256,
        "sha512": SHA512
    }

    hash_module = hash_algorithms[algorithm.lower()]


    try:

        # Calculate hash of received data.

        message_hash = hash_module.new(data)

        # Create RSA-PSS verifier using public key.

        verifier = pss.new(public_key)

        # Verify signature.
        #
        # If signature is valid, verify() returns normally.
        #
        # If invalid, verify() raises an exception.

        verifier.verify(
            message_hash,
            unb64(signature)
        )

        return True

    except (ValueError, TypeError):

        # Invalid signature or malformed signature data.

        return False


# ============================================================
# PART 8: PAILLIER HOMOMORPHIC ENCRYPTION
# ============================================================
#
# WHAT IS HOMOMORPHIC ENCRYPTION?
#
# It allows certain calculations on encrypted values
# without decrypting them first.
#
# PAILLIER:
#
# Supports ADDITIVE HOMOMORPHISM.
#
# IMPORTANT PROPERTY:
#
# E(a) * E(b) mod n^2 = E(a+b)
#
# In the phe library, we can simply add encrypted
# number objects using the + operator.
#
# ============================================================


def paillier_keys(bits=2048):

    # Generate Paillier public/private key pair.
    #
    # n_length determines modulus size.

    return paillier.generate_paillier_keypair(
        n_length=bits
    )


# ------------------------------------------------------------
# CONVERT ENCRYPTED NUMBER FOR JSON STORAGE
# ------------------------------------------------------------

def paillier_pack(cipher):

    # A phe EncryptedNumber contains:
    #
    # ciphertext:
    #   The encrypted integer.
    #
    # exponent:
    #   Encoding exponent used by the phe library.
    #
    # Convert ciphertext into a string because it may
    # be too large for some JSON consumers.
    #
    # The exponent must be preserved for correct decoding.

    return {
        "c": str(cipher.ciphertext()),
        "e": cipher.exponent
    }


# ------------------------------------------------------------
# RECONSTRUCT ENCRYPTED NUMBER FROM JSON
# ------------------------------------------------------------

def paillier_unpack(public_key, obj):

    # Recreate phe EncryptedNumber using:
    #
    # 1. Public key
    # 2. Stored ciphertext
    # 3. Stored exponent
    #
    # This allows homomorphic operations after loading
    # the encrypted record from a JSON file.

    return paillier.EncryptedNumber(
        public_key,
        int(obj["c"]),
        int(obj["e"])
    )


# ------------------------------------------------------------
# HOMOMORPHIC ADDITION
# ------------------------------------------------------------

def paillier_sum(public_key, items):

    # Start with an encryption of zero.
    #
    # Zero is the additive identity:
    #
    # 0 + a = a

    total = public_key.encrypt(0)

    # Add each encrypted number.
    #
    # The phe library performs homomorphic addition.
    #
    # Individual values remain encrypted.

    for item in items:
        total += item

    # Return encrypted total.
    #
    # Only the final total needs to be decrypted.

    return total


# ============================================================
# PART 9: SEARCHABLE ENCRYPTION
# ============================================================
#
# WHAT IS SEARCHABLE ENCRYPTION?
#
# Searchable encryption allows authorized searching
# over protected data.
#
# This toolkit uses:
#
# HMAC-SHA256 search tokens.
#
# IMPORTANT:
#
# Same keyword + same key = Same token.
#
# This makes keyword lookup possible.
#
# An inverted index maps:
#
# Search token -> Document IDs
#
# ============================================================


def searchable_token(word, key):

    # strip():
    # Removes spaces at the beginning and end.
    #
    # casefold():
    # Converts text into a normalized lowercase-like form.
    #
    # encode():
    # Converts string into bytes.

    word_bytes = word.strip().casefold().encode("utf-8")

    # Generate HMAC-SHA256.
    #
    # HMAC uses a secret key.
    #
    # This is different from plain SHA-256 hashing.

    token = hmac.new(
        key,
        word_bytes,
        hashlib.sha256
    ).hexdigest()

    return token


# ------------------------------------------------------------
# CREATE INVERTED INDEX
# ------------------------------------------------------------

def make_index(documents, key):

    # documents:
    #   Dictionary mapping document IDs to text.
    #
    # Example:
    #
    # {
    #   "doc1": "python is easy",
    #   "doc2": "python is useful"
    # }
    #
    # index:
    #   Dictionary mapping search tokens to document IDs.

    index = {}


    # Process each document.
    for doc_id, text in documents.items():

        # Convert text into normalized lowercase.
        #
        # split() separates text into words.
        #
        # set() removes duplicate words.

        unique_words = set(
            text.casefold().split()
        )


        # Process each unique word.
        for word in unique_words:

            # Generate search token.

            token = searchable_token(word, key)

            # setdefault() creates an empty list
            # if the token is not already in the index.
            #
            # Then append the document ID.

            index.setdefault(
                token,
                []
            ).append(doc_id)

    return index


# ============================================================
# PART 10: JSON FILE STORAGE
# ============================================================
#
# WHY USE JSON?
#
# JSON allows us to store Python dictionaries
# and lists in a file.
#
# This is useful for scenario-based questions where
# records must remain available after restarting
# the program.
#
# Example:
#
# Grant Portal:
# Store encrypted grant records.
#
# Voting System:
# Store encrypted ballots and signatures.
#
# IMPORTANT:
#
# JSON storage alone does not encrypt or authenticate
# the stored data.
#
# ============================================================


def load_json(path, default):

    # Convert input into a Path object.
    path = Path(path)

    # If the file exists:
    # Read its text and convert JSON into Python data.
    #
    # Otherwise:
    # Return the supplied default value.

    if path.exists():
        return json.loads(path.read_text())

    return default


def save_json(path, obj):

    # Convert input into Path object.
    path = Path(path)

    # Create temporary file path.
    #
    # Example:
    # records.json -> records.json.tmp
    #
    # This reduces the risk of leaving a partially
    # written destination file if writing fails.

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    # Convert Python object into formatted JSON.
    #
    # indent=2 makes the file easier to read.

    temp_path.write_text(
        json.dumps(obj, indent=2)
    )

    # Replace original file with temporary file.
    #
    # This is a basic atomic-replacement pattern
    # when both files are on the same filesystem.
    #
    # It does not provide encryption, locking,
    # backups or full crash durability.

    temp_path.replace(path)


# ============================================================
# PART 11: HEXADECIMAL DUMP
# ============================================================
#
# WHAT IS A HEX DUMP?
#
# A hex dump displays bytes in hexadecimal format.
#
# Example:
#
# "ABC" -> 41 42 43
#
# Useful when exam questions ask to display
# decrypted data in hexadecimal format.
#
# ============================================================


def hex_dump(data):

    # data must be bytes.
    #
    # hex(" ") separates bytes with spaces.

    return data.hex(" ")


# ============================================================
# PART 12: ELGAMAL DIGITAL SIGNATURES
# ============================================================
#
# WHAT IS ELGAMAL SIGNATURE?
#
# ElGamal is an asymmetric digital signature scheme.
#
# It uses:
#
# Private key x -> Signing
# Public key (p,g,y) -> Verification
#
# Where:
#
# y = g^x mod p
#
# Signature contains:
#
# (r, s)
#
# IMPORTANT:
#
# This is a classroom implementation.
# It does not use fully validated group parameters.
#
# ============================================================


def elgamal_signing_keys(bits=1024):

    # Import prime number generation utility.
    from Crypto.Util import number

    # Generate random prime p.
    p = number.getPrime(bits)

    # Choose base g.
    #
    # This simplified implementation does not
    # validate g as a generator.

    g = 2

    # Generate private key x.
    x = secrets.randbelow(p - 3) + 2

    # Calculate public key component:
    #
    # y = g^x mod p

    y = pow(g, x, p)

    # Return public and private keys.

    return (p, g, y), x


# ------------------------------------------------------------
# ELGAMAL SIGNING
# ------------------------------------------------------------

def elgamal_sign(
    data,
    public_key,
    private_x,
    algorithm="sha512"
):

    # Import math for GCD.
    import math

    # Extract public parameters.
    p, g, y = public_key


    # --------------------------------------------------------
    # STEP 1: HASH THE MESSAGE
    # --------------------------------------------------------

    # Calculate message hash using selected algorithm.
    #
    # digest() returns raw hash bytes.
    #
    # int.from_bytes() converts hash bytes to integer.
    #
    # Reduce modulo p-1.

    digest_bytes = hashlib.new(
        algorithm,
        data
    ).digest()

    digest = int.from_bytes(
        digest_bytes,
        "big"
    ) % (p - 1)


    # --------------------------------------------------------
    # STEP 2: GENERATE TEMPORARY KEY k
    # --------------------------------------------------------

    # k must be coprime to p-1.
    #
    # This ensures that its modular inverse exists.

    while True:

        k = secrets.randbelow(p - 3) + 2

        if math.gcd(k, p - 1) == 1:
            break


    # --------------------------------------------------------
    # STEP 3: CALCULATE SIGNATURE COMPONENT r
    # --------------------------------------------------------

    # Formula:
    #
    # r = g^k mod p

    r = pow(g, k, p)


    # --------------------------------------------------------
    # STEP 4: CALCULATE SIGNATURE COMPONENT s
    # --------------------------------------------------------

    # Calculate modular inverse of k:
    #
    # k_inverse = k^(-1) mod (p-1)

    k_inverse = pow(
        k,
        -1,
        p - 1
    )

    # Formula:
    #
    # s = k_inverse * (hash - x*r) mod (p-1)

    s = (
        k_inverse * (digest - private_x * r)
    ) % (p - 1)


    # --------------------------------------------------------
    # STEP 5: RETURN SIGNATURE
    # --------------------------------------------------------

    # Store large integers as strings for JSON.

    return {
        "r": str(r),
        "s": str(s)
    }


# ------------------------------------------------------------
# ELGAMAL SIGNATURE VERIFICATION
# ------------------------------------------------------------

def elgamal_verify(
    data,
    signature,
    public_key,
    algorithm="sha512"
):

    try:

        # Extract public key parameters.
        p, g, y = public_key

        # Extract signature components.
        r = int(signature["r"])
        s = int(signature["s"])


        # ----------------------------------------------------
        # STEP 1: VALIDATE SIGNATURE RANGE
        # ----------------------------------------------------

        # A valid signature must satisfy:
        #
        # 0 < r < p
        # 0 <= s < p-1

        if not (0 < r < p and 0 <= s < p - 1):
            return False


        # ----------------------------------------------------
        # STEP 2: HASH THE RECEIVED DATA
        # ----------------------------------------------------

        # Calculate hash using same algorithm as signer.

        hash_bytes_value = hashlib.new(
            algorithm,
            data
        ).digest()

        h = int.from_bytes(
            hash_bytes_value,
            "big"
        ) % (p - 1)


        # ----------------------------------------------------
        # STEP 3: VERIFY SIGNATURE
        # ----------------------------------------------------

        # ElGamal verification formula:
        #
        # g^h mod p = y^r * r^s mod p
        #
        # Calculate left side.

        left = pow(g, h, p)

        # Calculate right side.

        right = (
            pow(y, r, p) * pow(r, s, p)
        ) % p

        # If both sides match, verification succeeds.

        return left == right

    except (ValueError, KeyError, TypeError):

        # Return False for invalid or malformed signatures.

        return False


# ============================================================
# PART 13: FILE ENCRYPTION
# ============================================================
#
# These functions allow us to encrypt/decrypt
# complete files using the symmetric encryption
# functions defined earlier.
#
# Works with:
#
# Text files, PDFs, images, documents, etc.
#
# ============================================================


def encrypt_file(
    path,
    algorithm="AES",
    bits=256,
    mode="GCM"
):

    # Read the complete file as bytes.
    #
    # Path(path).read_bytes() is equivalent to:
    #
    # with open(path, "rb") as file:
    #     data = file.read()

    data = Path(path).read_bytes()

    # Encrypt file bytes.
    #
    # Returns:
    # 1. Encrypted envelope
    # 2. Symmetric encryption key
    #
    # This function does not automatically save
    # the encrypted envelope to disk.

    envelope, key = symmetric_encrypt(
        data,
        algorithm,
        bits,
        mode
    )

    return envelope, key


def decrypt_file(envelope, key, path):

    # Decrypt the encrypted file data.

    plaintext = symmetric_decrypt(
        envelope,
        key
    )

    # Save recovered bytes to output file.
    #
    # Path(path).write_bytes() creates/overwrites
    # the specified file.

    Path(path).write_bytes(plaintext)
