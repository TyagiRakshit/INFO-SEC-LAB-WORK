
# ============================================================
# INFORMATION SECURITY EXAM TOOLKIT
# FILE: searchable.py
#
# LAB 8 - SYMMETRIC SEARCHABLE ENCRYPTION (SSE)
#
# TOPICS:
# 1. AES-256-GCM Encryption
# 2. HMAC-SHA256 Search Tokens
# 3. Inverted Index
# 4. Keyword Search
# 5. Decryption of Matching Documents
# ============================================================
#
# AIM:
# To encrypt documents and search them using keywords
# without decrypting the entire dataset.
#
# ------------------------------------------------------------
# WHAT IS SEARCHABLE ENCRYPTION?
# ------------------------------------------------------------
#
# Searchable Encryption allows authorized users to
# search protected documents using special search tokens.
#
# Instead of reading every document to find a word,
# we create a searchable INDEX.
#
# ------------------------------------------------------------
# WHAT IS AN INVERTED INDEX?
# ------------------------------------------------------------
#
# An inverted index maps:
#
# WORD -> DOCUMENT IDs
#
# Example:
#
# Documents:
#
# doc1 = "python is easy"
# doc2 = "python supports encryption"
# doc3 = "cloud stores data"
#
# Normal index:
#
# "python" -> ["doc1", "doc2"]
# "cloud"  -> ["doc3"]
#
# In searchable encryption, we replace each keyword
# with a protected HMAC token.
#
# Protected index:
#
# HMAC("python") -> ["doc1", "doc2"]
# HMAC("cloud")  -> ["doc3"]
#
# ------------------------------------------------------------
# WHY USE TWO CRYPTOGRAPHIC ALGORITHMS?
# ------------------------------------------------------------
#
# AES-256-GCM:
#
# Encrypts the actual document contents.
#
# HMAC-SHA256:
#
# Generates deterministic keyword tokens.
#
# IMPORTANT:
#
# Same keyword + same HMAC key = Same search token.
#
# This allows the program to find matching keywords.
#
# AES-GCM uses a fresh nonce for encryption,
# so encrypting the same word twice generally produces
# different ciphertexts.
#
# Therefore, AES-GCM ciphertexts are not directly
# compared for keyword searches.
#
# SECURITY LIMITATION:
#
# This is a simplified SSE-style demonstration.
#
# The index still reveals document IDs, matching
# patterns, and repeated keyword searches.
#
# It is not a complete formal SSE protocol.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT LIBRARIES
# ============================================================

# secrets:
# Generates cryptographically secure random values.
#
# We can use it to generate encryption and search keys
# in the main application.

import secrets

# hmac:
# Creates keyed message authentication codes.
#
# We use HMAC to generate searchable keyword tokens.

import hmac

# hashlib:
# Provides SHA-256 hashing algorithm.

import hashlib


# Import reusable encryption functions.
#
# symmetric_encrypt():
# Encrypts data using AES, DES or 3DES.
#
# symmetric_decrypt():
# Decrypts the encrypted data.
#
# Both functions are defined in crypto_tools.py.

from crypto_tools import (
    symmetric_encrypt,
    symmetric_decrypt
)


# ============================================================
# PART 1: GENERATE SEARCHABLE KEYWORD TOKEN
# ============================================================

def keyword_token(keyword, key):

    # PARAMETERS:
    #
    # keyword:
    #   Word that we want to index or search.
    #
    # key:
    #   Secret HMAC key.
    #
    # Example:
    #
    # keyword = "Python"
    #
    # The function generates an HMAC-SHA256 token.
    #
    # The same keyword and key always generate
    # the same token.


    # --------------------------------------------------------
    # STEP 1: NORMALIZE KEYWORD
    # --------------------------------------------------------

    # casefold():
    # Converts text into a normalized lowercase-like form.
    #
    # Example:
    # "PYTHON" -> "python"
    #
    # strip():
    # Removes whitespace from beginning and end.

    normalized_word = keyword.casefold().strip()


    # --------------------------------------------------------
    # STEP 2: CONVERT WORD INTO BYTES
    # --------------------------------------------------------

    # HMAC operates on bytes.
    #
    # encode() converts string into bytes.
    #
    # Example:
    # "python" -> b"python"

    word_bytes = normalized_word.encode("utf-8")


    # --------------------------------------------------------
    # STEP 3: GENERATE HMAC-SHA256 TOKEN
    # --------------------------------------------------------

    # HMAC combines:
    #
    # 1. Secret key
    # 2. Keyword bytes
    # 3. SHA-256 hashing algorithm
    #
    # Unlike normal SHA-256, HMAC requires a secret key.
    #
    # This prevents someone without the key from
    # directly calculating the same tokens.
    #
    # However, repeated searches still reveal
    # repeated token values.

    token = hmac.new(
        key,
        word_bytes,
        hashlib.sha256
    ).hexdigest()


    # --------------------------------------------------------
    # STEP 4: RETURN TOKEN
    # --------------------------------------------------------

    # hexdigest() returns a hexadecimal string.
    #
    # SHA-256 output = 256 bits.
    #
    # 256 bits = 64 hexadecimal characters.

    return token


# ============================================================
# PART 2: BUILD SEARCHABLE INVERTED INDEX
# ============================================================

def build_index(documents, search_key):

    # PARAMETERS:
    #
    # documents:
    #   Dictionary mapping document IDs to text.
    #
    # Example:
    #
    # {
    #     "doc1": "python is easy",
    #     "doc2": "python supports encryption"
    # }
    #
    # search_key:
    #   Secret key used to generate HMAC tokens.
    #
    # OUTPUT:
    #
    # Dictionary mapping:
    #
    # Search token -> List of document IDs


    # --------------------------------------------------------
    # STEP 1: CREATE EMPTY INDEX
    # --------------------------------------------------------

    index = {}


    # --------------------------------------------------------
    # STEP 2: PROCESS EACH DOCUMENT
    # --------------------------------------------------------

    # .items() returns document ID and content.
    #
    # Example:
    #
    # doc_id = "doc1"
    # text = "python is easy"

    for doc_id, text in documents.items():


        # ----------------------------------------------------
        # STEP 3: EXTRACT UNIQUE WORDS
        # ----------------------------------------------------

        # casefold():
        # Normalizes text to lowercase-like form.
        #
        # split():
        # Separates text using whitespace.
        #
        # Example:
        # "python is easy"
        #
        # becomes:
        # ["python", "is", "easy"]
        #
        # set():
        # Removes duplicate words.
        #
        # Example:
        # "python python easy"
        #
        # becomes:
        # {"python", "easy"}
        #
        # This prevents storing the same document ID
        # repeatedly for a word within one document.

        unique_words = set(
            text.casefold().split()
        )


        # ----------------------------------------------------
        # STEP 4: CREATE TOKENS FOR WORDS
        # ----------------------------------------------------

        for word in unique_words:

            # Generate HMAC token for current word.

            token = keyword_token(
                word,
                search_key
            )


            # ------------------------------------------------
            # STEP 5: ADD DOCUMENT ID TO INDEX
            # ------------------------------------------------

            # setdefault() checks whether token exists.
            #
            # If token does not exist:
            # Create an empty list.
            #
            # Then append the document ID.
            #
            # Example:
            #
            # token("python") -> ["doc1", "doc2"]

            index.setdefault(
                token,
                []
            ).append(doc_id)


    # --------------------------------------------------------
    # STEP 6: RETURN INDEX
    # --------------------------------------------------------

    return index


# ============================================================
# PART 3: ENCRYPT ALL DOCUMENTS
# ============================================================

def encrypt_documents(documents, key):

    # PARAMETERS:
    #
    # documents:
    #   Dictionary containing original document text.
    #
    # key:
    #   AES-256 encryption key.
    #
    # IMPORTANT:
    #
    # AES-256 requires a 32-byte key.
    #
    # This function encrypts each document separately.
    #
    # A fresh AES-GCM nonce is generated for each document.


    # --------------------------------------------------------
    # STEP 1: CREATE EMPTY DICTIONARY
    # --------------------------------------------------------

    encrypted_documents = {}


    # --------------------------------------------------------
    # STEP 2: PROCESS EACH DOCUMENT
    # --------------------------------------------------------

    for doc_id, text in documents.items():

        # Convert document text into UTF-8 bytes.
        #
        # Example:
        # "python is easy" -> b"python is easy"

        document_bytes = text.encode("utf-8")


        # ----------------------------------------------------
        # STEP 3: ENCRYPT USING AES-256-GCM
        # ----------------------------------------------------

        # symmetric_encrypt() returns:
        #
        # 1. Encrypted envelope
        # 2. Encryption key
        #
        # We already supplied the key,
        # so we only need the encrypted envelope.
        #
        # AES-256:
        #   256-bit symmetric key.
        #
        # GCM:
        #   Provides confidentiality and authentication.

        envelope, _ = symmetric_encrypt(
            document_bytes,
            "AES",
            256,
            "GCM",
            key
        )


        # ----------------------------------------------------
        # STEP 4: STORE ENCRYPTED DOCUMENT
        # ----------------------------------------------------

        # Convert document ID into string.
        #
        # This makes IDs consistent during lookup.
        #
        # Store encrypted envelope under document ID.

        encrypted_documents[str(doc_id)] = envelope


    # --------------------------------------------------------
    # STEP 5: RETURN ENCRYPTED DOCUMENTS
    # --------------------------------------------------------

    return encrypted_documents


# ============================================================
# PART 4: SEARCH THE PROTECTED INDEX
# ============================================================

def query(index, word, key):

    # PARAMETERS:
    #
    # index:
    #   Protected inverted index.
    #
    # word:
    #   Keyword entered by user.
    #
    # key:
    #   Secret HMAC key used when building index.
    #
    # IMPORTANT:
    #
    # The SAME HMAC key must be used for:
    #
    # 1. Building the index.
    # 2. Searching the index.
    #
    # Otherwise, the tokens will not match.


    # --------------------------------------------------------
    # STEP 1: GENERATE QUERY TOKEN
    # --------------------------------------------------------

    search_token = keyword_token(
        word,
        key
    )


    # --------------------------------------------------------
    # STEP 2: SEARCH INDEX
    # --------------------------------------------------------

    # index.get(token, []):
    #
    # Returns matching document IDs if token exists.
    #
    # Returns an empty list if token does not exist.

    matching_ids = index.get(
        search_token,
        []
    )

    return matching_ids


# ============================================================
# PART 5: DECRYPT MATCHING DOCUMENTS
# ============================================================

def decrypt_results(ids, encrypted_documents, key):

    # PARAMETERS:
    #
    # ids:
    #   List of matching document IDs.
    #
    # encrypted_documents:
    #   Dictionary of encrypted document envelopes.
    #
    # key:
    #   AES-256 decryption key.
    #
    # OUTPUT:
    #
    # List of tuples:
    #
    # [
    #     ("doc1", "python is easy"),
    #     ("doc2", "python supports encryption")
    # ]


    # --------------------------------------------------------
    # STEP 1: CREATE EMPTY RESULTS LIST
    # --------------------------------------------------------

    results = []


    # --------------------------------------------------------
    # STEP 2: PROCESS MATCHING IDS
    # --------------------------------------------------------

    for doc_id in ids:

        # Convert document ID to string.
        #
        # The encrypted document dictionary uses
        # string IDs as keys.

        document_key = str(doc_id)


        # ----------------------------------------------------
        # STEP 3: GET ENCRYPTED DOCUMENT
        # ----------------------------------------------------

        encrypted_data = encrypted_documents[
            document_key
        ]


        # ----------------------------------------------------
        # STEP 4: DECRYPT DOCUMENT
        # ----------------------------------------------------

        # Use AES-GCM decryption.
        #
        # The function also verifies the authentication tag.
        #
        # If the ciphertext or tag has been modified,
        # an exception is raised.

        plaintext_bytes = symmetric_decrypt(
            encrypted_data,
            key
        )


        # ----------------------------------------------------
        # STEP 5: CONVERT BYTES INTO TEXT
        # --------------------------------------------------------

        plaintext = plaintext_bytes.decode("utf-8")


        # ----------------------------------------------------
        # STEP 6: STORE MATCHING RESULT
        # --------------------------------------------------------

        results.append(
            (doc_id, plaintext)
        )


    # --------------------------------------------------------
    # STEP 7: RETURN MATCHING DOCUMENTS
    # --------------------------------------------------------

    return results
