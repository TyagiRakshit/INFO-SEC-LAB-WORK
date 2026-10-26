
# ============================================================
# LAB 8 - CODE 2
# PAILLIER-BASED ENCRYPTED INDEX SEARCH
# ============================================================
#
# AIM:
# To encrypt keywords and document IDs using Paillier
# encryption and search for matching documents.
#
# WHAT IS PAILLIER?
#
# Paillier is an asymmetric encryption algorithm.
#
# It uses:
#
# PUBLIC KEY  -> Encryption
# PRIVATE KEY -> Decryption
#
# Paillier also supports additive homomorphic encryption,
# which we studied in Lab 7.
#
# IMPORTANT:
#
# This program demonstrates encrypted storage of
# keywords and document IDs.
#
# During searching, it DECRYPTS the keywords to compare
# them with the query.
#
# Therefore, this is a simplified lab demonstration,
# NOT a complete privacy-preserving PKSE implementation.
#
# BASIC FLOW:
#
# 1. Create 10 documents.
# 2. Generate Paillier public and private keys.
# 3. Convert keywords into integers.
# 4. Create an inverted index.
# 5. Encrypt keywords and document IDs.
# 6. Take a search query.
# 7. Encrypt the query.
# 8. Decrypt and compare keywords.
# 9. Return matching document IDs.
# 10. Display matching documents.
#
# ============================================================


# Install the required library if needed:
#
# pip install phe

# Import Paillier encryption from the phe library.

from phe import paillier


# ============================================================
# STEP 1: CREATE DATASET
# ============================================================

# Create 10 documents using a dictionary.
#
# Key   = Document ID
# Value = Document content

documents = {
    1: "python is easy",
    2: "python is used in security",
    3: "encryption protects data",
    4: "cloud stores data",
    5: "python supports encryption",
    6: "security is important",
    7: "data is stored securely",
    8: "search finds documents",
    9: "cloud security is useful",
    10: "python makes searching easy"
}


# ============================================================
# STEP 2: GENERATE PAILLIER KEYS
# ============================================================

# Generate a Paillier public-private key pair.
#
# The library handles the mathematical operations
# required for Paillier key generation.
#
# Public key:
# Used to encrypt integers.
#
# Private key:
# Used to decrypt encrypted integers.

public_key, private_key = paillier.generate_paillier_keypair()


# ============================================================
# STEP 3: CONVERT WORD INTO INTEGER
# ============================================================

def to_number(word):

    # Paillier encrypts numbers, not normal text strings.
    #
    # Therefore, we must convert each word into an integer.
    #
    # Example:
    # "abc"
    #
    # ASCII values:
    # a = 97
    # b = 98
    # c = 99
    #
    # First convert the word into bytes.
    #
    # "abc" -> b'abc'
    #
    # Then convert bytes into an integer.

    word_bytes = word.lower().encode("utf-8")

    # int.from_bytes() converts bytes into an integer.
    #
    # "big" means the first byte is the most significant.
    #
    # For example:
    #
    # b'abc' -> 6382179

    number = int.from_bytes(word_bytes, "big")

    return number


# ============================================================
# STEP 4: PAILLIER ENCRYPTION
# ============================================================

def encrypt(data):

    # Encrypt an integer using the public key.
    #
    # Paillier encryption is probabilistic.
    #
    # This means encrypting the same integer twice
    # normally produces different ciphertexts.

    encrypted_data = public_key.encrypt(data)

    return encrypted_data


# ============================================================
# STEP 5: PAILLIER DECRYPTION
# ============================================================

def decrypt(encrypted_data):

    # Decrypt using the private key.
    #
    # The original integer is recovered.

    original_data = private_key.decrypt(encrypted_data)

    return original_data


# ============================================================
# STEP 6: CREATE INVERTED INDEX
# ============================================================

# An inverted index maps words to document IDs.
#
# Example:
#
# "python" -> [1, 2, 5, 10]
# "cloud"  -> [4, 9]
#
# This helps us find matching documents.

index = {}


# Process each document.
for doc_id, text in documents.items():

    # Convert text into lowercase and split into words.
    #
    # Example:
    # "Python is Easy"
    #
    # becomes:
    # ["python", "is", "easy"]
    #
    # set() removes duplicate words.

    unique_words = set(text.lower().split())


    # Process every unique word.
    for word in unique_words:

        # Check whether word already exists in index.
        #
        # If not, create an empty list.

        if word not in index:
            index[word] = []

        # Add current document ID to that word's list.
        index[word].append(doc_id)


# ============================================================
# STEP 7: ENCRYPT THE INVERTED INDEX
# ============================================================

# This dictionary stores:
#
# Encrypted keyword -> List of encrypted document IDs

encrypted_index = {}


# Process each word and its document IDs.
for word, doc_ids in index.items():

    # --------------------------------------------------------
    # ENCRYPT KEYWORD
    # --------------------------------------------------------

    # Convert word into integer because Paillier
    # accepts numeric plaintext values.

    word_number = to_number(word)

    # Encrypt the integer using public key.
    encrypted_word = encrypt(word_number)


    # --------------------------------------------------------
    # ENCRYPT DOCUMENT IDs
    # --------------------------------------------------------

    # Empty list for encrypted document IDs.
    encrypted_ids = []

    # Encrypt each document ID separately.
    for doc_id in doc_ids:

        encrypted_id = encrypt(doc_id)

        encrypted_ids.append(encrypted_id)


    # Store encrypted keyword and encrypted IDs.
    encrypted_index[encrypted_word] = encrypted_ids


# ============================================================
# STEP 8: SEARCH THE ENCRYPTED INDEX
# ============================================================

def search(query):

    # --------------------------------------------------------
    # CONVERT AND ENCRYPT SEARCH QUERY
    # --------------------------------------------------------

    # Convert query into integer.
    #
    # Example:
    # "python" -> integer representation

    query_number = to_number(query)

    # Encrypt the query using the public key.
    encrypted_query = encrypt(query_number)


    # --------------------------------------------------------
    # COMPARE KEYWORDS
    # --------------------------------------------------------

    # Check every encrypted keyword in the index.
    for encrypted_word, encrypted_ids in encrypted_index.items():

        # IMPORTANT:
        #
        # Paillier uses random encryption.
        #
        # Therefore, encrypting the same word twice
        # generally gives different ciphertexts.
        #
        # Direct comparison like:
        #
        # encrypted_word == encrypted_query
        #
        # will not reliably identify equal plaintexts.
        #
        # So this demonstration DECRYPTS both values
        # before comparing them.
        #
        # This requires the private key.

        original_word_number = decrypt(encrypted_word)

        original_query_number = decrypt(encrypted_query)


        # Compare decrypted integer values.
        if original_word_number == original_query_number:

            # ------------------------------------------------
            # DECRYPT MATCHING DOCUMENT IDs
            # ------------------------------------------------

            results = []

            for encrypted_id in encrypted_ids:

                # Recover original document ID.
                doc_id = decrypt(encrypted_id)

                # Add matching ID to results.
                results.append(doc_id)

            # Return matching document IDs.
            return results


    # If no matching keyword is found,
    # return an empty list.
    return []


# ============================================================
# STEP 9: USER SEARCH
# ============================================================

# Take search query from user.
#
# lower() makes search case-insensitive.
# strip() removes extra spaces at both ends.

query = input("Enter word to search: ").lower().strip()

# Search encrypted index.
results = search(query)


# ============================================================
# STEP 10: DISPLAY MATCHING DOCUMENTS
# ============================================================

if results:

    print("\nMatching Documents:")

    # Display each matching document.
    for doc_id in results:

        print(
            "Document",
            doc_id,
            ":",
            documents[doc_id]
        )

else:

    print("No matching documents")
