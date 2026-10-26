
# ============================================================
# LAB 8 - CODE 1
# SYMMETRIC SEARCHABLE ENCRYPTION (SSE)
# USING AES-GCM AND HMAC-SHA256
# ============================================================
#
# AIM:
# To encrypt documents and search for a word using
# a protected inverted index.
#
# WHAT IS SEARCHABLE ENCRYPTION?
#
# Searchable Encryption allows us to search protected
# documents without decrypting the entire dataset.
#
# WHAT IS SSE?
#
# SSE stands for Symmetric Searchable Encryption.
#
# It uses secret-key cryptography to protect data
# and generate searchable representations.
#
# IN THIS PROGRAM:
#
# AES-GCM:
#   Encrypts document contents and document IDs.
#
# HMAC-SHA256:
#   Generates a consistent search token for each word.
#
# INVERTED INDEX:
#   Maps each protected keyword token to the encrypted
#   IDs of documents containing that word.
#
# EXAMPLE:
#
# doc1 = "python is easy"
# doc2 = "python is used in security"
#
# Search: "python"
#
# Result:
# doc1 and doc2
#
# IMPORTANT:
# We use the SAME secret key to generate search tokens.
# Therefore, the same word produces the same HMAC token.
#
# ============================================================


# Import required libraries

# AES is used for symmetric encryption
from Crypto.Cipher import AES

# Generates cryptographically secure random bytes
from Crypto.Random import get_random_bytes

# HMAC creates keyed hashes.
# SHA256 is the hash algorithm used inside HMAC.
from Crypto.Hash import HMAC, SHA256


# ============================================================
# STEP 1: CREATE DATASET
# ============================================================

# Create 10 documents.
#
# A dictionary stores data as key-value pairs.
#
# Here:
# Key   = Document ID
# Value = Document content

documents = {
    "doc1": "python is easy",
    "doc2": "python is used in security",
    "doc3": "aes provides encryption",
    "doc4": "security protects data",
    "doc5": "python supports encryption",
    "doc6": "cloud stores data",
    "doc7": "encryption protects files",
    "doc8": "search finds documents",
    "doc9": "cloud security is important",
    "doc10": "python makes searching easy"
}


# ============================================================
# STEP 2: GENERATE SECRET KEY
# ============================================================

# Generate a random 16-byte secret key.
#
# 1 byte = 8 bits
#
# 16 bytes = 128 bits
#
# Therefore, this is an AES-128 key.
#
# This demonstration also uses the key for HMAC.
# In real systems, separate derived keys are preferable.

key = get_random_bytes(16)


# ============================================================
# STEP 3: AES ENCRYPTION FUNCTION
# ============================================================

def encrypt(data):

    # Create an AES cipher using GCM mode.
    #
    # AES = Advanced Encryption Standard
    #
    # GCM = Galois/Counter Mode
    #
    # GCM provides:
    #
    # 1. Confidentiality - Hides the plaintext.
    # 2. Integrity - Detects unauthorized modification.
    #
    # A fresh nonce is generated automatically.

    cipher = AES.new(key, AES.MODE_GCM)

    # Convert the input string into bytes.
    #
    # Example:
    # "python" -> b'python'
    #
    # encrypt_and_digest() returns:
    #
    # ciphertext = Encrypted data
    # tag        = Authentication tag
    #
    # The tag is used to detect tampering.

    ciphertext, tag = cipher.encrypt_and_digest(
        data.encode("utf-8")
    )

    # Return three values:
    #
    # nonce      = Unique value used for encryption
    # ciphertext = Encrypted data
    # tag        = Authentication value
    #
    # All three are needed for decryption/verification.

    return cipher.nonce, ciphertext, tag


# ============================================================
# STEP 4: AES DECRYPTION FUNCTION
# ============================================================

def decrypt(encrypted_data):

    # Extract the three stored values.

    nonce, ciphertext, tag = encrypted_data

    # Create AES cipher using the SAME secret key
    # and the nonce used during encryption.

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    # Decrypt and verify the authentication tag.
    #
    # If ciphertext or tag has been modified,
    # verification fails and an exception is raised.

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    # Convert bytes back into a normal string.
    #
    # Example:
    # b'python' -> 'python'

    return plaintext.decode("utf-8")


# ============================================================
# STEP 5: GENERATE SEARCHABLE TOKEN
# ============================================================

def token(word):

    # Convert the word into lowercase.
    #
    # Example:
    # "Python" -> "python"
    #
    # This makes searches case-insensitive.

    word = word.lower()

    # Convert the word into bytes.
    word_bytes = word.encode("utf-8")

    # Generate HMAC using the secret key and SHA-256.
    #
    # HMAC = Hash-based Message Authentication Code.
    #
    # Unlike a normal SHA-256 hash, HMAC uses a secret key.
    #
    # The same word + same key gives the same token.
    #
    # Different words normally produce different tokens.

    hmac_object = HMAC.new(
        key,
        word_bytes,
        digestmod=SHA256
    )

    # digest() returns the HMAC as bytes.
    #
    # We use this as the searchable keyword token.

    return hmac_object.digest()


# ============================================================
# STEP 6: CREATE THE PROTECTED INVERTED INDEX
# ============================================================

# Dictionary to store:
#
# Search Token -> List of encrypted document IDs
#
# Example (conceptual):
#
# token("python") -> [Encrypted doc1, Encrypted doc2]
#
# The actual dictionary keys are HMAC byte strings.

index = {}

# Dictionary to store encrypted document contents.
#
# Example:
# "doc1" -> (nonce, ciphertext, tag)
#
# NOTE:
# The document IDs used as dictionary keys remain visible
# in this simple demonstration.

encrypted_docs = {}


# Process every document in the dataset.

for doc_id, text in documents.items():

    # Encrypt the complete document.
    #
    # Example:
    # "python is easy" becomes encrypted bytes.
    #
    # Store encrypted data using the document ID.

    encrypted_docs[doc_id] = encrypt(text)


    # --------------------------------------------------------
    # EXTRACT UNIQUE WORDS
    # --------------------------------------------------------

    # text.lower() converts the document to lowercase.
    #
    # split() separates the text into words.
    #
    # Example:
    # "python is easy"
    #
    # becomes:
    # ["python", "is", "easy"]
    #
    # set() removes duplicate words.
    #
    # Example:
    # ["python", "python", "easy"]
    #
    # becomes a set containing:
    # {"python", "easy"}
    #
    # We use set() so a document ID is added only once
    # for each word in that document.

    unique_words = set(text.lower().split())


    # Process each unique word.
    for word in unique_words:

        # Generate HMAC search token for the word.

        search_token = token(word)


        # ----------------------------------------------------
        # ADD TOKEN TO INDEX
        # ----------------------------------------------------

        # Check whether the token already exists.
        #
        # If it is new, create an empty list.

        if search_token not in index:
            index[search_token] = []


        # Encrypt the document ID.
        #
        # Example:
        # "doc1" becomes (nonce, ciphertext, tag)

        encrypted_id = encrypt(doc_id)

        # Store encrypted document ID under the token.
        #
        # This creates the protected inverted index.

        index[search_token].append(encrypted_id)


# ============================================================
# STEP 7: SEARCH THE PROTECTED INDEX
# ============================================================

def search(query):

    # Convert the search query into an HMAC token.
    #
    # Example:
    # Query = "python"
    #
    # We calculate token("python").
    #
    # Because HMAC is deterministic for a fixed key
    # and input, this matches the stored keyword token.

    search_token = token(query)


    # --------------------------------------------------------
    # CHECK WHETHER TOKEN EXISTS
    # --------------------------------------------------------

    # If the token is not in the index,
    # no document contains that exact indexed word.

    if search_token not in index:
        return []


    # Empty list to store matching documents.

    results = []


    # --------------------------------------------------------
    # RETRIEVE MATCHING DOCUMENTS
    # --------------------------------------------------------

    # Get all encrypted document IDs for the token.

    for encrypted_id in index[search_token]:

        # Decrypt the document ID.
        #
        # Example:
        # Encrypted ID -> "doc1"

        doc_id = decrypt(encrypted_id)

        # Use document ID to locate encrypted document.
        encrypted_document = encrypted_docs[doc_id]

        # Decrypt the document content.
        #
        # Example:
        # Encrypted data -> "python is easy"

        document_text = decrypt(encrypted_document)

        # Store document ID and its original content.
        #
        # A tuple contains two values:
        # (document ID, document text)

        results.append((doc_id, document_text))


    # Return all matching documents.
    return results


# ============================================================
# STEP 8: USER SEARCH
# ============================================================

# Take a word from the user.
query = input("Enter word to search: ").strip()

# Call search function.
results = search(query)


# ============================================================
# STEP 9: DISPLAY SEARCH RESULTS
# ============================================================

# Check whether any matching documents were found.

if results:

    print("\nMatching Documents:")

    # Display document ID and decrypted content.
    for doc_id, text in results:
        print(doc_id, ":", text)

else:

    # Display when no documents match.
    print("No matching documents")
