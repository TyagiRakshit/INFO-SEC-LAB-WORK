# pip install phe

from phe import paillier

# 1. Create 10 documents
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

# 2. Generate public and private keys
public_key, private_key = paillier.generate_paillier_keypair()

# Convert a word into an integer
def to_number(word):
    return int.from_bytes(word.lower().encode(), "big")

# Encryption
def encrypt(data):
    return public_key.encrypt(data)

# Decryption
def decrypt(data):
    return private_key.decrypt(data)

# 3. Create encrypted inverted index
index = {}

for doc_id, text in documents.items():
    for word in set(text.lower().split()):
        number = to_number(word)

        if word not in index:
            index[word] = []

        index[word].append(doc_id)

# Encrypt keywords and document IDs
encrypted_index = {}

for word, ids in index.items():
    encrypted_word = encrypt(to_number(word))
    encrypted_ids = [encrypt(i) for i in ids]
    encrypted_index[encrypted_word] = encrypted_ids

# 4. Search encrypted index
def search(query):
    encrypted_query = encrypt(to_number(query))

    for encrypted_word, encrypted_ids in encrypted_index.items():

        # Decrypt to compare the keywords
        if decrypt(encrypted_word) == decrypt(encrypted_query):
            return [decrypt(i) for i in encrypted_ids]

    return []

# 5. User input
query = input("Enter word to search: ").lower()
results = search(query)

if results:
    for doc_id in results:
        print("Document", doc_id, ":", documents[doc_id])
else:
    print("No matching documents")
