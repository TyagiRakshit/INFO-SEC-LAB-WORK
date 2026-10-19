
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

# 1. Dataset: 10 documents
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

key = get_random_bytes(16)  # AES-128 key

# 2. AES encryption
def encrypt(data):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce, ct, tag

# 3. AES decryption
def decrypt(data):
    nonce, ct, tag = data
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()

# 4. Generate a searchable token for each word
def token(word):
    h = HMAC.new(key, word.lower().encode(), SHA256)
    return h.digest()

# 5. Create encrypted inverted index
index = {}
encrypted_docs = {}

for doc_id, text in documents.items():
    encrypted_docs[doc_id] = encrypt(text)

    for word in set(text.lower().split()):
        t = token(word)
        if t not in index:
            index[t] = []
        index[t].append(encrypt(doc_id))

# 6. Search encrypted index
def search(query):
    t = token(query)

    if t not in index:
        return []

    results = []
    for encrypted_id in index[t]:
        doc_id = decrypt(encrypted_id)
        results.append((doc_id, decrypt(encrypted_docs[doc_id])))

    return results

# 7. User search
query = input("Enter word to search: ")

results = search(query)

if results:
    for doc_id, text in results:
        print(doc_id, ":", text)
else:
    print("No matching documents")
