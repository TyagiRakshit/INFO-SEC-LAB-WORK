from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


message = b"Secure Transactions"


# Receiver's ECC keys
private_key = ECC.generate(curve="P-256")
public_key = private_key.public_key()


# Sender's ECC keys
sender_private = ECC.generate(curve="P-256")
sender_public = sender_private.public_key()


# Sender creates shared secret using:
# sender private key + receiver public key
sender_secret = key_agreement(
    static_priv=sender_private,
    static_pub=public_key,
    kdf=lambda x: SHA256.new(x).digest()
)


# Encrypt
cipher = AES.new(sender_secret, AES.MODE_EAX)

ciphertext, tag = cipher.encrypt_and_digest(message)


# Receiver creates the SAME shared secret using:
# receiver private key + sender public key
receiver_secret = key_agreement(
    static_priv=private_key,
    static_pub=sender_public,
    kdf=lambda x: SHA256.new(x).digest()
)


# Decrypt
cipher = AES.new(
    receiver_secret,
    AES.MODE_EAX,
    nonce=cipher.nonce
)

plaintext = cipher.decrypt_and_verify(ciphertext, tag)


print("Original message :", message.decode())
print("Ciphertext       :", ciphertext.hex())
print("Decrypted message:", plaintext.decode())
