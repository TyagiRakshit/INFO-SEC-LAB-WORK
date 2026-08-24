import os
import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ---------------- KEY GENERATION ----------------

print("--- 1. KEY GENERATION ---")

# RSA 2048-bit Key Generation
start = time.perf_counter()
rsa_priv = RSA.generate(2048)
rsa_keygen_time = time.perf_counter() - start
rsa_pub = rsa_priv.public_key()

# ECC secp256r1 Key Generation
start = time.perf_counter()
ecc_priv = ECC.generate(curve="P-256")
ecc_keygen_time = time.perf_counter() - start
ecc_pub = ecc_priv.public_key()

print(f"RSA-2048 KeyGen Time : {rsa_keygen_time * 1e3:.2f} ms")
print(f"ECC-P256 KeyGen Time : {ecc_keygen_time * 1e3:.2f} ms\n")


# ---------------- RSA HYBRID FILE TRANSFER ----------------

def rsa_encrypt_file(file_bytes, public_key):
    # Encrypt AES session key using RSA-OAEP
    session_key = get_random_bytes(32)  # AES-256 key
    rsa_cipher = PKCS1_OAEP.new(public_key)
    enc_session_key = rsa_cipher.encrypt(session_key)

    # Encrypt payload using AES-GCM
    nonce = get_random_bytes(12)
    aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_bytes)

    return enc_session_key, nonce, tag, ciphertext


def rsa_decrypt_file(enc_session_key, nonce, tag, ciphertext, private_key):
    # Decrypt AES session key using RSA private key
    rsa_cipher = PKCS1_OAEP.new(private_key)
    session_key = rsa_cipher.decrypt(enc_session_key)

    # Decrypt payload using AES-GCM
    aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    return aes_cipher.decrypt_and_verify(ciphertext, tag)


# ---------------- ECC (ECDH) HYBRID FILE TRANSFER ----------------

def kdf(shared_secret):
    return SHA256.new(shared_secret).digest()


def ecc_encrypt_file(file_bytes, recipient_pub_key):
    # Ephemeral key pair generation for ECDH
    ephemeral_priv = ECC.generate(curve="P-256")
    ephemeral_pub = ephemeral_priv.public_key()

    # Shared secret derivation via ECDH
    session_key = key_agreement(
        static_priv=ephemeral_priv,
        static_pub=recipient_pub_key,
        kdf=kdf
    )

    # Encrypt payload using AES-GCM
    nonce = get_random_bytes(12)
    aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_bytes)

    return ephemeral_pub, nonce, tag, ciphertext


def ecc_decrypt_file(ephemeral_pub, nonce, tag, ciphertext, recipient_priv_key):
    # Recipient derives same shared secret using ephemeral public key
    session_key = key_agreement(
        static_priv=recipient_priv_key,
        static_pub=ephemeral_pub,
        kdf=kdf
    )

    # Decrypt payload using AES-GCM
    aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    return aes_cipher.decrypt_and_verify(ciphertext, tag)


# ---------------- BENCHMARKING ----------------

file_sizes = [1, 10]  # MB

print("--- 2. FILE ENCRYPTION & DECRYPTION BENCHMARK ---")
for size in file_sizes:
    print(f"\n[ Testing File Size: {size} MB ]")
    data = os.urandom(size * 1024 * 1024)

    # Benchmark RSA Hybrid
    t0 = time.perf_counter()
    rsa_enc_data = rsa_encrypt_file(data, rsa_pub)
    rsa_enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    rsa_dec_data = rsa_decrypt_file(*rsa_enc_data, rsa_priv)
    rsa_dec_time = time.perf_counter() - t0
    assert rsa_dec_data == data, "RSA File Decryption Failed!"

    # Benchmark ECC Hybrid
    t0 = time.perf_counter()
    ecc_enc_data = ecc_encrypt_file(data, ecc_pub)
    ecc_enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    ecc_dec_data = ecc_decrypt_file(*ecc_enc_data, ecc_priv)
    ecc_dec_time = time.perf_counter() - t0
    assert ecc_dec_data == data, "ECC File Decryption Failed!"

    print(f"RSA-2048 Encrypt Time : {rsa_enc_time * 1e3:.2f} ms | Decrypt Time : {rsa_dec_time * 1e3:.2f} ms")
    print(f"ECC-P256 Encrypt Time : {ecc_enc_time * 1e3:.2f} ms | Decrypt Time : {ecc_dec_time * 1e3:.2f} ms")