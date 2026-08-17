# Compare the encryption and decryption times for DES and AES-256 for the message
# "Performance Testing of Encryption Algorithms". Use a standard implementation and report
# your findings.
# Compare the encryption and decryption times for DES and AES-256
# Message: "Performance Testing of Encryption Algorithms"

import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

message = "Performance Testing of Encryption Algorithms"
plaintext_bytes = message.encode('utf-8')

# Keys (Must match cipher key-length constraints)
des_key = b"A1B2C3D4"                  # 8 bytes (64-bit key, 56-bit effective)
aes256_key = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes (256-bit key)

ITERATIONS = 10000


des_padded = pad(plaintext_bytes, DES.block_size)

start_time = time.perf_counter()
for _ in range(ITERATIONS):
    des_cipher = DES.new(des_key, DES.MODE_ECB)
    des_ciphertext = des_cipher.encrypt(des_padded)
des_enc_time = (time.perf_counter() - start_time) / ITERATIONS

# DES Decryption
start_time = time.perf_counter()
for _ in range(ITERATIONS):
    des_decipher = DES.new(des_key, DES.MODE_ECB)
    des_decrypted_padded = des_decipher.decrypt(des_ciphertext)
    _ = unpad(des_decrypted_padded, DES.block_size)
des_dec_time = (time.perf_counter() - start_time) / ITERATIONS

aes_padded = pad(plaintext_bytes, AES.block_size)

start_time = time.perf_counter()
for _ in range(ITERATIONS):
    aes_cipher = AES.new(aes256_key, AES.MODE_ECB)
    aes_ciphertext = aes_cipher.encrypt(aes_padded)
aes_enc_time = (time.perf_counter() - start_time) / ITERATIONS

start_time = time.perf_counter()
for _ in range(ITERATIONS):
    aes_decipher = AES.new(aes256_key, AES.MODE_ECB)
    aes_decrypted_padded = aes_decipher.decrypt(aes_ciphertext)
    _ = unpad(aes_decrypted_padded, AES.block_size)
aes_dec_time = (time.perf_counter() - start_time) / ITERATIONS


print(f"Message: '{message}' ({len(plaintext_bytes)} bytes)\n")

print(f"{'Algorithm':<10} | {'Key Size':<10} | {'Block Size':<10} | {'Avg Encrypt Time (μs)':<22} | {'Avg Decrypt Time (μs)':<22}")
print("-" * 85)
print(f"{'DES':<10} | {'56-bit':<10} | {'64-bit':<10} | {des_enc_time * 1e6:<22.4f} | {des_dec_time * 1e6:<22.4f}")
print(f"{'AES-256':<10} | {'256-bit':<10} | {'128-bit':<10} | {aes_enc_time * 1e6:<22.4f} | {aes_dec_time * 1e6:<22.4f}")