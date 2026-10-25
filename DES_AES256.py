# Compare the encryption and decryption times for DES and AES-256 for the message
# "Performance Testing of Encryption Algorithms". Use a standard implementation and report
# your findings.
# Compare the encryption and decryption times for DES and AES-256
# Message: "Performance Testing of Encryption Algorithms"
import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

message = "Performance Testing of Encryption Algorithms"
data = message.encode()

des_key = b"A1B2C3D4"
aes_key = b"0123456789ABCDEF0123456789ABCDEF"

N = 10000


# ---------------- DES ----------------

start = time.perf_counter()

for i in range(N):
    cipher = DES.new(des_key, DES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data, DES.block_size))

des_encrypt_time = (time.perf_counter() - start) / N


start = time.perf_counter()

for i in range(N):
    cipher = DES.new(des_key, DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)

des_decrypt_time = (time.perf_counter() - start) / N


# ---------------- AES-256 ----------------

start = time.perf_counter()

for i in range(N):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data, AES.block_size))

aes_encrypt_time = (time.perf_counter() - start) / N


start = time.perf_counter()

for i in range(N):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

aes_decrypt_time = (time.perf_counter() - start) / N


# ---------------- Results ----------------

print("\nPerformance Comparison")
print("----------------------")
print(f"DES     Encryption: {des_encrypt_time * 1e6:.2f} microseconds")
print(f"DES     Decryption: {des_decrypt_time * 1e6:.2f} microseconds")
print(f"AES-256 Encryption: {aes_encrypt_time * 1e6:.2f} microseconds")
print(f"AES-256 Decryption: {aes_decrypt_time * 1e6:.2f} microseconds")
