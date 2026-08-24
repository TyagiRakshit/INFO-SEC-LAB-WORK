import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# User Input
message_str = input("Enter message: ")
message_bytes = message_str.encode('utf-8')

p = getPrime(512)
g = 2
x = random.randint(1, p - 2)
h = pow(g, x, p)

print(f"Prime (p)        : {p}")
print(f"Generator (g)    : {g}")
print(f"Public Key (h)   : {h}\n")


m = bytes_to_long(message_bytes)
k = random.randint(1, p - 2)

c1 = pow(g, k, p)

s = pow(h, k, p)
c2 = (m * s) % p

print("--- ENCRYPTED CIPHERTEXT ---")
print(f"c1 (Ephemeral)   : {c1}")
print(f"c2 (Encrypted)   : {c2}\n")


s_decrypt = pow(c1, x, p)
s_inv = pow(s_decrypt, -1, p)
m_decrypted = (c2 * s_inv) % p

plaintext = long_to_bytes(m_decrypted).decode('utf-8')

print("--- DECRYPTED RESULTS ---")
print(f"Decrypted Text   : {plaintext}")