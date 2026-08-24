import random
import time
from Crypto.Hash import SHA256

# ---------------- 1. GLOBAL PARAMETERS (RFC 3526 - 2048-bit MODP Group) ----------------

# 2048-bit Prime (p) and Generator (g = 2)
P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 BCA3D2CA 604DF226 53148649 4873FAC4 F5CF1DDC
D124A6A9 3A1D6406 C4CAD64B 6A3099D5 EF6A20B9 54F84801
A6439E40 6700BA08 2E5E0B0F 3722BE75 4A060556 7D965425
7E7D207B 709A5D2C 1401636D C1392A09 6C48800D 3B1423B2
E54FE056 805973B4 19861FE6 6730D48D 757D2FEA 29DF8E76
64C4B507 1B9FE2D7 003B7E6D 303E505B C693117E 0B9105B6
1901B14E 82608556 61840049 80681073 9CE14883 658D2E49
B914E01F 7196020E FE160620 5005D5D2 9A724A47 a3864613
02DA1916 001B3408 6CE69367 1908C6EC C64279B7 550373FF
FFFFFFFF FFFFFFFF
"""
p = int(P_HEX.replace(" ", "").replace("\n", ""), 16)
g = 2


# ---------------- 2. KEY GENERATION ----------------

print("--- 1. DIFFIE-HELLMAN KEY GENERATION ---")

# Peer A generates private key (a) and public key (A = g^a mod p)
start_a = time.perf_counter()
peer_a_priv = random.randint(2, p - 2)
peer_a_pub = pow(g, peer_a_priv, p)
peer_a_keygen_time = time.perf_counter() - start_a

# Peer B generates private key (b) and public key (B = g^b mod p)
start_b = time.perf_counter()
peer_b_priv = random.randint(2, p - 2)
peer_b_pub = pow(g, peer_b_priv, p)
peer_b_keygen_time = time.perf_counter() - start_b

print(f"Peer A Key Generation Time : {peer_a_keygen_time * 1e3:.4f} ms")
print(f"Peer B Key Generation Time : {peer_b_keygen_time * 1e3:.4f} ms\n")


# ---------------- 3. SHARED SECRET DERIVATION ----------------

def kdf(shared_int):
    # Convert integer secret to bytes and hash to produce a 256-bit key
    secret_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, byteorder='big')
    return SHA256.new(secret_bytes).digest()


print("--- 2. SHARED SECRET DERIVATION ---")

# Peer A computes: S_A = (B ^ a) mod p
start_ex_a = time.perf_counter()
shared_secret_a = pow(peer_b_pub, peer_a_priv, p)
key_a = kdf(shared_secret_a)
peer_a_ex_time = time.perf_counter() - start_ex_a

# Peer B computes: S_B = (A ^ b) mod p
start_ex_b = time.perf_counter()
shared_secret_b = pow(peer_a_pub, peer_b_priv, p)
key_b = kdf(shared_secret_b)
peer_b_ex_time = time.perf_counter() - start_ex_b


# ---------------- 4. RESULTS & VERIFICATION ----------------

print(f"Peer A Exchange Time      : {peer_a_ex_time * 1e3:.4f} ms")
print(f"Peer B Exchange Time      : {peer_b_ex_time * 1e3:.4f} ms\n")

print(f"Peer A Shared Key (Hex)   : {key_a.hex().upper()}")
print(f"Peer B Shared Key (Hex)   : {key_b.hex().upper()}")

assert key_a == key_b, "Key exchange failed! Keys do not match."
print("\nSuccess: Both peers derived identical 256-bit shared keys!")