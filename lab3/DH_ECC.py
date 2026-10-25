from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256


# ============================================================
# 1. GENERATE ECC KEY PAIR FOR A PEER
# ============================================================

def generate_keys():

    # Each peer generates its own PRIVATE key.
    #
    # P-256 is the ECC curve used here.
    #
    # IMPORTANT:
    # Private key  -> must NEVER be shared
    # Public key   -> can be shared openly
    #
    # If the question specifies another ECC curve,
    # replace "P-256" with that curve.
    
    private_key = ECC.generate(curve="P-256")

    # Derive the public key from the private key.
    public_key = private_key.public_key()

    return private_key, public_key


# ============================================================
# 2. DERIVE THE SHARED SECRET
# ============================================================

def generate_shared_secret(private_key, other_public_key):

    # Diffie-Hellman / ECDH works using:
    #
    #       OUR PRIVATE KEY
    #              +
    #       OTHER PEER'S PUBLIC KEY
    #              |
    #              v
    #         SHARED SECRET
    #
    # The important property is:
    #
    # Peer A calculates:
    #
    #     A_private + B_public
    #
    # Peer B calculates:
    #
    #     B_private + A_public
    #
    # Both obtain the SAME shared secret.
    #
    # The secret itself is NEVER transmitted
    # over the insecure channel.

    shared_secret = key_agreement(
        static_priv=private_key,
        static_pub=other_public_key,

        # Convert the raw shared secret into a
        # usable cryptographic key using SHA-256.
        #
        # This is a KDF (Key Derivation Function).
        kdf=lambda x: SHA256.new(x).digest()
    )

    return shared_secret


# ============================================================
# MAIN PROGRAM
# ============================================================

print("========== DIFFIE-HELLMAN KEY EXCHANGE ==========")


# ============================================================
# STEP 1: PEER A GENERATES ITS KEYS
# ============================================================

print("\n--- Peer A Key Generation ---")

a_private, a_public = generate_keys()

print("Peer A generated:")
print("  Private Key : Generated")
print("  Public Key  : Generated")


# ============================================================
# STEP 2: PEER B GENERATES ITS KEYS
# ============================================================

print("\n--- Peer B Key Generation ---")

b_private, b_public = generate_keys()

print("Peer B generated:")
print("  Private Key : Generated")
print("  Public Key  : Generated")


# ============================================================
# STEP 3: PUBLIC KEY EXCHANGE
# ============================================================

# In a real peer-to-peer system:
#
# Peer A ------------------> Peer B
#        A public key
#
# Peer B ------------------> Peer A
#        B public key
#
# These PUBLIC keys can travel through an insecure channel.
#
# Neither peer sends its private key.
#
# For our program, we simply pass the public keys
# to the other peer.

print("\n--- Public Key Exchange ---")

print("Peer A sends its public key to Peer B")
print("Peer B sends its public key to Peer A")


# ============================================================
# STEP 4: PEER A CALCULATES SHARED SECRET
# ============================================================

print("\n--- Peer A Computes Shared Secret ---")

a_shared_secret = generate_shared_secret(
    a_private,
    b_public
)

print("Peer A computed shared secret.")


# ============================================================
# STEP 5: PEER B CALCULATES SHARED SECRET
# ============================================================

print("\n--- Peer B Computes Shared Secret ---")

b_shared_secret = generate_shared_secret(
    b_private,
    a_public
)

print("Peer B computed shared secret.")


# ============================================================
# STEP 6: VERIFY BOTH SECRETS
# ============================================================

print("\n--- Verification ---")

if a_shared_secret == b_shared_secret:
    print("SUCCESS: Both peers have the same shared secret.")
else:
    print("FAILED: Shared secrets do not match.")


# ============================================================
# OPTIONAL: DISPLAY THE SHARED KEY
# ============================================================

# In a real system, DO NOT print the shared secret.
# We are printing it here only for laboratory demonstration.

print("\nShared Secret:")
print(a_shared_secret.hex())
