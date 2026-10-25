from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# ============================================================
# 1. RSA KEY GENERATION
# ============================================================

def generate_rsa_keys():
    # Q4 specifically says RSA 2048-bit
    # If the question gives another size, change 2048.
    private_key = RSA.generate(2048)

    # Public key is obtained from private key
    public_key = private_key.public_key()

    return private_key, public_key


# ============================================================
# 2. RSA HYBRID FILE ENCRYPTION
# ============================================================

def rsa_encrypt_file(data, public_key):

    # --------------------------------------------------------
    # Generate a random AES-256 session key
    # --------------------------------------------------------
    # AES encrypts the ACTUAL FILE.
    #
    # Why not encrypt the entire file using RSA?
    # RSA is not designed for large data/files.
    # Therefore:
    #
    #       File ----AES----> Ciphertext
    #                    ^
    #                    |
    #              AES session key
    #                    ^
    #                    |
    #             RSA encrypts key
    #
    # --------------------------------------------------------

    session_key = get_random_bytes(32)     # 32 bytes = 256 bits


    # --------------------------------------------------------
    # Encrypt AES session key using RSA PUBLIC KEY
    # --------------------------------------------------------

    rsa_cipher = PKCS1_OAEP.new(public_key)

    encrypted_session_key = rsa_cipher.encrypt(session_key)


    # --------------------------------------------------------
    # Encrypt actual file using AES-GCM
    # --------------------------------------------------------

    # 12-byte nonce is commonly used with GCM
    nonce = get_random_bytes(12)

    aes_cipher = AES.new(
        session_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    ciphertext, tag = aes_cipher.encrypt_and_digest(data)


    # Return everything receiver needs
    return encrypted_session_key, nonce, tag, ciphertext


# ============================================================
# 3. RSA FILE DECRYPTION
# ============================================================

def rsa_decrypt_file(
        encrypted_session_key,
        nonce,
        tag,
        ciphertext,
        private_key):

    # --------------------------------------------------------
    # Recover AES session key using RSA PRIVATE KEY
    # --------------------------------------------------------

    rsa_cipher = PKCS1_OAEP.new(private_key)

    session_key = rsa_cipher.decrypt(
        encrypted_session_key
    )


    # --------------------------------------------------------
    # Decrypt the actual file using AES
    # --------------------------------------------------------

    aes_cipher = AES.new(
        session_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = aes_cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext


# ============================================================
# 4. ECC KEY GENERATION
# ============================================================

def generate_ecc_keys():

    # Q4 specifies secp256r1.
    #
    # In PyCryptodome:
    # secp256r1 = P-256
    #
    # If the question specifies another supported curve,
    # change "P-256" accordingly.

    private_key = ECC.generate(
        curve="P-256"
    )

    public_key = private_key.public_key()

    return private_key, public_key


# ============================================================
# 5. SHA-256 KDF
# ============================================================

def kdf(shared_secret):

    # ECDH produces a shared secret.
    # SHA-256 converts that shared secret into
    # a usable AES key.

    return SHA256.new(shared_secret).digest()


# ============================================================
# 6. ECC HYBRID FILE ENCRYPTION
# ============================================================

def ecc_encrypt_file(data, receiver_public_key):

    # --------------------------------------------------------
    # Generate temporary / ephemeral ECC key pair
    # --------------------------------------------------------
    #
    # Sender creates a new ECC key pair for this transfer.
    #
    # sender_private  -> kept secret
    # sender_public   -> sent to receiver
    #
    # --------------------------------------------------------

    ephemeral_private = ECC.generate(
        curve="P-256"
    )

    ephemeral_public = ephemeral_private.public_key()


    # --------------------------------------------------------
    # ECDH KEY AGREEMENT
    # --------------------------------------------------------
    #
    # Sender:
    #
    #     sender private key
    #              +
    #     receiver public key
    #              |
    #              v
    #        shared secret
    #
    # Receiver will independently calculate the SAME
    # shared secret using:
    #
    #     receiver private key
    #              +
    #     sender ephemeral public key
    #
    # --------------------------------------------------------

    session_key = key_agreement(
        static_priv=ephemeral_private,
        static_pub=receiver_public_key,
        kdf=kdf
    )


    # --------------------------------------------------------
    # Encrypt actual file using AES-GCM
    # --------------------------------------------------------

    nonce = get_random_bytes(12)

    aes_cipher = AES.new(
        session_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    ciphertext, tag = aes_cipher.encrypt_and_digest(data)


    # Receiver needs the ephemeral public key,
    # nonce, tag and ciphertext.
    return ephemeral_public, nonce, tag, ciphertext


# ============================================================
# 7. ECC FILE DECRYPTION
# ============================================================

def ecc_decrypt_file(
        ephemeral_public,
        nonce,
        tag,
        ciphertext,
        receiver_private_key):

    # --------------------------------------------------------
    # Receiver calculates the SAME shared secret
    # --------------------------------------------------------

    session_key = key_agreement(
        static_priv=receiver_private_key,
        static_pub=ephemeral_public,
        kdf=kdf
    )


    # --------------------------------------------------------
    # Decrypt actual file using AES-GCM
    # --------------------------------------------------------

    aes_cipher = AES.new(
        session_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = aes_cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext


# ============================================================
# MAIN PROGRAM
# ============================================================

# ------------------------------------------------------------
# STEP 1: Generate RSA keys
# ------------------------------------------------------------

rsa_private, rsa_public = generate_rsa_keys()


# ------------------------------------------------------------
# STEP 2: Generate ECC keys
# ------------------------------------------------------------

ecc_private, ecc_public = generate_ecc_keys()


# ------------------------------------------------------------
# STEP 3: Read the file
# ------------------------------------------------------------

filename = input("Enter file name: ")

with open(filename, "rb") as file:
    data = file.read()


# ============================================================
# RSA FILE TRANSFER
# ============================================================

print("\n========== RSA FILE TRANSFER ==========")

# Sender encrypts the file using receiver's RSA public key
rsa_encrypted = rsa_encrypt_file(
    data,
    rsa_public
)

# Receiver decrypts using RSA private key
rsa_decrypted = rsa_decrypt_file(
    *rsa_encrypted,
    rsa_private
)

print("RSA Decryption:", "SUCCESS" if rsa_decrypted == data else "FAILED")


# ============================================================
# ECC FILE TRANSFER
# ============================================================

print("\n========== ECC FILE TRANSFER ==========")

# Sender encrypts using receiver's ECC public key
ecc_encrypted = ecc_encrypt_file(
    data,
    ecc_public
)

# Receiver decrypts using receiver's ECC private key
ecc_decrypted = ecc_decrypt_file(
    *ecc_encrypted,
    ecc_private
)

print("ECC Decryption:", "SUCCESS" if ecc_decrypted == data else "FAILED")


