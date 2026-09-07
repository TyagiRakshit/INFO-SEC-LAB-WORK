# ============================================================
# SecureCorp Secure Communication System
#
# Features:
# 1. RSA encryption/decryption
# 2. X25519 key exchange (modern Diffie-Hellman style)
# 3. Key generation and distribution
# 4. Key revocation
# 5. Scalable addition of new subsystems
# ============================================================

from cryptography.hazmat.primitives.asymmetric import rsa, x25519, padding
from cryptography.hazmat.primitives import hashes


# ============================================================
# KEY MANAGEMENT SYSTEM
# ============================================================

class KeyManager:

    def __init__(self):
        # Stores all registered systems and their keys
        self.systems = {}

    # --------------------------------------------------------
    # Generate keys for a new subsystem
    # --------------------------------------------------------

    def add_system(self, name):

        # Generate RSA private key
        rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Generate X25519 private key
        dh_private = x25519.X25519PrivateKey.generate()

        # Generate corresponding public keys
        rsa_public = rsa_private.public_key()
        dh_public = dh_private.public_key()

        # Store everything
        self.systems[name] = {
            "rsa_private": rsa_private,
            "rsa_public": rsa_public,

            "dh_private": dh_private,
            "dh_public": dh_public,

            "active": True
        }

        print(f"{name} registered successfully.")

    # --------------------------------------------------------
    # Distribute public keys
    # --------------------------------------------------------

    def get_public_keys(self, name):

        if name not in self.systems:
            raise ValueError("System not found.")

        if not self.systems[name]["active"]:
            raise ValueError("System keys have been revoked.")

        return (
            self.systems[name]["rsa_public"],
            self.systems[name]["dh_public"]
        )

    # --------------------------------------------------------
    # Revoke a system's keys
    # --------------------------------------------------------

    def revoke_system(self, name):

        if name not in self.systems:
            raise ValueError("System not found.")

        self.systems[name]["active"] = False

        print(f"{name} keys revoked.")


# ============================================================
# DIFFIE-HELLMAN STYLE KEY EXCHANGE USING X25519
# ============================================================

def perform_dh_exchange(key_manager, system_a, system_b):

    a = key_manager.systems[system_a]
    b = key_manager.systems[system_b]

    # Check whether both systems are active
    if not a["active"] or not b["active"]:
        raise ValueError("One of the systems has revoked keys.")

    # System A calculates shared secret
    shared_a = a["dh_private"].exchange(
        b["dh_public"]
    )

    # System B calculates shared secret
    shared_b = b["dh_private"].exchange(
        a["dh_public"]
    )

    print("\n--- DIFFIE-HELLMAN KEY EXCHANGE ---")

    print(
        f"{system_a} shared secret : "
        f"{shared_a.hex()[:32]}..."
    )

    print(
        f"{system_b} shared secret : "
        f"{shared_b.hex()[:32]}..."
    )

    # Verify that both systems generated the same secret
    if shared_a == shared_b:
        print("Shared secret established successfully.")
    else:
        print("Key exchange failed.")

    return shared_a


# ============================================================
# RSA ENCRYPTION
# ============================================================

def rsa_encrypt(message, public_key):

    ciphertext = public_key.encrypt(
        message.encode(),

        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),

            algorithm=hashes.SHA256(),

            label=None
        )
    )

    return ciphertext


# ============================================================
# RSA DECRYPTION
# ============================================================

def rsa_decrypt(ciphertext, private_key):

    plaintext = private_key.decrypt(
        ciphertext,

        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),

            algorithm=hashes.SHA256(),

            label=None
        )
    )

    return plaintext.decode()


# ============================================================
# MAIN PROGRAM
# ============================================================

key_manager = KeyManager()


# ------------------------------------------------------------
# 1. REGISTER SECURECORP SYSTEMS
# ------------------------------------------------------------

key_manager.add_system("Finance System")
key_manager.add_system("HR System")
key_manager.add_system("Supply Chain System")


# ------------------------------------------------------------
# 2. DISTRIBUTE PUBLIC KEYS
# ------------------------------------------------------------

finance_rsa_public, finance_dh_public = \
    key_manager.get_public_keys("Finance System")

hr_rsa_public, hr_dh_public = \
    key_manager.get_public_keys("HR System")


# ------------------------------------------------------------
# 3. DIFFIE-HELLMAN KEY EXCHANGE
# ------------------------------------------------------------

shared_secret = perform_dh_exchange(
    key_manager,
    "Finance System",
    "HR System"
)


# ------------------------------------------------------------
# 4. RSA ENCRYPTION
# ------------------------------------------------------------

message = "Confidential financial report"

ciphertext = rsa_encrypt(
    message,
    hr_rsa_public
)

print("\n--- RSA ENCRYPTION ---")

print("Original Message :", message)

print(
    "Encrypted Message:",
    ciphertext.hex()[:60] + "..."
)


# ------------------------------------------------------------
# 5. RSA DECRYPTION
# ------------------------------------------------------------

decrypted_message = rsa_decrypt(
    ciphertext,
    key_manager.systems["HR System"]["rsa_private"]
)

print("Decrypted Message:", decrypted_message)


# ------------------------------------------------------------
# 6. KEY REVOCATION
# ------------------------------------------------------------

print("\n--- KEY MANAGEMENT ---")

key_manager.revoke_system("HR System")


# Try to access HR's public keys after revocation

try:

    key_manager.get_public_keys("HR System")

except ValueError as error:

    print("Access denied:", error)


# ------------------------------------------------------------
# 7. SCALABILITY
# ------------------------------------------------------------

print("\n--- REGISTERING NEW SUBSYSTEM ---")

key_manager.add_system("Legal System")


# Display all registered systems

print("\nRegistered Systems:")

for system in key_manager.systems:
    print("-", system)