"""
===============================================================
 SECURECORP SECURE COMMUNICATION SYSTEM
===============================================================

Requirements implemented:

1. RSA:
   - Generate RSA public/private key pairs for every subsystem.
   - RSA is used for:
       a) Digital signatures -> authentication + document integrity
       b) RSA-OAEP encryption -> encrypting small secrets/data

2. Diffie-Hellman:
   - Two subsystems establish a common secret key.
   - The secret itself is NEVER transmitted.

3. Key Management:
   - Register new subsystems.
   - Generate their RSA keys.
   - Store public/private keys.
   - Distribute public keys.
   - Revoke a subsystem's keys.

4. Scalability:
   - New subsystems can be added simply by:
          key_manager.register_subsystem("System D")
   - The cryptographic code does not need to change.

NOTE:
The small DH parameters used below are for LAB/DEMONSTRATION.
Real systems must use standardized, cryptographically secure
DH groups or ECDH/X25519.

===============================================================
"""

import base64
import hashlib
from dataclasses import dataclass
from typing import Dict

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# =============================================================
# PART 1 — DIFFIE-HELLMAN PARAMETERS
# =============================================================

# In Diffie-Hellman:
#
#       p = large prime number
#       g = generator
#
# These values are PUBLIC.
#
# Everyone in the system can know p and g.
#
# For the lab we use small values so that the mathematics
# can be understood easily.
#
# Real systems MUST NOT use p = 23.

DH_P = 23
DH_G = 5


# =============================================================
# PART 2 — SUBSYSTEM OBJECT
# =============================================================

@dataclass
class Subsystem:
    """
    Represents one enterprise subsystem.

    Example:
        Finance System
        HR System
        Supply Chain System
    """

    name: str

    # RSA keys
    rsa_private_key: RSA.RsaKey = None
    rsa_public_key: RSA.RsaKey = None

    # Key status
    active: bool = True


# =============================================================
# PART 3 — KEY MANAGEMENT SYSTEM
# =============================================================

class KeyManager:

    def __init__(self):
        """
        Dictionary makes the system scalable.

        Instead of writing:

            finance_key
            hr_key
            supply_chain_key

        separately, we maintain:

            subsystems["Finance"]
            subsystems["HR"]
            subsystems["Supply Chain"]

        Therefore adding System D requires no new cryptographic
        code.
        """

        self.subsystems: Dict[str, Subsystem] = {}

    # ---------------------------------------------------------
    # REGISTER A NEW SUBSYSTEM
    # ---------------------------------------------------------

    def register_subsystem(self, name):
        """
        Generate and register RSA keys for a new subsystem.

        This is the main scalability mechanism.

        Example:

            register_subsystem("Finance")
            register_subsystem("HR")
            register_subsystem("Supply Chain")
            register_subsystem("Marketing")

        The last line automatically adds a new subsystem.
        """

        if name in self.subsystems:
            raise ValueError(f"{name} already exists.")

        # Generate a 2048-bit RSA key pair.
        #
        # The private key contains:
        #     private information
        #
        # The public key can safely be distributed.
        rsa_private = RSA.generate(2048)

        rsa_public = rsa_private.publickey()

        subsystem = Subsystem(
            name=name,
            rsa_private_key=rsa_private,
            rsa_public_key=rsa_public,
            active=True
        )

        self.subsystems[name] = subsystem

        print(f"[+] Registered subsystem: {name}")

    # ---------------------------------------------------------
    # GET PUBLIC KEY
    # ---------------------------------------------------------

    def get_public_key(self, name):
        """
        Public keys may be distributed to other subsystems.

        Example:

            HR needs Finance's public key.

            finance_public_key =
                key_manager.get_public_key("Finance")
        """

        subsystem = self._get_active_subsystem(name)

        return subsystem.rsa_public_key

    # ---------------------------------------------------------
    # GET PRIVATE KEY
    # ---------------------------------------------------------

    def get_private_key(self, name):
        """
        Private keys must remain confidential.

        In a real enterprise this would NOT simply return the
        private key from memory. It would normally be protected
        using an HSM / secure key vault.

        This simplified implementation is for the lab.
        """

        subsystem = self._get_active_subsystem(name)

        return subsystem.rsa_private_key

    # ---------------------------------------------------------
    # REVOKE KEY
    # ---------------------------------------------------------

    def revoke_subsystem(self, name):
        """
        Revoke a subsystem.

        After revocation the subsystem is no longer allowed
        to participate in new secure communication.

        Example:
            key_manager.revoke_subsystem("HR")
        """

        subsystem = self.subsystems.get(name)

        if subsystem is None:
            raise ValueError("Subsystem does not exist.")

        subsystem.active = False

        print(f"[!] Keys revoked for: {name}")

    # ---------------------------------------------------------
    # INTERNAL FUNCTION
    # ---------------------------------------------------------

    def _get_active_subsystem(self, name):

        subsystem = self.subsystems.get(name)

        if subsystem is None:
            raise ValueError(f"Unknown subsystem: {name}")

        if not subsystem.active:
            raise ValueError(
                f"{name} has been revoked and cannot communicate."
            )

        return subsystem


# =============================================================
# PART 4 — DIFFIE-HELLMAN KEY EXCHANGE
# =============================================================

class DiffieHellman:

    def __init__(self, p=DH_P, g=DH_G):
        """
        Store public DH parameters.

        p and g are PUBLIC.

        Every participant can know them.
        """

        self.p = p
        self.g = g

    # ---------------------------------------------------------
    # GENERATE PRIVATE KEY
    # ---------------------------------------------------------

    def generate_private_key(self):
        """
        Generate a private DH number.

        For this LAB implementation we simply choose a number.

        In real cryptography this must use a secure random
        generator and secure standardized parameters.
        """

        import secrets

        # Private value must never be transmitted.
        return secrets.randbelow(self.p - 2) + 1

    # ---------------------------------------------------------
    # GENERATE PUBLIC KEY
    # ---------------------------------------------------------

    def generate_public_key(self, private_key):
        """
        DH public key formula:

                    A = g^a mod p

        where:

            a = private key
            g = public generator
            p = public prime

        The resulting A can be sent over an insecure channel.
        """

        return pow(self.g, private_key, self.p)

    # ---------------------------------------------------------
    # CALCULATE SHARED SECRET
    # ---------------------------------------------------------

    def calculate_shared_secret(
        self,
        other_public_key,
        private_key
    ):
        """
        DH shared secret:

                    K = B^a mod p

        Alice calculates:

                    K = B^a mod p

        Bob calculates:

                    K = A^b mod p

        Because:

                    B = g^b

        Alice gets:

                    (g^b)^a
                  = g^(ab)

        Bob gets:

                    (g^a)^b
                  = g^(ab)

        Therefore:

                    K_Alice = K_Bob

        The secret K is NEVER transmitted.
        """

        return pow(
            other_public_key,
            private_key,
            self.p
        )


# =============================================================
# PART 5 — CONVERT DH SECRET INTO AES KEY
# =============================================================

def derive_aes_key(shared_secret):
    """
    DH gives us a mathematical shared secret.

    We should NOT directly use the raw DH number as an AES key.

    Instead:

        Shared Secret
              |
              v
           SHA-256
              |
              v
        256-bit AES key

    This is a simple educational Key Derivation step.
    """

    return hashlib.sha256(
        str(shared_secret).encode()
    ).digest()


# =============================================================
# PART 6 — AES ENCRYPTION
# =============================================================

def aes_encrypt(key, plaintext):
    """
    AES-GCM provides:

        1. Confidentiality
        2. Integrity
        3. Authentication

    RSA and DH are NOT designed to encrypt large documents.

    Therefore:

        DH -> establish secret
        SHA-256 -> derive AES key
        AES-GCM -> encrypt actual document
    """

    cipher = AES.new(
        key,
        AES.MODE_GCM
    )

    ciphertext, tag = cipher.encrypt_and_digest(
        plaintext.encode()
    )

    return {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }


# =============================================================
# PART 7 — AES DECRYPTION
# =============================================================

def aes_decrypt(key, encrypted_data):
    """
    Reverse the AES-GCM operation.

    The authentication tag is checked first.

    If the ciphertext was modified, verification fails.
    """

    nonce = base64.b64decode(
        encrypted_data["nonce"]
    )

    ciphertext = base64.b64decode(
        encrypted_data["ciphertext"]
    )

    tag = base64.b64decode(
        encrypted_data["tag"]
    )

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext.decode()


# =============================================================
# PART 8 — RSA DIGITAL SIGNATURE
# =============================================================

def rsa_sign(private_key, message):
    """
    The sender signs a document using its RSA PRIVATE key.

    Conceptually:

        Document
            |
          SHA-256
            |
          Hash
            |
       RSA Private Key
            |
         Signature

    Anyone possessing the sender's PUBLIC key can verify it.

    This provides:

        Authentication
        Integrity
        Non-repudiation (within the limitations of the system)
    """

    digest = SHA256.new(
        message.encode()
    )

    signature = pkcs1_15.new(
        private_key
    ).sign(digest)

    return signature


# =============================================================
# PART 9 — RSA SIGNATURE VERIFICATION
# =============================================================

def rsa_verify(public_key, message, signature):
    """
    Receiver verifies the signature using the sender's
    RSA PUBLIC key.

    If verification succeeds:

        - message came from the expected key holder
        - message was not modified

    """

    digest = SHA256.new(
        message.encode()
    )

    try:

        pkcs1_15.new(
            public_key
        ).verify(
            digest,
            signature
        )

        return True

    except (ValueError, TypeError):

        return False


# =============================================================
# PART 10 — RSA ENCRYPTION
# =============================================================

def rsa_encrypt(public_key, message):
    """
    RSA-OAEP encryption.

    RSA encryption uses:

        Receiver's PUBLIC key -> encryption
        Receiver's PRIVATE key -> decryption

    IMPORTANT:

    RSA is intended for relatively small data such as keys
    or short messages.

    We should NOT RSA-encrypt a large financial report.

    Large documents should be encrypted using AES.
    """

    cipher = PKCS1_OAEP.new(
        public_key
    )

    ciphertext = cipher.encrypt(
        message.encode()
    )

    return ciphertext


# =============================================================
# PART 11 — RSA DECRYPTION
# =============================================================

def rsa_decrypt(private_key, ciphertext):
    """
    RSA-OAEP decryption.

    Only the holder of the corresponding private key can
    decrypt the RSA-encrypted data.
    """

    cipher = PKCS1_OAEP.new(
        private_key
    )

    plaintext = cipher.decrypt(
        ciphertext
    )

    return plaintext.decode()


# =============================================================
# PART 12 — SECURE COMMUNICATION FUNCTION
# =============================================================

def establish_secure_channel(
    sender_name,
    receiver_name,
    key_manager
):
    """
    Establish a secure channel between two subsystems.

    Example:

        Finance -> HR

    Process:

        1. Obtain RSA public keys.
        2. Generate DH private keys.
        3. Generate DH public keys.
        4. Exchange DH public keys.
        5. Calculate shared secret.
        6. Derive AES key.

    """

    print("\n" + "=" * 60)
    print(
        f"ESTABLISHING SECURE CHANNEL:"
        f" {sender_name} -> {receiver_name}"
    )
    print("=" * 60)

    # ---------------------------------------------------------
    # STEP 1 — GET SUBSYSTEMS
    # ---------------------------------------------------------

    sender = key_manager._get_active_subsystem(
        sender_name
    )

    receiver = key_manager._get_active_subsystem(
        receiver_name
    )

    # ---------------------------------------------------------
    # STEP 2 — CREATE DH OBJECT
    # ---------------------------------------------------------

    dh = DiffieHellman()

    # ---------------------------------------------------------
    # STEP 3 — GENERATE PRIVATE DH KEYS
    # ---------------------------------------------------------

    sender_private_dh = dh.generate_private_key()
    receiver_private_dh = dh.generate_private_key()

    # IMPORTANT:
    #
    # These values NEVER leave their respective systems.

    # ---------------------------------------------------------
    # STEP 4 — GENERATE DH PUBLIC VALUES
    # ---------------------------------------------------------

    sender_public_dh = dh.generate_public_key(
        sender_private_dh
    )

    receiver_public_dh = dh.generate_public_key(
        receiver_private_dh
    )

    print(
        f"{sender_name} DH public value: "
        f"{sender_public_dh}"
    )

    print(
        f"{receiver_name} DH public value: "
        f"{receiver_public_dh}"
    )

    # ---------------------------------------------------------
    # STEP 5 — EXCHANGE PUBLIC DH VALUES
    # ---------------------------------------------------------

    # Sender receives receiver's public value.
    # Receiver receives sender's public value.

    # ---------------------------------------------------------
    # STEP 6 — CALCULATE SHARED SECRET
    # ---------------------------------------------------------

    sender_shared_secret = dh.calculate_shared_secret(
        receiver_public_dh,
        sender_private_dh
    )

    receiver_shared_secret = dh.calculate_shared_secret(
        sender_public_dh,
        receiver_private_dh
    )

    print(
        f"{sender_name} shared secret: "
        f"{sender_shared_secret}"
    )

    print(
        f"{receiver_name} shared secret: "
        f"{receiver_shared_secret}"
    )

    # ---------------------------------------------------------
    # STEP 7 — VERIFY BOTH GOT SAME SECRET
    # ---------------------------------------------------------

    if sender_shared_secret != receiver_shared_secret:
        raise ValueError(
            "DH key exchange failed!"
        )

    print("[+] DH key exchange successful.")

    # ---------------------------------------------------------
    # STEP 8 — DERIVE AES SESSION KEY
    # ---------------------------------------------------------

    session_key = derive_aes_key(
        sender_shared_secret
    )

    print("[+] AES session key established.")

    return session_key


# =============================================================
# PART 13 — COMPLETE DOCUMENT TRANSFER
# =============================================================

def secure_document_transfer(
    sender_name,
    receiver_name,
    document,
    key_manager
):
    """
    Complete secure document transfer.

    Example:

        Finance sends:
            "Annual Financial Report"

        to:

            HR

    Security operations:

        DH
         ↓
        Shared secret
         ↓
        AES key
         ↓
        AES-GCM encryption

        RSA
         ↓
        Digital signature
         ↓
        Receiver verifies sender
    """

    # ---------------------------------------------------------
    # STEP 1 — ESTABLISH DH SESSION
    # ---------------------------------------------------------

    session_key = establish_secure_channel(
        sender_name,
        receiver_name,
        key_manager
    )

    # ---------------------------------------------------------
    # STEP 2 — GET SENDER PRIVATE KEY
    # ---------------------------------------------------------

    sender_private_key = (
        key_manager
        .get_private_key(sender_name)
    )

    # ---------------------------------------------------------
    # STEP 3 — SIGN DOCUMENT
    # ---------------------------------------------------------

    signature = rsa_sign(
        sender_private_key,
        document
    )

    print(
        f"[+] {sender_name} signed the document."
    )

    # ---------------------------------------------------------
    # STEP 4 — ENCRYPT DOCUMENT USING AES
    # ---------------------------------------------------------

    encrypted_document = aes_encrypt(
        session_key,
        document
    )

    print(
        "[+] Document encrypted using AES-GCM."
    )

    # ---------------------------------------------------------
    # STEP 5 — RECEIVER GETS SENDER'S PUBLIC KEY
    # ---------------------------------------------------------

    sender_public_key = (
        key_manager
        .get_public_key(sender_name)
    )

    # ---------------------------------------------------------
    # STEP 6 — VERIFY RSA SIGNATURE
    # ---------------------------------------------------------

    signature_valid = rsa_verify(
        sender_public_key,
        document,
        signature
    )

    if not signature_valid:

        raise ValueError(
            "RSA signature verification failed!"
        )

    print(
        f"[+] {receiver_name} verified "
        f"{sender_name}'s signature."
    )

    # ---------------------------------------------------------
    # STEP 7 — DECRYPT DOCUMENT
    # ---------------------------------------------------------

    decrypted_document = aes_decrypt(
        session_key,
        encrypted_document
    )

    print(
        "[+] Receiver decrypted the document."
    )

    return decrypted_document


# =============================================================
# PART 14 — MAIN PROGRAM
# =============================================================

def main():

    print("=" * 60)
    print("       SECURECORP SECURITY SYSTEM")
    print("=" * 60)

    # ---------------------------------------------------------
    # CREATE CENTRAL KEY MANAGEMENT SYSTEM
    # ---------------------------------------------------------

    key_manager = KeyManager()

    # ---------------------------------------------------------
    # REGISTER EXISTING SUBSYSTEMS
    # ---------------------------------------------------------

    key_manager.register_subsystem(
        "Finance"
    )

    key_manager.register_subsystem(
        "HR"
    )

    key_manager.register_subsystem(
        "Supply Chain"
    )

    # ---------------------------------------------------------
    # SCALABILITY
    # ---------------------------------------------------------
    #
    # Suppose SecureCorp creates another subsystem.
    #
    # We simply register it.
    #
    # No cryptographic algorithm needs to be rewritten.

    key_manager.register_subsystem(
        "Marketing"
    )

    # ---------------------------------------------------------
    # SECURE DOCUMENT
    # ---------------------------------------------------------

    document = (
        "CONFIDENTIAL FINANCIAL REPORT - "
        "Q4 SecureCorp"
    )

    # ---------------------------------------------------------
    # FINANCE -> HR
    # ---------------------------------------------------------

    decrypted_document = secure_document_transfer(
        sender_name="Finance",
        receiver_name="HR",
        document=document,
        key_manager=key_manager
    )

    print("\n" + "=" * 60)
    print("FINAL RESULT")
    print("=" * 60)

    print(
        "Original document :",
        document
    )

    print(
        "Decrypted document:",
        decrypted_document
    )

    print(
        "\nCommunication successful:",
        document == decrypted_document
    )

    # ---------------------------------------------------------
    # KEY REVOCATION
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("KEY REVOCATION")
    print("=" * 60)

    key_manager.revoke_subsystem(
        "HR"
    )

    # HR is now disabled for future secure channels.

    print("\nHR has been revoked.")


# =============================================================
# PROGRAM ENTRY POINT
# =============================================================

if __name__ == "__main__":
    main()
