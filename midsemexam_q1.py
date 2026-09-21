"""
============================================================
                 SECUREVAULT
        Secure Record Management System
============================================================

ROLES:
    1. Client
    2. Lawyer
    3. Compliance Officer

CRYPTOGRAPHIC TECHNIQUES:
    1. DES-CBC       -> Confidentiality
    2. SHA-256       -> Integrity
    3. ElGamal       -> Digital Signature / Authentication

CLIENT:
    - Enters confidential record
    - Encrypts using DES-CBC
    - Generates random IV
    - Calculates SHA-256 of ciphertext
    - Signs ciphertext using ElGamal private key
    - Stores ciphertext, IV, hash, signature and timestamp

LAWYER:
    - Loads encrypted record
    - Verifies SHA-256
    - Verifies ElGamal signature
    - Decrypts ONLY if both checks pass
    - Displays plaintext
    - Logs access

COMPLIANCE OFFICER:
    - Loads encrypted record
    - Verifies SHA-256
    - Verifies ElGamal signature
    - Generates compliance report
    - NEVER decrypts or accesses plaintext

============================================================
"""

import json
import math
import secrets
from datetime import datetime

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, isPrime


# ============================================================
#                    CONFIGURATION
# ============================================================

# File where encrypted record and security metadata are stored
RECORD_FILE = "secure_record.json"

# File where role activities are recorded
AUDIT_FILE = "audit_log.txt"

# File where compliance report is stored
COMPLIANCE_FILE = "compliance_report.json"


# ============================================================
#                    DES KEY
# ============================================================

def get_des_key():
    """
    Ask the user for an 8-byte DES key.

    DES uses a block/key size of 64 bits = 8 bytes.

    Example:
        12345678

    IMPORTANT:
    For this lab, we simply ask the user to enter
    an 8-character key.
    """

    while True:

        key = input(
            "Enter DES key (exactly 8 characters): "
        )

        # Convert string to bytes and check length.
        #
        # We check bytes rather than characters because
        # DES operates on bytes.
        if len(key.encode()) == 8:

            return key.encode()

        print(
            "ERROR: DES key must be exactly 8 bytes."
        )


# ============================================================
#                ELGAMAL KEY GENERATION
# ============================================================
#
# ElGamal uses:
#
#       p = large prime
#       g = generator
#
# Private key:
#
#       x
#
# Public key:
#
#       y = g^x mod p
#
# ------------------------------------------------------------
# IMPORTANT FIX:
# ------------------------------------------------------------
#
# The original program tried to factor p-1 by checking:
#
#       2, 3, 4, 5, 6, ...
#
# for a 256-bit prime.
#
# This caused the program to appear frozen before reaching
# the menu.
#
# Instead, we generate a SAFE PRIME:
#
#       p = 2q + 1
#
# where both p and q are prime.
#
# Therefore:
#
#       p - 1 = 2q
#
# The only prime factors of p-1 are:
#
#       2 and q
#
# So finding a generator becomes very fast.
#
# ============================================================


def find_generator_safe_prime(p, q):
    """
    Find a generator g for a safe prime p.

    Since:

        p = 2q + 1

    we have:

        p - 1 = 2q

    Therefore the prime factors of p-1 are only:

        2 and q

    A primitive root g must satisfy:

        g^((p-1)/2) mod p != 1

    and

        g^((p-1)/q) mod p != 1

    Which becomes:

        g^q mod p != 1

    and:

        g^2 mod p != 1
    """

    # Try small possible generators.
    for g in range(2, 100):

        # First condition:
        #
        # g^q mod p must NOT be 1.
        if pow(g, q, p) == 1:

            continue

        # Second condition:
        #
        # g^2 mod p must NOT be 1.
        if pow(g, 2, p) == 1:

            continue

        # Both conditions passed.
        return g

    raise ValueError(
        "Could not find a generator."
    )


# ============================================================
#             GENERATE ELGAMAL KEY PAIR
# ============================================================

def generate_elgamal_keys():
    """
    Generate ElGamal parameters and keys.

    We generate a safe prime:

        p = 2q + 1

    where p and q are both prime.

    Then:

        g = generator

        x = private key

        y = g^x mod p

    Public key:
        (p, g, y)

    Private key:
        x
    """

    print("\nGenerating ElGamal keys...")

    # --------------------------------------------------------
    # STEP 1:
    #
    # Generate q and p until both are prime.
    #
    # q = 255-bit prime
    #
    # p = 2q + 1
    # --------------------------------------------------------

    while True:

        # Generate a random 255-bit prime q.
        q = getPrime(255)

        # Construct candidate safe prime.
        p = 2 * q + 1

        # Check whether p is also prime.
        if isPrime(p):

            break

    # --------------------------------------------------------
    # STEP 2:
    #
    # Find generator g.
    # --------------------------------------------------------

    g = find_generator_safe_prime(
        p,
        q
    )

    # --------------------------------------------------------
    # STEP 3:
    #
    # Generate private key x.
    #
    #       1 < x < p-1
    # --------------------------------------------------------

    x = secrets.randbelow(
        p - 2
    ) + 1

    # --------------------------------------------------------
    # STEP 4:
    #
    # Generate public key y.
    #
    #       y = g^x mod p
    # --------------------------------------------------------

    y = pow(
        g,
        x,
        p
    )

    print(
        "ElGamal keys generated successfully."
    )

    # Return everything needed by the program.
    return {

        "p": p,
        "g": g,
        "x": x,
        "y": y
    }


# ============================================================
#                 ELGAMAL DIGITAL SIGNATURE
# ============================================================
#
# We sign the encrypted ciphertext.
#
# First:
#
#       H = SHA256(ciphertext)
#
# Then choose random k such that:
#
#       gcd(k, p-1) = 1
#
# Calculate:
#
#       r = g^k mod p
#
#       s = k^-1(H - xr) mod (p-1)
#
# Signature:
#
#       (r, s)
#
# ============================================================


def elgamal_sign(data, private_key):
    """
    Create an ElGamal digital signature for data.
    """

    p = private_key["p"]
    g = private_key["g"]
    x = private_key["x"]

    # --------------------------------------------------------
    # STEP 1:
    #
    # Calculate SHA-256 hash of the data.
    #
    # The hash is converted to an integer because
    # ElGamal mathematical operations use integers.
    # --------------------------------------------------------

    hash_value = SHA256.new(
        data
    ).digest()

    h = int.from_bytes(
        hash_value,
        "big"
    )

    # --------------------------------------------------------
    # STEP 2:
    #
    # Generate random k.
    #
    # We require:
    #
    #       gcd(k, p-1) = 1
    #
    # because we need k inverse modulo p-1.
    # --------------------------------------------------------

    while True:

        k = secrets.randbelow(
            p - 2
        ) + 1

        if math.gcd(
            k,
            p - 1
        ) == 1:

            break

    # --------------------------------------------------------
    # STEP 3:
    #
    # Calculate:
    #
    #       r = g^k mod p
    # --------------------------------------------------------

    r = pow(
        g,
        k,
        p
    )

    # --------------------------------------------------------
    # STEP 4:
    #
    # Calculate inverse of k:
    #
    #       k^-1 mod (p-1)
    # --------------------------------------------------------

    k_inverse = pow(
        k,
        -1,
        p - 1
    )

    # --------------------------------------------------------
    # STEP 5:
    #
    # Calculate:
    #
    #       s = k^-1(H - xr) mod (p-1)
    # --------------------------------------------------------

    s = (
        k_inverse *
        (h - x * r)
    ) % (p - 1)

    # Return signature pair.
    return r, s


# ============================================================
#              ELGAMAL SIGNATURE VERIFICATION
# ============================================================

def elgamal_verify(
    data,
    signature,
    public_key
):
    """
    Verify an ElGamal digital signature.

    Verification equation:

        g^H mod p

    must equal:

        y^r * r^s mod p
    """

    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]

    r, s = signature

    # --------------------------------------------------------
    # Check that r is within valid range.
    # --------------------------------------------------------

    if not (
        0 < r < p
    ):

        return False

    # --------------------------------------------------------
    # Check that s is within valid range.
    # --------------------------------------------------------

    if not (
        0 < s < p - 1
    ):

        return False

    # --------------------------------------------------------
    # Calculate SHA-256 hash again.
    #
    # The verifier independently hashes the ciphertext.
    # --------------------------------------------------------

    hash_value = SHA256.new(
        data
    ).digest()

    h = int.from_bytes(
        hash_value,
        "big"
    )

    # --------------------------------------------------------
    # LEFT SIDE:
    #
    #       g^H mod p
    # --------------------------------------------------------

    left = pow(
        g,
        h,
        p
    )

    # --------------------------------------------------------
    # RIGHT SIDE:
    #
    #       y^r * r^s mod p
    # --------------------------------------------------------

    right = (
        pow(y, r, p) *
        pow(r, s, p)
    ) % p

    # Signature is valid if both sides match.
    return left == right


# ============================================================
#                    DES ENCRYPTION
# ============================================================

def des_encrypt(
    plaintext,
    key
):
    """
    Encrypt plaintext using DES in CBC mode.

    Steps:

        1. Generate random IV
        2. Convert plaintext to bytes
        3. Apply PKCS#7 padding
        4. Encrypt using DES-CBC
        5. Return ciphertext and IV
    """

    # --------------------------------------------------------
    # DES block size = 8 bytes.
    #
    # Therefore IV must also be 8 bytes.
    # --------------------------------------------------------

    iv = secrets.token_bytes(
        8
    )

    # --------------------------------------------------------
    # Create DES-CBC cipher.
    # --------------------------------------------------------

    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )

    # --------------------------------------------------------
    # Convert plaintext string into bytes.
    # --------------------------------------------------------

    plaintext_bytes = plaintext.encode()

    # --------------------------------------------------------
    # DES-CBC requires data length to be a multiple
    # of the block size.
    #
    # PKCS#7 adds padding when necessary.
    # --------------------------------------------------------

    padded_data = pad(
        plaintext_bytes,
        DES.block_size
    )

    # --------------------------------------------------------
    # Encrypt padded plaintext.
    # --------------------------------------------------------

    ciphertext = cipher.encrypt(
        padded_data
    )

    # Return ciphertext and IV.
    return ciphertext, iv


# ============================================================
#                    DES DECRYPTION
# ============================================================

def des_decrypt(
    ciphertext,
    key,
    iv
):
    """
    Decrypt DES-CBC ciphertext.

    The same:

        key
        IV

    used during encryption are required.
    """

    # --------------------------------------------------------
    # Recreate DES-CBC cipher.
    # --------------------------------------------------------

    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )

    # --------------------------------------------------------
    # Decrypt ciphertext.
    # --------------------------------------------------------

    padded_plaintext = cipher.decrypt(
        ciphertext
    )

    # --------------------------------------------------------
    # Remove PKCS#7 padding.
    # --------------------------------------------------------

    plaintext = unpad(
        padded_plaintext,
        DES.block_size
    )

    # --------------------------------------------------------
    # Convert bytes back into a normal string.
    # --------------------------------------------------------

    return plaintext.decode()


# ============================================================
#                    SHA-256 HASH
# ============================================================

def calculate_hash(data):
    """
    Calculate SHA-256 hash of the supplied data.

    SHA-256 is used for integrity verification.

    It does NOT encrypt the data.

    Example:

        ciphertext
             |
             v
         SHA-256
             |
             v
        hash value
    """

    return SHA256.new(
        data
    ).hexdigest()


# ============================================================
#                    AUDIT LOGGING
# ============================================================

def audit_log(
    role,
    operation,
    status
):
    """
    Record an activity in the audit log.

    Example:

        2026-09-21 09:30:20 |
        LAWYER |
        ACCESS |
        SUCCESS
    """

    # Generate current timestamp.
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Create log entry.
    entry = (
        f"{timestamp} | "
        f"{role} | "
        f"{operation} | "
        f"{status}\n"
    )

    # Append to audit file.
    #
    # "a" means append, so previous logs are not deleted.
    with open(
        AUDIT_FILE,
        "a"
    ) as file:

        file.write(entry)


# ============================================================
#             SAVE ENCRYPTED RECORD TO FILE
# ============================================================

def save_record(
    ciphertext,
    iv,
    hash_value,
    signature,
    timestamp,
    public_key
):
    """
    Store the encrypted record and security metadata.

    IMPORTANT:

    Plaintext is NEVER stored.

    Stored information:

        ciphertext
        IV
        SHA-256 hash
        ElGamal signature
        timestamp
        public key
    """

    # --------------------------------------------------------
    # JSON cannot directly store bytes.
    #
    # Therefore:
    #
    #       bytes -> hexadecimal string
    #
    # is used.
    # --------------------------------------------------------

    record = {

        "ciphertext":
            ciphertext.hex(),

        "iv":
            iv.hex(),

        "sha256":
            hash_value,

        "signature": {

            "r":
                signature[0],

            "s":
                signature[1]
        },

        "timestamp":
            timestamp,

        "public_key": {

            "p":
                public_key["p"],

            "g":
                public_key["g"],

            "y":
                public_key["y"]
        }
    }

    # --------------------------------------------------------
    # Store the dictionary as JSON.
    # --------------------------------------------------------

    with open(
        RECORD_FILE,
        "w"
    ) as file:

        json.dump(
            record,
            file,
            indent=4
        )


# ============================================================
#             LOAD ENCRYPTED RECORD FROM FILE
# ============================================================

def load_record():
    """
    Read the stored SecureVault record from JSON.
    """

    with open(
        RECORD_FILE,
        "r"
    ) as file:

        record = json.load(file)

    return record


# ============================================================
#                 CLIENT ROLE
# ============================================================

def client_role(private_key):

    print("\n================================")
    print("             CLIENT")
    print("================================")

    # --------------------------------------------------------
    # STEP 1:
    # Ask the client for confidential information.
    # --------------------------------------------------------

    plaintext = input(
        "Enter confidential client record: "
    )

    # --------------------------------------------------------
    # STEP 2:
    # Get DES key.
    #
    # DES requires exactly 8 bytes.
    # --------------------------------------------------------

    des_key = get_des_key()

    # --------------------------------------------------------
    # STEP 3:
    # Encrypt record using DES-CBC.
    #
    # Result:
    #
    #       ciphertext
    #       IV
    # --------------------------------------------------------

    ciphertext, iv = des_encrypt(
        plaintext,
        des_key
    )

    # --------------------------------------------------------
    # STEP 4:
    # Calculate SHA-256 hash of ciphertext.
    #
    # We hash the encrypted data rather than plaintext.
    # --------------------------------------------------------

    hash_value = calculate_hash(
        ciphertext
    )

    # --------------------------------------------------------
    # STEP 5:
    # Generate ElGamal digital signature.
    #
    # We sign the ciphertext.
    # --------------------------------------------------------

    signature = elgamal_sign(
        ciphertext,
        private_key
    )

    # --------------------------------------------------------
    # STEP 6:
    # Generate timestamp.
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------------
    # STEP 7:
    # Extract public portion of ElGamal key.
    #
    # Public key:
    #
    #       (p, g, y)
    #
    # Private key x is NOT stored in the record.
    # --------------------------------------------------------

    public_key = {

        "p":
            private_key["p"],

        "g":
            private_key["g"],

        "y":
            private_key["y"]
    }

    # --------------------------------------------------------
    # STEP 8:
    # Save encrypted record and metadata.
    # --------------------------------------------------------

    save_record(
        ciphertext,
        iv,
        hash_value,
        signature,
        timestamp,
        public_key
    )

    # --------------------------------------------------------
    # DISPLAY SECURITY INFORMATION
    # --------------------------------------------------------

    print(
        "\n--- RECORD STORED SUCCESSFULLY ---"
    )

    print("\nCiphertext:")
    print(
        ciphertext.hex()
    )

    print("\nIV:")
    print(
        iv.hex()
    )

    print("\nSHA-256 Hash:")
    print(
        hash_value
    )

    print("\nElGamal Signature:")

    print(
        "r =",
        signature[0]
    )

    print(
        "s =",
        signature[1]
    )

    print("\nTimestamp:")
    print(
        timestamp
    )

    # --------------------------------------------------------
    # Record activity in audit log.
    # --------------------------------------------------------

    audit_log(
        "CLIENT",
        "CREATE RECORD",
        "SUCCESS"
    )


# ============================================================
#              VERIFY SECURITY METADATA
# ============================================================

def verify_record(record):
    """
    Perform BOTH security checks:

        1. SHA-256 integrity verification
        2. ElGamal signature verification

    This function is used by:

        Lawyer
        Compliance Officer

    Keeping it as a separate function avoids duplicating
    cryptographic verification code.
    """

    # --------------------------------------------------------
    # Recover ciphertext from hexadecimal representation.
    #
    # hex string -> bytes
    # --------------------------------------------------------

    ciphertext = bytes.fromhex(
        record["ciphertext"]
    )

    # ========================================================
    #                 HASH VERIFICATION
    # ========================================================

    # Calculate hash again.
    calculated_hash = calculate_hash(
        ciphertext
    )

    # Compare newly calculated hash with stored hash.
    hash_valid = (
        calculated_hash ==
        record["sha256"]
    )

    # ========================================================
    #             ELGAMAL SIGNATURE VERIFICATION
    # ========================================================

    # Recover signature.
    signature = (

        record["signature"]["r"],

        record["signature"]["s"]
    )

    # Recover client's public key.
    public_key = {

        "p":
            record["public_key"]["p"],

        "g":
            record["public_key"]["g"],

        "y":
            record["public_key"]["y"]
    }

    # Verify signature against ciphertext.
    signature_valid = elgamal_verify(
        ciphertext,
        signature,
        public_key
    )

    # Return both verification results.
    return (
        hash_valid,
        signature_valid
    )


# ============================================================
#                    LAWYER ROLE
# ============================================================

def lawyer_role():

    print("\n================================")
    print("             LAWYER")
    print("================================")

    # --------------------------------------------------------
    # STEP 1:
    # Load stored record.
    # --------------------------------------------------------

    try:

        record = load_record()

    except FileNotFoundError:

        print(
            "No stored record found."
        )

        audit_log(
            "LAWYER",
            "ACCESS",
            "FAILED - RECORD NOT FOUND"
        )

        return

    # --------------------------------------------------------
    # STEP 2:
    # Verify SHA-256 and ElGamal signature.
    # --------------------------------------------------------

    hash_valid, signature_valid = verify_record(
        record
    )

    # --------------------------------------------------------
    # DISPLAY VERIFICATION RESULTS
    # --------------------------------------------------------

    print(
        "\n--- VERIFICATION RESULTS ---"
    )

    print(
        "SHA-256 Hash:",
        "VALID" if hash_valid else "INVALID"
    )

    print(
        "ElGamal Signature:",
        "VALID" if signature_valid else "INVALID"
    )

    # --------------------------------------------------------
    # SECURITY RULE:
    #
    # Lawyer can decrypt ONLY when BOTH checks succeed.
    #
    #       hash_valid AND signature_valid
    #
    # If even one fails:
    #
    #       NO DECRYPTION
    # --------------------------------------------------------

    if not (
        hash_valid and
        signature_valid
    ):

        print(
            "\nACCESS DENIED."
        )

        print(
            "Plaintext will NOT be decrypted."
        )

        audit_log(
            "LAWYER",
            "ACCESS",
            "DENIED - VERIFICATION FAILED"
        )

        return

    # --------------------------------------------------------
    # STEP 3:
    # Ask for DES key.
    #
    # Notice that this happens ONLY after successful
    # integrity and signature verification.
    # --------------------------------------------------------

    des_key = get_des_key()

    # --------------------------------------------------------
    # Recover ciphertext.
    # --------------------------------------------------------

    ciphertext = bytes.fromhex(
        record["ciphertext"]
    )

    # --------------------------------------------------------
    # Recover IV.
    # --------------------------------------------------------

    iv = bytes.fromhex(
        record["iv"]
    )

    # --------------------------------------------------------
    # STEP 4:
    # Decrypt.
    # --------------------------------------------------------

    try:

        plaintext = des_decrypt(
            ciphertext,
            des_key,
            iv
        )

        # ----------------------------------------------------
        # Display plaintext.
        # ----------------------------------------------------

        print(
            "\n--- DECRYPTED CLIENT RECORD ---"
        )

        print(
            plaintext
        )

        # ----------------------------------------------------
        # Record successful access.
        # ----------------------------------------------------

        audit_log(
            "LAWYER",
            "ACCESS",
            "SUCCESS"
        )

    except Exception:

        # Wrong key or corrupted ciphertext can cause
        # padding/decryption failure.

        print(
            "\nDecryption failed."
        )

        print(
            "Check whether the correct DES key was entered."
        )

        audit_log(
            "LAWYER",
            "ACCESS",
            "FAILED - DECRYPTION ERROR"
        )


# ============================================================
#              COMPLIANCE OFFICER ROLE
# ============================================================

def compliance_role():

    print("\n================================")
    print("       COMPLIANCE OFFICER")
    print("================================")

    # --------------------------------------------------------
    # STEP 1:
    # Load encrypted record.
    # --------------------------------------------------------

    try:

        record = load_record()

    except FileNotFoundError:

        print(
            "No stored record found."
        )

        audit_log(
            "COMPLIANCE",
            "AUDIT",
            "FAILED - RECORD NOT FOUND"
        )

        return

    # --------------------------------------------------------
    # STEP 2:
    # Verify SHA-256 and ElGamal signature.
    # --------------------------------------------------------

    hash_valid, signature_valid = verify_record(
        record
    )

    # --------------------------------------------------------
    # DISPLAY VERIFICATION RESULTS
    # --------------------------------------------------------

    print(
        "\n--- COMPLIANCE VERIFICATION ---"
    )

    print(
        "SHA-256 Hash:",
        "VALID" if hash_valid else "INVALID"
    )

    print(
        "ElGamal Signature:",
        "VALID" if signature_valid else "INVALID"
    )

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # The Compliance Officer NEVER gets the DES key.
    #
    # Therefore:
    #
    #       No DES decryption
    #       No plaintext
    #
    # This implements role-based access control.
    # --------------------------------------------------------

    # --------------------------------------------------------
    # STEP 3:
    # Generate compliance report timestamp.
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------------
    # STEP 4:
    # Create compliance report.
    # --------------------------------------------------------

    report = {

        "report_timestamp":
            timestamp,

        "record_timestamp":
            record["timestamp"],

        "sha256_verification":
            "VALID"
            if hash_valid
            else "INVALID",

        "elgamal_verification":
            "VALID"
            if signature_valid
            else "INVALID",

        "plaintext_access":
            "NOT PERMITTED"
    }

    # --------------------------------------------------------
    # STEP 5:
    # Save compliance report.
    # --------------------------------------------------------

    with open(
        COMPLIANCE_FILE,
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    # --------------------------------------------------------
    # DISPLAY COMPLIANCE REPORT
    # --------------------------------------------------------

    print(
        "\n--- COMPLIANCE REPORT ---"
    )

    print(
        json.dumps(
            report,
            indent=4
        )
    )

    # --------------------------------------------------------
    # Record audit operation.
    # --------------------------------------------------------

    audit_log(
        "COMPLIANCE",
        "AUDIT",
        "COMPLETED"
    )


# ============================================================
#                    MAIN PROGRAM
# ============================================================

def main():

    # --------------------------------------------------------
    # PROGRAM HEADER
    # --------------------------------------------------------

    print(
        "\n======================================"
    )

    print(
        "          SECUREVAULT"
    )

    print(
        "   Secure Record Management System"
    )

    print(
        "======================================"
    )

    # --------------------------------------------------------
    # Generate client's ElGamal key pair.
    #
    # IMPORTANT:
    #
    # This happens once when the application starts.
    # --------------------------------------------------------

    client_keys = generate_elgamal_keys()

    # --------------------------------------------------------
    # Separate private/public information.
    #
    # Private key:
    #
    #       x
    #
    # Public information:
    #
    #       p, g, y
    # --------------------------------------------------------

    private_key = {

        "p":
            client_keys["p"],

        "g":
            client_keys["g"],

        "x":
            client_keys["x"],

        "y":
            client_keys["y"]
    }

    # ========================================================
    #                    ROLE MENU
    # ========================================================

    while True:

        print(
            "\n--------------- MENU ---------------"
        )

        print(
            "1. Client"
        )

        print(
            "2. Lawyer"
        )

        print(
            "3. Compliance Officer"
        )

        print(
            "4. Exit"
        )

        choice = input(
            "\nEnter choice: "
        )

        # ----------------------------------------------------
        # CLIENT
        # ----------------------------------------------------

        if choice == "1":

            client_role(
                private_key
            )

        # ----------------------------------------------------
        # LAWYER
        # ----------------------------------------------------

        elif choice == "2":

            lawyer_role()

        # ----------------------------------------------------
        # COMPLIANCE OFFICER
        # ----------------------------------------------------

        elif choice == "3":

            compliance_role()

        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        elif choice == "4":

            print(
                "\nExiting SecureVault..."
            )

            break

        # ----------------------------------------------------
        # INVALID INPUT
        # ----------------------------------------------------

        else:

            print(
                "\nInvalid choice. Please try again."
            )


# ============================================================
#                    PROGRAM START
# ============================================================

if __name__ == "__main__":

    main()
