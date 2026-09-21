'''
SecureVault – Secure Record Management System

Design and implement an application named "SecureVault" for securely storing, authenticating, accessing, and auditing confidential client records. 
The application must have three roles: Client, Lawyer, and Compliance Officer.
The application must use:
1. DES in CBC mode for encryption and decryption.
2. SHA-256 for data integrity verification.
3. ElGamal Digital Signature for authentication and verification.

CLIENT:

The Client should:
1. Enter/provide a confidential record.
2. Encrypt the record using DES in CBC mode.
3. Generate an IV and use it during encryption.
4. Calculate the SHA-256 hash of the encrypted data.
5. Generate an ElGamal digital signature using the client's private key.
6. Display the following:
- Ciphertext
- IV
- SHA-256 hash value
- ElGamal signature
- Timestamp
7. Store the ciphertext, IV, hash value, signature, and timestamp in a file for future verification and access.

LAWYER:

The Lawyer should:
1. Read the stored ciphertext, IV, hash value, signature, and timestamp from the file.
2. Recalculate the SHA-256 hash and compare it with the stored hash value.
3. Verify the ElGamal digital signature using the client's public key.
4. Display the hash verification and signature verification status.
5. Only if the hash and signature verification are successful, decrypt the ciphertext using DES in CBC mode.
6. Display the recovered plaintext record.
7. Store the verification/access status along with a timestamp.

If the integrity or signature verification fails, the Lawyer must not decrypt or access the plaintext.

COMPLIANCE OFFICER:

The Compliance Officer should:
1. Access the stored encrypted record and its associated security metadata.
2. Verify the SHA-256 hash to check whether the stored data has been modified.
3. Verify the ElGamal digital signature using the client's public key.
4. Display the hash verification and signature verification status.
5. Record the verification results along with a timestamp.
6. Generate a Compliance Report containing the verification status and relevant metadata.
7. The Compliance Officer must NOT decrypt the ciphertext or access the client's plaintext record.

The application should maintain proper role-based access, ensuring that:
- The Client can create and securely store records.
- The Lawyer can verify and decrypt records after successful authentication.
- The Compliance Officer can independently audit the record's integrity and authenticity without accessing the plaintext.

The system should clearly display all relevant security information and verification results.

'''

import json
import math
import secrets
from datetime import datetime

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime


# ============================================================
#                    CONFIGURATION
# ============================================================

RECORD_FILE = "secure_record.json"
AUDIT_FILE = "audit_log.txt"


# ============================================================
#                    DES KEY
# ============================================================
#
# DES requires EXACTLY 8 bytes = 64 bits.
#
# For a real system, the DES key should NEVER be hardcoded.
# It should be stored in a secure key-management system.
#
# For this LAB, we ask the user to enter an 8-character key.
#
# Example:
#
#       12345678
#
# ============================================================


def get_des_key():
    """
    Ask the user for an 8-byte DES key.

    DES requires exactly 8 bytes.
    """

    while True:

        key = input("Enter DES key (exactly 8 characters): ")

        if len(key.encode()) == 8:
            return key.encode()

        print("DES key must be exactly 8 bytes.")


# ============================================================
#                    ELGAMAL DIGITAL SIGNATURE
# ============================================================
#
# ElGamal Signature uses:
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
# SIGNING
# ------------------------------------------------------------
#
# Hash the message:
#
#       H = SHA256(message)
#
# Choose random k such that:
#
#       gcd(k, p-1) = 1
#
# Calculate:
#
#       r = g^k mod p
#
#       s = k^-1 (H - x*r) mod (p-1)
#
# Signature:
#
#       (r, s)
#
# ------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------
#
# Verify:
#
#       g^H mod p
#
# equals
#
#       y^r * r^s mod p
#
# ============================================================


# ------------------------------------------------------------
# FIND A PRIMITIVE ROOT / GENERATOR
# ------------------------------------------------------------
#
# For ElGamal we need a generator g.
#
# This function finds a primitive root modulo p.
#
# This implementation is intentionally simple for the lab.
# ------------------------------------------------------------

def find_generator(p):

    # Factor p-1.
    #
    # We need the prime factors of p-1 to test whether g
    # is a generator.
    factors = []

    value = p - 1
    factor = 2

    while factor * factor <= value:

        if value % factor == 0:

            factors.append(factor)

            while value % factor == 0:
                value //= factor

        factor += 1

    if value > 1:
        factors.append(value)


    # Try possible generators.
    for g in range(2, p):

        valid = True

        for factor in factors:

            # A primitive root must satisfy:
            #
            # g^((p-1)/q) != 1 mod p
            #
            # for every prime factor q of p-1.
            if pow(g, (p - 1) // factor, p) == 1:

                valid = False
                break

        if valid:
            return g

    raise ValueError("Could not find generator.")


# ------------------------------------------------------------
# GENERATE ELGAMAL KEY PAIR
# ------------------------------------------------------------

def generate_elgamal_keys():

    # Generate a prime p.
    #
    # 256 bits is enough for a lab demonstration.
    #
    # For real cryptographic systems, much stronger parameters
    # and standardized schemes should be used.
    p = getPrime(256)


    # Find generator g.
    g = find_generator(p)


    # --------------------------------------------------------
    # PRIVATE KEY
    # --------------------------------------------------------
    #
    # Choose:
    #
    #       1 < x < p-1
    #
    x = secrets.randbelow(p - 2) + 1


    # --------------------------------------------------------
    # PUBLIC KEY
    # --------------------------------------------------------
    #
    #       y = g^x mod p
    #
    y = pow(g, x, p)


    return {
        "p": p,
        "g": g,
        "x": x,
        "y": y
    }


# ============================================================
#                    ELGAMAL SIGNATURE
# ============================================================

def elgamal_sign(data, private_key):

    p = private_key["p"]
    g = private_key["g"]
    x = private_key["x"]


    # --------------------------------------------------------
    # STEP 1: SHA-256 HASH
    # --------------------------------------------------------
    #
    # We do NOT sign the entire data directly.
    #
    # Instead:
    #
    #       data
    #         ↓
    #       SHA-256
    #         ↓
    #       hash
    #
    # The hash is converted into an integer because ElGamal
    # operates on numbers.
    #
    hash_value = SHA256.new(data).digest()

    h = int.from_bytes(hash_value, "big")


    # --------------------------------------------------------
    # STEP 2: GENERATE RANDOM k
    # --------------------------------------------------------
    #
    # k must satisfy:
    #
    #       gcd(k, p-1) = 1
    #
    # because we need:
    #
    #       k^-1 mod (p-1)
    #
    while True:

        k = secrets.randbelow(p - 2) + 1

        if math.gcd(k, p - 1) == 1:
            break


    # --------------------------------------------------------
    # STEP 3: CALCULATE r
    # --------------------------------------------------------
    #
    #       r = g^k mod p
    #
    r = pow(g, k, p)


    # --------------------------------------------------------
    # STEP 4: CALCULATE s
    # --------------------------------------------------------
    #
    #       s = k^-1 (H - x*r) mod (p-1)
    #
    k_inverse = pow(k, -1, p - 1)

    s = (
        k_inverse * (h - x * r)
    ) % (p - 1)


    # Signature consists of:
    #
    #       (r, s)
    #
    return r, s


# ============================================================
#                 ELGAMAL SIGNATURE VERIFICATION
# ============================================================

def elgamal_verify(data, signature, public_key):

    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]


    r, s = signature


    # --------------------------------------------------------
    # CHECK THAT r AND s ARE VALID
    # --------------------------------------------------------

    if not (0 < r < p):
        return False

    if not (0 < s < p - 1):
        return False


    # --------------------------------------------------------
    # CALCULATE MESSAGE HASH AGAIN
    # --------------------------------------------------------
    #
    # The verifier independently calculates SHA-256.
    #
    hash_value = SHA256.new(data).digest()

    h = int.from_bytes(hash_value, "big")


    # --------------------------------------------------------
    # ELGAMAL VERIFICATION EQUATION
    # --------------------------------------------------------
    #
    # Left:
    #
    #       g^H mod p
    #
    left = pow(g, h, p)


    # Right:
    #
    #       y^r × r^s mod p
    #
    right = (
        pow(y, r, p) *
        pow(r, s, p)
    ) % p


    # If both values are equal, the signature is valid.
    return left == right


# ============================================================
#                    DES ENCRYPTION
# ============================================================
#
# DES works on 64-bit blocks.
#
# CBC = Cipher Block Chaining
#
# Encryption of each block depends on the previous ciphertext
# block.
#
# We need an IV:
#
#       IV = Initialization Vector
#
# IV is NOT secret and can be stored with ciphertext.
#
# ============================================================

def des_encrypt(plaintext, key):

    # Create a random 8-byte IV.
    #
    # DES block size = 8 bytes.
    #
    iv = secrets.token_bytes(8)


    # Create DES cipher in CBC mode.
    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )


    # Convert plaintext to bytes.
    plaintext_bytes = plaintext.encode()


    # CBC requires complete 8-byte blocks.
    #
    # PKCS#7 padding adds extra bytes when necessary.
    padded_data = pad(
        plaintext_bytes,
        DES.block_size
    )


    # Encrypt padded plaintext.
    ciphertext = cipher.encrypt(padded_data)


    # Return both ciphertext and IV.
    return ciphertext, iv


# ============================================================
#                    DES DECRYPTION
# ============================================================

def des_decrypt(ciphertext, key, iv):

    # Recreate the same DES-CBC cipher using:
    #
    #       same key
    #       same IV
    #
    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )


    # Decrypt ciphertext.
    padded_plaintext = cipher.decrypt(ciphertext)


    # Remove PKCS#7 padding.
    plaintext = unpad(
        padded_plaintext,
        DES.block_size
    )


    # Convert bytes back to string.
    return plaintext.decode()


# ============================================================
#                    SHA-256 HASH
# ============================================================

def calculate_hash(data):

    """
    Calculate SHA-256 hash of the supplied bytes.

    SHA-256 provides integrity verification.

    IMPORTANT:
    SHA-256 does NOT encrypt the data.
    """

    return SHA256.new(data).hexdigest()


# ============================================================
#                    AUDIT LOGGING
# ============================================================

def audit_log(role, operation, status):

    """
    Store role/activity/status with timestamp.

    Example:

    2026-09-21 04:20:10 | LAWYER | ACCESS | SUCCESS

    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    entry = (
        f"{timestamp} | "
        f"{role} | "
        f"{operation} | "
        f"{status}\n"
    )


    # Append instead of overwriting previous logs.
    with open(AUDIT_FILE, "a") as file:
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
    Store all information required for future verification.

    Notice that plaintext is NOT stored.

    We store:

        ciphertext
        IV
        SHA-256 hash
        ElGamal signature
        timestamp
        client's public key

    """

    record = {

        # Bytes cannot directly be stored in JSON.
        # Therefore convert them to hexadecimal strings.
        "ciphertext": ciphertext.hex(),

        "iv": iv.hex(),

        "sha256": hash_value,

        "signature": {
            "r": signature[0],
            "s": signature[1]
        },

        "timestamp": timestamp,

        "public_key": {
            "p": public_key["p"],
            "g": public_key["g"],
            "y": public_key["y"]
        }
    }


    # Write JSON file.
    with open(RECORD_FILE, "w") as file:

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
    Read the previously stored SecureVault record.
    """

    with open(RECORD_FILE, "r") as file:

        record = json.load(file)


    return record


# ============================================================
#                 CLIENT ROLE
# ============================================================

def client_role(private_key):

    print("\n================================")
    print("          CLIENT")
    print("================================")


    # --------------------------------------------------------
    # STEP 1: GET CONFIDENTIAL RECORD
    # --------------------------------------------------------

    plaintext = input(
        "Enter confidential client record: "
    )


    # --------------------------------------------------------
    # STEP 2: GET DES KEY
    # --------------------------------------------------------
    #
    # The client uses the DES key to encrypt the record.
    #
    des_key = get_des_key()


    # --------------------------------------------------------
    # STEP 3: DES-CBC ENCRYPTION
    # --------------------------------------------------------

    ciphertext, iv = des_encrypt(
        plaintext,
        des_key
    )


    # --------------------------------------------------------
    # STEP 4: SHA-256 OF ENCRYPTED DATA
    # --------------------------------------------------------
    #
    # IMPORTANT:
    #
    # The question specifically asks for the hash of the
    # ENCRYPTED DATA.
    #
    hash_value = calculate_hash(ciphertext)


    # --------------------------------------------------------
    # STEP 5: ELGAMAL DIGITAL SIGNATURE
    # --------------------------------------------------------
    #
    # We sign the encrypted ciphertext.
    #
    # Therefore the signature protects the ciphertext's
    # authenticity/integrity.
    #
    signature = elgamal_sign(
        ciphertext,
        private_key
    )


    # --------------------------------------------------------
    # STEP 6: TIMESTAMP
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # --------------------------------------------------------
    # STEP 7: GET CLIENT PUBLIC KEY
    # --------------------------------------------------------
    #
    # The lawyer and compliance officer need the public key
    # to verify the ElGamal signature.
    #
    public_key = {
        "p": private_key["p"],
        "g": private_key["g"],
        "y": private_key["y"]
    }


    # --------------------------------------------------------
    # STEP 8: SAVE EVERYTHING
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

    print("\n--- RECORD STORED SUCCESSFULLY ---")

    print("\nCiphertext:")
    print(ciphertext.hex())

    print("\nIV:")
    print(iv.hex())

    print("\nSHA-256 Hash:")
    print(hash_value)

    print("\nElGamal Signature:")
    print("r =", signature[0])
    print("s =", signature[1])

    print("\nTimestamp:")
    print(timestamp)


    # Audit the operation.
    audit_log(
        "CLIENT",
        "CREATE RECORD",
        "SUCCESS"
    )


# ============================================================
#                 VERIFY SECURITY METADATA
# ============================================================

def verify_record(record):

    """
    Common verification function.

    BOTH Lawyer and Compliance Officer need to perform:

        1. SHA-256 verification
        2. ElGamal signature verification

    Therefore we keep the logic in one reusable function.
    """

    # --------------------------------------------------------
    # RECOVER STORED CIPHERTEXT
    # --------------------------------------------------------

    ciphertext = bytes.fromhex(
        record["ciphertext"]
    )


    # --------------------------------------------------------
    # 1. SHA-256 VERIFICATION
    # --------------------------------------------------------

    # Calculate hash again from the current ciphertext.
    calculated_hash = calculate_hash(
        ciphertext
    )


    # Compare calculated hash with stored hash.
    hash_valid = (
        calculated_hash ==
        record["sha256"]
    )


    # --------------------------------------------------------
    # 2. ELGAMAL SIGNATURE VERIFICATION
    # --------------------------------------------------------

    # Recover stored signature.
    signature = (
        record["signature"]["r"],
        record["signature"]["s"]
    )


    # Recover client's public key.
    public_key = {
        "p": record["public_key"]["p"],
        "g": record["public_key"]["g"],
        "y": record["public_key"]["y"]
    }


    # Verify signature against ciphertext.
    signature_valid = elgamal_verify(
        ciphertext,
        signature,
        public_key
    )


    # Return both results.
    return hash_valid, signature_valid


# ============================================================
#                    LAWYER ROLE
# ============================================================

def lawyer_role():

    print("\n================================")
    print("          LAWYER")
    print("================================")


    # --------------------------------------------------------
    # STEP 1: LOAD STORED RECORD
    # --------------------------------------------------------

    try:

        record = load_record()

    except FileNotFoundError:

        print("No stored record found.")

        audit_log(
            "LAWYER",
            "ACCESS",
            "FAILED - RECORD NOT FOUND"
        )

        return


    # --------------------------------------------------------
    # STEP 2: VERIFY HASH + SIGNATURE
    # --------------------------------------------------------

    hash_valid, signature_valid = verify_record(
        record
    )


    # Display verification results.
    print("\n--- VERIFICATION RESULTS ---")

    print(
        "SHA-256 Hash:",
        "VALID" if hash_valid else "INVALID"
    )

    print(
        "ElGamal Signature:",
        "VALID" if signature_valid else "INVALID"
    )


    # --------------------------------------------------------
    # SECURITY CONDITION
    # --------------------------------------------------------
    #
    # Lawyer can decrypt ONLY if BOTH checks succeed.
    #
    #       hash_valid AND signature_valid
    #
    if not (hash_valid and signature_valid):

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
    # STEP 3: ASK FOR DES KEY
    # --------------------------------------------------------
    #
    # Only after successful verification do we request the
    # decryption key.
    #
    des_key = get_des_key()


    # Recover ciphertext and IV.
    ciphertext = bytes.fromhex(
        record["ciphertext"]
    )

    iv = bytes.fromhex(
        record["iv"]
    )


    # --------------------------------------------------------
    # STEP 4: DECRYPT
    # --------------------------------------------------------

    try:

        plaintext = des_decrypt(
            ciphertext,
            des_key,
            iv
        )


        # Display recovered record.
        print("\n--- DECRYPTED CLIENT RECORD ---")
        print(plaintext)


        # Record successful access.
        audit_log(
            "LAWYER",
            "ACCESS",
            "SUCCESS"
        )


    except Exception:

        # Wrong DES key or corrupted ciphertext can cause
        # decryption/padding failure.
        print(
            "\nDecryption failed."
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
    # STEP 1: LOAD STORED RECORD
    # --------------------------------------------------------

    try:

        record = load_record()

    except FileNotFoundError:

        print("No stored record found.")

        audit_log(
            "COMPLIANCE",
            "AUDIT",
            "FAILED - RECORD NOT FOUND"
        )

        return


    # --------------------------------------------------------
    # STEP 2: VERIFY HASH + SIGNATURE
    # --------------------------------------------------------
    #
    # The Compliance Officer performs exactly the same
    # security verification.
    #
    hash_valid, signature_valid = verify_record(
        record
    )


    # --------------------------------------------------------
    # STEP 3: DISPLAY RESULTS
    # --------------------------------------------------------

    print("\n--- COMPLIANCE VERIFICATION ---")

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
    # Compliance Officer NEVER receives the DES key.
    #
    # Therefore this function contains NO decryption code.
    #
    # This implements role-based access control.
    # --------------------------------------------------------


    # --------------------------------------------------------
    # STEP 4: GENERATE COMPLIANCE REPORT
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    report = {

        "report_timestamp": timestamp,

        "record_timestamp": record["timestamp"],

        "sha256_verification":
            "VALID" if hash_valid else "INVALID",

        "elgamal_verification":
            "VALID" if signature_valid else "INVALID",

        # Compliance officer can see security metadata,
        # but not plaintext.
        "plaintext_access": "NOT PERMITTED"
    }


    # Save report.
    with open(
        "compliance_report.json",
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )


    # Display report.
    print("\n--- COMPLIANCE REPORT ---")

    print(
        json.dumps(
            report,
            indent=4
        )
    )


    # Audit operation.
    audit_log(
        "COMPLIANCE",
        "AUDIT",
        "COMPLETED"
    )


# ============================================================
#                    MAIN PROGRAM
# ============================================================

def main():

    print("\n======================================")
    print("          SECUREVAULT")
    print("   Secure Record Management System")
    print("======================================")


    # --------------------------------------------------------
    # Generate client's ElGamal key pair.
    #
    # Private key:
    #
    #       x
    #
    # Public key:
    #
    #       (p, g, y)
    #
    # The client keeps the private key.
    # --------------------------------------------------------

    client_keys = generate_elgamal_keys()


    private_key = {
        "p": client_keys["p"],
        "g": client_keys["g"],
        "x": client_keys["x"],
        "y": client_keys["y"]
    }


    # --------------------------------------------------------
    # ROLE MENU
    # --------------------------------------------------------

    while True:

        print("\n--------------- MENU ---------------")

        print("1. Client")
        print("2. Lawyer")
        print("3. Compliance Officer")
        print("4. Exit")


        choice = input(
            "\nEnter choice: "
        )


        # ----------------------------------------------------
        # CLIENT
        # ----------------------------------------------------

        if choice == "1":

            client_role(private_key)


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


        else:

            print(
                "Invalid choice."
            )


# ============================================================
#                    PROGRAM START
# ============================================================

if __name__ == "__main__":

    main()
