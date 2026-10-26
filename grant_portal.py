
# ============================================================
# INFORMATION SECURITY LAB EXAM
# FILE: grant_portal.py
#
# QUESTION: SECURE GRANT EXPENSE PORTAL
# ============================================================
#
# AIM:
# Create a menu-driven grant management system where:
#
# 1. Researchers submit encrypted grant records.
# 2. Reviewers verify integrity and authenticity.
# 3. Finance officers calculate encrypted totals.
# 4. Records remain saved after restarting the program.
#
# ------------------------------------------------------------
# CRYPTOGRAPHIC TECHNIQUES USED
# ------------------------------------------------------------
#
# AES-192:
#   Encrypts grant descriptions.
#
# PAILLIER:
#   Encrypts grant amounts and supports addition
#   without decrypting individual amounts.
#
# MD5:
#   Generates a 128-bit hash of the stored record.
#
# RSA-PSS:
#   Digitally signs the MD5 digest text.
#
# JSON:
#   Stores encrypted grant records and cryptographic keys.
#
# IMPORTANT:
# MD5 is collision-insecure. It is used here because
# the exam question explicitly requires it.
#
# This program uses role selection for demonstration.
# It does not authenticate real user identities.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT LIBRARIES
# ============================================================

# Path:
# Helps create file paths.

from pathlib import Path

# json:
# Converts dictionaries into a consistent byte format
# for hashing and signing.

import json

# hmac:
# Used to compare MD5 hashes safely.
#
# This import is REQUIRED because verify()
# calls hmac.compare_digest().

import hmac

# RSA:
# Used to load stored RSA private keys.

from Crypto.PublicKey import RSA

# Import reusable cryptographic functions.
#
# These functions are defined in crypto_tools.py.

from crypto_tools import (
    b64,
    unb64,
    get_random_bytes,
    load_json,
    save_json,
    rsa_keys,
    paillier_keys,
    paillier_pack,
    paillier_unpack,
    paillier_sum,
    symmetric_encrypt,
    symmetric_decrypt,
    hash_bytes,
    rsa_sign,
    rsa_verify,
    hex_dump
)


# ============================================================
# STEP 2: DEFINE STORAGE FILE PATHS
# ============================================================

# __file__ represents the current Python file.
#
# Path(__file__).parent gives its folder.
#
# This ensures that JSON files are stored beside
# grant_portal.py, regardless of the working directory.

ROOT = Path(__file__).parent

# File used to store grant records.
DATA = ROOT / "grant_records.json"

# File used to store encryption and signing keys.
KEYS = ROOT / "grant_keys.json"


# ============================================================
# STEP 3: SET UP CRYPTOGRAPHIC KEYS
# ============================================================

def setup():

    # This function either:
    #
    # 1. Loads previously saved keys, OR
    # 2. Generates new keys on the first execution.
    #
    # WHY SAVE KEYS?
    #
    # If we generate new keys every time the program
    # starts, old encrypted records may become
    # impossible to decrypt.
    #
    # Therefore, keys must persist across restarts.


    # --------------------------------------------------------
    # CASE 1: KEY FILE ALREADY EXISTS
    # --------------------------------------------------------

    if KEYS.exists():

        # Load existing keys from JSON file.

        stored_keys = load_json(KEYS, {})


        # ----------------------------------------------------
        # LOAD RSA PRIVATE KEY
        # ----------------------------------------------------

        # The RSA private key was saved as Base64 text.
        #
        # unb64() converts Base64 back into bytes.
        #
        # RSA.import_key() reconstructs the RSA key.

        rsa_private = RSA.import_key(
            unb64(stored_keys["rsa_private"])
        )


        # ----------------------------------------------------
        # LOAD PAILLIER KEYS
        # ----------------------------------------------------

        from phe import paillier

        # Reconstruct Paillier public key from n.
        #
        # n = p * q

        paillier_public = paillier.PaillierPublicKey(
            int(stored_keys["paillier_n"])
        )

        # Reconstruct Paillier private key using
        # the two prime numbers p and q.

        paillier_private = paillier.PaillierPrivateKey(
            paillier_public,
            int(stored_keys["paillier_p"]),
            int(stored_keys["paillier_q"])
        )


        # ----------------------------------------------------
        # LOAD AES KEY
        # ----------------------------------------------------

        # AES key was stored as Base64 text.
        #
        # Decode it back into the original 24 bytes.
        #
        # 24 bytes * 8 = 192 bits.

        aes_key = unb64(stored_keys["aes"])


        # Return all loaded keys.

        return (
            aes_key,
            rsa_private,
            paillier_public,
            paillier_private
        )


    # --------------------------------------------------------
    # CASE 2: FIRST EXECUTION - GENERATE NEW KEYS
    # --------------------------------------------------------

    # Generate RSA public/private key pair.
    #
    # We keep the private key because the public key
    # can be obtained using private_key.publickey().

    _, rsa_private = rsa_keys()


    # Generate Paillier public/private keys.

    paillier_public, paillier_private = paillier_keys()


    # Generate a 24-byte AES key.
    #
    # 24 * 8 = 192 bits.
    #
    # Therefore, AES-192 is used.

    aes_key = get_random_bytes(24)


    # --------------------------------------------------------
    # SAVE KEYS FOR FUTURE EXECUTIONS
    # --------------------------------------------------------

    # Create dictionary containing key information.
    #
    # Large Paillier integers are converted to strings.
    #
    # Binary AES/RSA keys are converted to Base64.

    key_record = {

        "aes": b64(aes_key),

        "rsa_private": b64(
            rsa_private.export_key()
        ),

        "paillier_n": str(paillier_public.n),

        "paillier_p": str(paillier_private.p),

        "paillier_q": str(paillier_private.q)
    }


    # Save keys to JSON file.

    save_json(KEYS, key_record)

    print("New cryptographic keys generated.")
    print("Keys saved for future program runs.")

    # WARNING:
    # This classroom demo stores private keys unencrypted.
    # Never expose grant_keys.json in a real application.

    return (
        aes_key,
        rsa_private,
        paillier_public,
        paillier_private
    )


# ============================================================
# STEP 4: CREATE CANONICAL RECORD
# ============================================================

def canonical(record):

    # WHAT IS CANONICALIZATION?
    #
    # Canonicalization converts data into a consistent
    # representation before hashing or signing.
    #
    # WHY IS IT NEEDED?
    #
    # JSON dictionaries can contain keys in different
    # orders.
    #
    # We want the same record to always produce
    # exactly the same bytes.
    #
    # We hash three stored fields:
    #
    # 1. Grant ID
    # 2. Encrypted description
    # 3. Encrypted amount
    #
    # We do NOT include the MD5 or signature fields
    # because they are calculated afterward.

    selected_fields = {
        "id": record["id"],
        "description": record["description"],
        "amount": record["amount"]
    }

    # sort_keys=True:
    # Sorts dictionary keys consistently.
    #
    # separators=(",", ":"):
    # Removes unnecessary spaces.
    #
    # encode():
    # Converts JSON string into bytes.

    return json.dumps(
        selected_fields,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


# ============================================================
# STEP 5: VERIFY RECORD INTEGRITY AND SIGNATURE
# ============================================================

def verify(record, rsa_public):

    # This function checks:
    #
    # 1. Whether the stored MD5 matches the record.
    # 2. Whether the RSA digital signature is valid.
    #
    # Both must pass for the record to be accepted.

    try:

        # ----------------------------------------------------
        # VERIFY MD5 INTEGRITY
        # ----------------------------------------------------

        # Recalculate MD5 of the stored record fields.

        calculated_md5 = hash_bytes(
            canonical(record),
            "md5"
        )

        # Compare newly calculated MD5 with stored MD5.
        #
        # True means both digests match.

        hash_ok = hmac.compare_digest(
            calculated_md5,
            record["md5"]
        )


        # ----------------------------------------------------
        # VERIFY RSA DIGITAL SIGNATURE
        # ----------------------------------------------------

        # During submission, the program signed
        # the stored MD5 hexadecimal text.
        #
        # rsa_verify() hashes that text using SHA-256
        # internally before RSA-PSS verification.
        #
        # Therefore, this is RSA-PSS/SHA-256 over
        # the MD5 hex string, not direct raw-MD5 signing.

        signature_ok = rsa_verify(
            record["md5"].encode("utf-8"),
            record["signature"],
            rsa_public
        )


        # ----------------------------------------------------
        # FINAL VERIFICATION RESULT
        # ----------------------------------------------------

        # Both checks must pass.

        is_valid = hash_ok and signature_ok

        # Return three Boolean values.
        #
        # is_valid:
        #   Overall result.
        #
        # hash_ok:
        #   MD5 integrity result.
        #
        # signature_ok:
        #   RSA signature verification result.

        return is_valid, hash_ok, signature_ok

    except (KeyError, ValueError, TypeError):

        # Handle missing or invalid record fields.

        return False, False, False


# ============================================================
# STEP 6: MAIN MENU-DRIVEN APPLICATION
# ============================================================

def main():

    # Load or generate cryptographic keys.

    aes_key, rsa_private, paillier_public, paillier_private = setup()

    # Obtain RSA public key from private key.

    rsa_public = rsa_private.publickey()


    # --------------------------------------------------------
    # LOAD PREVIOUS GRANT RECORDS
    # --------------------------------------------------------

    # If the file exists, load stored records.
    #
    # Otherwise, start with an empty dictionary.

    records = load_json(DATA, {})


    # --------------------------------------------------------
    # MAIN MENU LOOP
    # --------------------------------------------------------

    # while True keeps the program running until
    # the user chooses Exit.

    while True:

        print("\n========== GRANT PORTAL ==========")
        print("1. Researcher")
        print("2. Reviewer")
        print("3. Finance Officer")
        print("0. Exit")

        role = input("Choose role: ").strip()


        # ====================================================
        # ROLE 1: RESEARCHER
        # ====================================================

        if role == "0":
            break

        elif role == "1":

            print("\n--- RESEARCHER MENU ---")
            print("1. Submit Grant")
            print("2. List Records")

            choice = input("Choose: ").strip()


            # ------------------------------------------------
            # SUBMIT NEW GRANT
            # ------------------------------------------------

            if choice == "1":

                # Take Grant ID.

                grant_id = input(
                    "Enter Grant ID: "
                ).strip()

                # Reject empty or duplicate IDs.
                #
                # A dictionary cannot store two records
                # under the same unique key.

                if not grant_id or grant_id in records:
                    print("Invalid or duplicate Grant ID.")
                    continue


                # Take grant description.

                description = input(
                    "Enter Grant Description: "
                ).strip()


                try:

                    # Take amount as an integer.

                    amount = int(
                        input("Enter Grant Amount: ")
                    )


                    # ------------------------------------------------
                    # VALIDATE AMOUNT
                    # ------------------------------------------------

                    # Amount must be nonnegative.
                    #
                    # Paillier plaintext must also fit
                    # within the supported numeric range.

                    if amount < 0 or amount >= paillier_public.n:
                        raise ValueError


                    # ------------------------------------------------
                    # ENCRYPT DESCRIPTION USING AES-192
                    # ------------------------------------------------

                    # Convert description into bytes.
                    #
                    # Encrypt using:
                    #
                    # Algorithm = AES
                    # Key size  = 192 bits
                    # Mode      = GCM
                    #
                    # We supply the persistent AES key.

                    encrypted_description, _ = symmetric_encrypt(
                        description.encode("utf-8"),
                        "AES",
                        192,
                        "GCM",
                        aes_key
                    )


                    # ------------------------------------------------
                    # ENCRYPT AMOUNT USING PAILLIER
                    # ------------------------------------------------

                    # Encrypt amount using Paillier public key.
                    #
                    # paillier_pack() converts encrypted
                    # number into a JSON-compatible dictionary.

                    encrypted_amount = paillier_pack(
                        paillier_public.encrypt(amount)
                    )


                    # ------------------------------------------------
                    # CREATE RECORD
                    # ------------------------------------------------

                    record = {
                        "id": grant_id,
                        "description": encrypted_description,
                        "amount": encrypted_amount
                    }


                    # ------------------------------------------------
                    # CALCULATE MD5 HASH
                    # ------------------------------------------------

                    # Calculate MD5 of the canonical record.
                    #
                    # This includes the encrypted description
                    # and encrypted amount.

                    record["md5"] = hash_bytes(
                        canonical(record),
                        "md5"
                    )


                    # ------------------------------------------------
                    # GENERATE RSA DIGITAL SIGNATURE
                    # ------------------------------------------------

                    # Sign the MD5 hexadecimal string.
                    #
                    # RSA-PSS uses SHA-256 internally
                    # in the existing helper.

                    record["signature"] = rsa_sign(
                        record["md5"].encode("utf-8"),
                        rsa_private
                    )


                    # ------------------------------------------------
                    # SAVE RECORD
                    # ------------------------------------------------

                    # Store record using Grant ID as key.

                    records[grant_id] = record

                    # Save all records to JSON.
                    #
                    # This ensures records remain available
                    # after restarting the program.

                    save_json(DATA, records)

                    print(
                        "Grant saved successfully:",
                        grant_id
                    )

                except ValueError:

                    print("Invalid grant amount.")


            # ------------------------------------------------
            # LIST EXISTING RECORDS
            # ------------------------------------------------

            elif choice == "2":

                print("\n--- STORED GRANT RECORDS ---")

                # Iterate through all saved records.

                for grant_id, record in records.items():

                    print("Grant ID:", grant_id)

                    print(
                        "MD5:",
                        record.get("md5")
                    )

                    # Display only first 32 characters
                    # of encrypted amount for readability.

                    encrypted_value = str(
                        record.get("amount", {}).get("c", "")
                    )

                    print(
                        "Encrypted Amount:",
                        encrypted_value[:32] + "..."
                    )

                    print("----------------------")


        # ====================================================
        # ROLE 2: REVIEWER
        # ====================================================

        elif role == "2":

            print("\n--- REVIEWER MENU ---")

            # Search record using Grant ID.

            grant_id = input(
                "Enter Grant ID to review: "
            ).strip()

            record = records.get(grant_id)


            # Check whether record exists.

            if not record:
                print("Grant not found.")
                continue


            # ------------------------------------------------
            # VERIFY MD5 AND RSA SIGNATURE
            # ------------------------------------------------

            is_valid, hash_ok, signature_ok = verify(
                record,
                rsa_public
            )

            print("MD5 Integrity:", hash_ok)
            print("RSA Signature:", signature_ok)


            # ------------------------------------------------
            # DECRYPT DESCRIPTION IF VALID
            # ------------------------------------------------

            if is_valid:

                try:

                    # Decrypt AES-192 encrypted description.

                    decrypted_description = symmetric_decrypt(
                        record["description"],
                        aes_key
                    )

                    # Display decrypted bytes in hexadecimal.
                    #
                    # Example:
                    #
                    # "ABC" -> 41 42 43

                    print(
                        "Decrypted Description (HEX):",
                        hex_dump(decrypted_description)
                    )

                except (ValueError, KeyError):

                    print(
                        "Description decryption failed."
                    )

            else:

                print(
                    "Record tampered or signature invalid."
                )


        # ====================================================
        # ROLE 3: FINANCE OFFICER
        # ====================================================

        elif role == "3":

            print("\n--- FINANCE OFFICER MENU ---")

            # Take comma-separated Grant IDs.
            #
            # Example:
            # G101,G102,G103

            entered_ids = input(
                "Enter Grant IDs separated by commas: "
            )

            # split(","):
            # Separates IDs using commas.
            #
            # strip():
            # Removes extra spaces.
            #
            # Example:
            # "G101, G102"
            #
            # becomes:
            # ["G101", "G102"]

            selected_ids = [
                item.strip()
                for item in entered_ids.split(",")
                if item.strip()
            ]


            # ------------------------------------------------
            # VALIDATE SELECTED IDS
            # ------------------------------------------------

            # Reject:
            #
            # 1. Empty selection.
            # 2. Duplicate Grant IDs.
            # 3. Missing Grant IDs.

            if (
                not selected_ids
                or len(selected_ids) != len(set(selected_ids))
                or any(item not in records for item in selected_ids)
            ):

                print(
                    "Invalid, duplicate or missing Grant ID."
                )
                continue


            # ------------------------------------------------
            # VERIFY ALL SELECTED RECORDS
            # ------------------------------------------------

            # Do not aggregate records whose integrity
            # or signature verification fails.

            if any(
                not verify(records[item], rsa_public)[0]
                for item in selected_ids
            ):

                print(
                    "Verification failed. Aggregation cancelled."
                )
                continue


            # ------------------------------------------------
            # PERFORM HOMOMORPHIC ADDITION
            # ------------------------------------------------

            try:

                # Convert stored Paillier ciphertexts
                # into EncryptedNumber objects.

                encrypted_amounts = [
                    paillier_unpack(
                        paillier_public,
                        records[item]["amount"]
                    )
                    for item in selected_ids
                ]


                # Add encrypted values.
                #
                # IMPORTANT:
                #
                # Individual amounts are NOT decrypted.
                #
                # Paillier supports:
                #
                # E(a) + E(b) = E(a+b)
                #
                # The phe library handles the
                # ciphertext arithmetic internally.

                encrypted_total = paillier_sum(
                    paillier_public,
                    encrypted_amounts
                )


                # Display encrypted aggregate.

                print(
                    "Aggregated Ciphertext:",
                    encrypted_total.ciphertext()
                )


                # ------------------------------------------------
                # DECRYPT ONLY FINAL TOTAL
                # ------------------------------------------------

                # The individual grant amounts remain
                # encrypted throughout aggregation.

                final_total = paillier_private.decrypt(
                    encrypted_total
                )

                print(
                    "Final Grant Expenditure:",
                    final_total
                )

            except (ValueError, KeyError, OverflowError) as error:

                print(
                    "Invalid encrypted amount:",
                    error
                )


        # ====================================================
        # INVALID MENU CHOICE
        # ====================================================

        else:

            print("Invalid menu choice.")


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    main()
