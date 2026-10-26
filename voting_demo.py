
# ============================================================
# INFORMATION SECURITY LAB EXAM TOOLKIT
# FILE: voting_demo.py
#
# QUESTION 2: SECURE E-VOTING SYSTEM
# ============================================================
#
# AIM:
# To demonstrate a menu-driven electronic voting system
# using multiple cryptographic algorithms.
#
# ------------------------------------------------------------
# CRYPTOGRAPHIC TECHNIQUES USED
# ------------------------------------------------------------
#
# SHA-512:
#   Calculates a hash of the ballot for integrity.
#
# AES-256-CBC:
#   Encrypts the complete ballot for confidentiality.
#
# RSA-4096:
#   Encrypts the AES session key using RSA-OAEP.
#
# ELGAMAL DIGITAL SIGNATURE:
#   Signs the ballot using a private signing key.
#
# PAILLIER:
#   Encrypts candidate vote indicators.
#   Allows votes to be counted without decrypting
#   individual vote indicators.
#
# HMAC-SHA256:
#   Generates searchable constituency tokens.
#
# JSON:
#   Stores ballots and keys across program restarts.
#
# ------------------------------------------------------------
# IMPORTANT LIMITATIONS
# ------------------------------------------------------------
#
# This is a LOCAL CLASSROOM DEMONSTRATION.
#
# It is NOT a real secure electronic voting system.
#
# The following are NOT implemented:
#
# 1. Real voter authentication.
# 2. Trusted timestamp authority.
# 3. Threshold Paillier decryption.
# 4. One-vote-per-voter enforcement.
# 5. Zero-knowledge candidate validity proofs.
# 6. Fully private server-side searching.
#
# Also:
#
# The program uses one shared ElGamal signing key.
# It does not generate separate voter signing keys.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT LIBRARIES
# ============================================================

# Path:
# Used to create paths for JSON storage.

from pathlib import Path

# datetime:
# Used to generate ballot submission timestamps.
#
# timezone.utc:
# Ensures timestamps use UTC.

from datetime import datetime, timezone

# json:
# Used to convert ballot dictionaries into
# a consistent byte representation.

import json

# RSA:
# Used to reconstruct stored RSA private keys.

from Crypto.PublicKey import RSA

# Import reusable cryptographic functions.

from crypto_tools import (
    b64,
    unb64,
    get_random_bytes,
    load_json,
    save_json,
    rsa_keys,
    rsa_wrap,
    rsa_unwrap,
    symmetric_encrypt,
    symmetric_decrypt,
    hash_bytes,
    elgamal_signing_keys,
    elgamal_sign,
    elgamal_verify,
    paillier_keys,
    paillier_pack,
    paillier_unpack,
    paillier_sum,
    searchable_token
)


# ============================================================
# STEP 2: DEFINE STORAGE PATHS
# ============================================================

# Get folder containing this Python file.

ROOT = Path(__file__).parent

# File storing cryptographic keys.
KEYS = ROOT / "vote_keys.json"

# File storing encrypted ballot records.
DATA = ROOT / "ballots.json"


# ============================================================
# STEP 3: LOAD OR GENERATE KEYS
# ============================================================

def setup():

    # This function:
    #
    # 1. Loads previously stored keys if available.
    # 2. Generates new keys during the first execution.
    #
    # WHY SAVE KEYS?
    #
    # If keys change after restarting the program,
    # old encrypted ballots may become undecryptable.


    # --------------------------------------------------------
    # CASE 1: LOAD EXISTING KEYS
    # --------------------------------------------------------

    if KEYS.exists():

        # Read stored key information from JSON.

        stored = load_json(KEYS, {})


        # ----------------------------------------------------
        # LOAD RSA PRIVATE KEY
        # ----------------------------------------------------

        # RSA private key was stored as Base64 text.
        #
        # Decode and reconstruct it.

        rsa_private = RSA.import_key(
            unb64(stored["rsa"])
        )


        # ----------------------------------------------------
        # LOAD PAILLIER KEYS
        # ----------------------------------------------------

        from phe import paillier

        # Reconstruct public key using modulus n.

        paillier_public = paillier.PaillierPublicKey(
            int(stored["n"])
        )

        # Reconstruct private key using p and q.

        paillier_private = paillier.PaillierPrivateKey(
            paillier_public,
            int(stored["p"]),
            int(stored["q"])
        )


        # ----------------------------------------------------
        # LOAD ELGAMAL SIGNING KEYS
        # ----------------------------------------------------

        # ElGamal public key contains:
        #
        # (p, g, y)
        #
        # Convert stored strings back into integers.

        elgamal_public = tuple(
            map(int, stored["elg_public"])
        )

        # Load private signing key x.

        elgamal_private = int(
            stored["elg_private"]
        )


        # ----------------------------------------------------
        # LOAD SEARCH KEY
        # ----------------------------------------------------

        # Decode the stored HMAC search key.

        index_key = unb64(
            stored["index_key"]
        )


        # Return all keys.

        return (
            rsa_private,
            paillier_public,
            paillier_private,
            elgamal_public,
            elgamal_private,
            index_key
        )


    # --------------------------------------------------------
    # CASE 2: GENERATE NEW KEYS
    # --------------------------------------------------------

    # Generate RSA-4096 private/public key pair.
    #
    # RSA-4096 means the modulus is 4096 bits.
    #
    # The public key is obtained from the private key.

    _, rsa_private = rsa_keys(4096)


    # Generate Paillier keys.

    paillier_public, paillier_private = paillier_keys()


    # Generate ElGamal signing keys.

    elgamal_public, elgamal_private = elgamal_signing_keys()


    # Generate a 32-byte secret key for HMAC search.
    #
    # 32 bytes = 256 bits.

    index_key = get_random_bytes(32)


    # --------------------------------------------------------
    # SAVE KEYS
    # --------------------------------------------------------

    # Convert keys into JSON-compatible formats.
    #
    # RSA private key:
    # Export as bytes and Base64 encode.
    #
    # Paillier parameters:
    # Convert large integers into strings.
    #
    # ElGamal keys:
    # Convert integers into strings.
    #
    # Search key:
    # Convert bytes into Base64.

    key_record = {

        "rsa": b64(
            rsa_private.export_key()
        ),

        "n": str(paillier_public.n),

        "p": str(paillier_private.p),

        "q": str(paillier_private.q),

        "elg_public": list(
            map(str, elgamal_public)
        ),

        "elg_private": str(elgamal_private),

        "index_key": b64(index_key)
    }


    # Save key record persistently.

    save_json(
        KEYS,
        key_record
    )


    # WARNING:
    # Private keys are stored unencrypted in this demo.
    # Real systems require protected key storage.

    return (
        rsa_private,
        paillier_public,
        paillier_private,
        elgamal_public,
        elgamal_private,
        index_key
    )


# ============================================================
# STEP 4: CONVERT BALLOT INTO CONSISTENT BYTES
# ============================================================

def ballot_bytes(ballot):

    # WHAT IS CANONICALIZATION?
    #
    # It converts a dictionary into a consistent
    # representation before hashing and signing.
    #
    # sort_keys=True:
    # Sorts dictionary keys alphabetically.
    #
    # separators=(",", ":"):
    # Removes unnecessary spaces.
    #
    # encode():
    # Converts JSON text into bytes.
    #
    # This ensures the same ballot dictionary
    # produces the same byte sequence.

    return json.dumps(
        ballot,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


# ============================================================
# STEP 5: MAIN MENU-DRIVEN APPLICATION
# ============================================================

def main():

    # Load or generate keys.

    (
        rsa_private,
        paillier_public,
        paillier_private,
        elgamal_public,
        elgamal_private,
        index_key
    ) = setup()


    # Load previously saved ballots.
    #
    # If ballots.json does not exist, use {}.

    ballots = load_json(DATA, {})


    # --------------------------------------------------------
    # MAIN MENU LOOP
    # --------------------------------------------------------

    while True:

        print("\n========== E-VOTING DEMO ==========")
        print("1. Cast Ballot")
        print("2. Verify / Decrypt Ballot")
        print("3. Search Constituency")
        print("4. Tally Candidate Votes")
        print("0. Exit")

        choice = input(
            "Enter choice: "
        ).strip()


        # ====================================================
        # OPTION 0: EXIT
        # ====================================================

        if choice == "0":
            break


        # ====================================================
        # OPTION 1: CAST BALLOT
        # ====================================================

        elif choice == "1":

            # ------------------------------------------------
            # TAKE BALLOT DETAILS
            # ------------------------------------------------

            ballot_id = input(
                "Enter unique Ballot ID: "
            ).strip()

            constituency = input(
                "Enter Constituency: "
            ).strip()


            try:

                candidate = int(
                    input("Enter Candidate ID (1-3): ")
                )


                # ------------------------------------------------
                # VALIDATE BALLOT DETAILS
                # ------------------------------------------------

                # Reject:
                #
                # 1. Empty ballot ID.
                # 2. Duplicate ballot ID.
                # 3. Empty constituency.
                # 4. Invalid candidate ID.

                if (
                    not ballot_id
                    or ballot_id in ballots
                    or not constituency
                    or candidate not in (1, 2, 3)
                ):

                    raise ValueError


                # ------------------------------------------------
                # GENERATE TIMESTAMP
                # ------------------------------------------------

                # Record current UTC date and time.
                #
                # IMPORTANT:
                # This is the computer's local clock
                # expressed in UTC.
                #
                # It is NOT a trusted timestamp authority.

                timestamp = datetime.now(
                    timezone.utc
                ).isoformat()


                # ------------------------------------------------
                # CREATE ORIGINAL BALLOT
                # ------------------------------------------------

                ballot = {
                    "candidate": candidate,
                    "constituency": constituency,
                    "timestamp": timestamp
                }


                # ------------------------------------------------
                # CONVERT BALLOT TO BYTES
                # ------------------------------------------------

                # Convert dictionary into canonical JSON bytes.

                raw_ballot = ballot_bytes(ballot)


                # =================================================
                # STEP 1: CALCULATE SHA-512 HASH
                # =================================================

                # SHA-512 produces a 512-bit digest.
                #
                # The hash is used for integrity checking.

                digest = hash_bytes(
                    raw_ballot,
                    "sha512"
                )


                # =================================================
                # STEP 2: ENCRYPT BALLOT USING AES-256-CBC
                # =================================================

                # AES-256:
                # Uses a 256-bit symmetric key.
                #
                # CBC:
                # Cipher Block Chaining mode.
                #
                # The helper also generates an HMAC tag
                # to detect tampering.
                #
                # Returns:
                #
                # encrypted_ballot = Ciphertext envelope
                # aes_key = Random AES session key

                encrypted_ballot, aes_key = symmetric_encrypt(
                    raw_ballot,
                    "AES",
                    256,
                    "CBC"
                )


                # =================================================
                # STEP 3: ENCRYPT AES KEY USING RSA-4096
                # =================================================

                # RSA-OAEP encrypts the AES session key.
                #
                # This is HYBRID ENCRYPTION:
                #
                # AES encrypts the ballot.
                # RSA encrypts the AES key.
                #
                # The RSA private key is needed to
                # recover the AES key.

                wrapped_key = rsa_wrap(
                    rsa_private.publickey(),
                    aes_key
                )


                # =================================================
                # STEP 4: GENERATE ELGAMAL SIGNATURE
                # =================================================

                # Sign the original ballot bytes.
                #
                # elgamal_sign() uses SHA-512 by default.
                #
                # The private signing key generates
                # signature components (r, s).
                #
                # The public key verifies the signature.

                signature = elgamal_sign(
                    raw_ballot,
                    elgamal_public,
                    elgamal_private
                )


                # =================================================
                # STEP 5: ENCRYPT VOTE USING PAILLIER
                # =================================================

                # IMPORTANT CONCEPT:
                #
                # To count votes for each candidate,
                # we use ONE-HOT ENCODING.
                #
                # Example:
                #
                # Candidate 1 -> [1, 0, 0]
                # Candidate 2 -> [0, 1, 0]
                # Candidate 3 -> [0, 0, 1]
                #
                # WHY?
                #
                # If we simply add candidate IDs:
                #
                # Candidate 1 + Candidate 3 = 4
                #
                # This does not tell us how many votes
                # each candidate received.
                #
                # Instead, we encrypt each indicator:
                #
                # 1 = Vote for this candidate
                # 0 = No vote for this candidate
                #
                # Paillier can then add encrypted
                # indicators for each candidate.

                encrypted_votes = []

                for candidate_number in (1, 2, 3):

                    # int(True) = 1
                    # int(False) = 0
                    #
                    # Example:
                    #
                    # candidate = 2
                    #
                    # Results:
                    #
                    # 1 == 2 -> 0
                    # 2 == 2 -> 1
                    # 3 == 2 -> 0

                    vote_indicator = int(
                        candidate_number == candidate
                    )

                    # Encrypt indicator using Paillier.

                    encrypted_vote = paillier_public.encrypt(
                        vote_indicator
                    )

                    # Convert encrypted number for JSON.

                    packed_vote = paillier_pack(
                        encrypted_vote
                    )

                    encrypted_votes.append(
                        packed_vote
                    )


                # =================================================
                # STEP 6: CREATE SEARCHABLE CONSTITUENCY TOKEN
                # =================================================

                # Generate HMAC-SHA256 token.
                #
                # The same constituency and key produce
                # the same token.
                #
                # This allows searching by constituency
                # without storing the plaintext constituency
                # as a separate searchable index value.

                search_token = searchable_token(
                    constituency,
                    index_key
                )


                # =================================================
                # STEP 7: STORE BALLOT RECORD
                # =================================================

                # Save all encrypted data and metadata.
                #
                # The record includes:
                #
                # - AES encrypted ballot
                # - RSA encrypted AES key
                # - SHA-512 hash
                # - ElGamal signature
                # - Paillier encrypted vote vector
                # - Search token
                # - Timestamp

                ballots[ballot_id] = {

                    "ballot": encrypted_ballot,

                    "wrapped_key": wrapped_key,

                    "hash": digest,

                    "signature": signature,

                    "votes": encrypted_votes,

                    "search_token": search_token,

                    "timestamp": timestamp
                }


                # Save records to JSON file.

                save_json(
                    DATA,
                    ballots
                )


                # ------------------------------------------------
                # DISPLAY RESULT
                # ------------------------------------------------

                print(
                    "Ballot stored:",
                    ballot_id
                )

                print(
                    "SHA-512:",
                    digest
                )

                print(
                    "Local UTC Timestamp:",
                    timestamp
                )


            except ValueError:

                print("Invalid ballot input.")


        # ====================================================
        # OPTION 2: VERIFY AND DECRYPT BALLOT
        # ====================================================

        elif choice == "2":

            # Take ballot ID.

            ballot_id = input(
                "Enter Ballot ID: "
            ).strip()

            # Search stored ballot.

            record = ballots.get(ballot_id)


            if not record:

                print("Ballot not found.")
                continue


            try:

                # ------------------------------------------------
                # STEP 1: DECRYPT AES SESSION KEY
                # ------------------------------------------------

                # Use RSA private key to recover AES key.

                aes_key = rsa_unwrap(
                    rsa_private,
                    record["wrapped_key"]
                )


                # ------------------------------------------------
                # STEP 2: DECRYPT BALLOT
                # ------------------------------------------------

                # Use recovered AES key.
                #
                # CBC decryption also verifies the HMAC tag.

                raw_ballot = symmetric_decrypt(
                    record["ballot"],
                    aes_key
                )


                # ------------------------------------------------
                # STEP 3: VERIFY SHA-512 HASH
                # ------------------------------------------------

                # Recalculate SHA-512 and compare
                # with stored hash.

                calculated_hash = hash_bytes(
                    raw_ballot,
                    "sha512"
                )

                hash_valid = (
                    calculated_hash == record["hash"]
                )

                print(
                    "SHA-512 Integrity:",
                    hash_valid
                )


                # ------------------------------------------------
                # STEP 4: VERIFY ELGAMAL SIGNATURE
                # ------------------------------------------------

                # Use ElGamal public key to verify
                # the signature over ballot bytes.

                signature_valid = elgamal_verify(
                    raw_ballot,
                    record["signature"],
                    elgamal_public
                )

                print(
                    "ElGamal Signature:",
                    signature_valid
                )


                # ------------------------------------------------
                # STEP 5: DISPLAY DECRYPTED BALLOT
                # ------------------------------------------------

                # The original program prints the ballot
                # even if hash or signature verification
                # returns False.
                #
                # For stronger handling, display sensitive
                # ballot contents only after both checks pass.

                print(
                    "Ballot:",
                    raw_ballot.decode("utf-8")
                )

                print(
                    "Timestamp is local/untrusted."
                )

                print(
                    "Deadline compliance cannot be certified."
                )


            except (
                ValueError,
                KeyError,
                TypeError
            ) as error:

                print(
                    "Tampered or invalid ballot:",
                    error
                )


        # ====================================================
        # OPTION 3: SEARCH BY CONSTITUENCY
        # ====================================================

        elif choice == "3":

            # Take constituency query.

            constituency = input(
                "Enter Constituency: "
            )


            # ------------------------------------------------
            # GENERATE SEARCH TOKEN
            # ------------------------------------------------

            # Use the same HMAC search key.
            #
            # Example:
            #
            # "C101" -> HMAC token

            token = searchable_token(
                constituency,
                index_key
            )


            # ------------------------------------------------
            # FIND MATCHING BALLOTS
            # ------------------------------------------------

            # Compare search token with stored tokens.
            #
            # Matching ballot IDs are returned.
            #
            # The encrypted ballot contents are not
            # decrypted during this search.

            matching_ids = [

                ballot_id

                for ballot_id, record in ballots.items()

                if record.get("search_token") == token
            ]


            print(
                "Matching Ballot IDs:",
                matching_ids
            )


        # ====================================================
        # OPTION 4: HOMOMORPHIC VOTE TALLY
        # ====================================================

        elif choice == "4":

            # IMPORTANT:
            #
            # We verify ballots before counting them.
            #
            # We do NOT decrypt individual Paillier
            # vote indicators.
            #
            # We decrypt only the final encrypted
            # total for each candidate.


            # ------------------------------------------------
            # STEP 1: CREATE VERIFIED BALLOT LIST
            # ------------------------------------------------

            selected_ballots = []


            # ------------------------------------------------
            # STEP 2: VERIFY EVERY BALLOT
            # ------------------------------------------------

            for ballot_id, record in ballots.items():

                try:

                    # Recover AES session key.

                    aes_key = rsa_unwrap(
                        rsa_private,
                        record["wrapped_key"]
                    )


                    # Decrypt ballot and verify HMAC.

                    raw_ballot = symmetric_decrypt(
                        record["ballot"],
                        aes_key
                    )


                    # Recalculate SHA-512 hash.

                    hash_valid = (
                        hash_bytes(
                            raw_ballot,
                            "sha512"
                        ) == record["hash"]
                    )


                    # Verify ElGamal signature.

                    signature_valid = elgamal_verify(
                        raw_ballot,
                        record["signature"],
                        elgamal_public
                    )


                    # Skip invalid ballots.

                    if not hash_valid or not signature_valid:

                        print(
                            "Skipping invalid ballot:",
                            ballot_id
                        )

                        continue


                    # Add verified ballot to tally list.

                    selected_ballots.append(
                        record
                    )


                except (
                    ValueError,
                    KeyError,
                    TypeError
                ):

                    print(
                        "Skipping corrupted ballot:",
                        ballot_id
                    )


            # ------------------------------------------------
            # STEP 3: DISPLAY VERIFIED BALLOT COUNT
            # ------------------------------------------------

            print(
                "Verified Ballots:",
                len(selected_ballots)
            )


            # =================================================
            # STEP 4: HOMOMORPHICALLY TALLY EACH CANDIDATE
            # =================================================

            # There are three candidates.
            #
            # i = 0 -> Candidate 1
            # i = 1 -> Candidate 2
            # i = 2 -> Candidate 3

            for i in range(3):

                # ------------------------------------------------
                # RESTORE ENCRYPTED VOTE INDICATORS
                # ------------------------------------------------

                # Extract the encrypted vote indicator
                # for candidate i from each verified ballot.

                encrypted_indicators = [

                    paillier_unpack(
                        paillier_public,
                        record["votes"][i]
                    )

                    for record in selected_ballots
                ]


                # ------------------------------------------------
                # HOMOMORPHIC ADDITION
                # ------------------------------------------------

                # Add encrypted vote indicators.
                #
                # Paillier performs:
                #
                # E(a) + E(b) = E(a+b)
                #
                # The library handles ciphertext arithmetic.

                encrypted_total = paillier_sum(
                    paillier_public,
                    encrypted_indicators
                )


                # ------------------------------------------------
                # DISPLAY ENCRYPTED TALLY
                # ------------------------------------------------

                # Display only first 50 digits
                # because Paillier ciphertexts are large.

                ciphertext_preview = str(
                    encrypted_total.ciphertext()
                )[:50]

                print(
                    "Candidate",
                    i + 1,
                    "Encrypted Tally:",
                    ciphertext_preview + "..."
                )


                # ------------------------------------------------
                # DECRYPT FINAL COUNT
                # ------------------------------------------------

                # Only the final aggregated count
                # is decrypted.
                #
                # Individual vote indicators remain encrypted.

                final_count = paillier_private.decrypt(
                    encrypted_total
                )

                print(
                    "Candidate",
                    i + 1,
                    "Final Count:",
                    final_count
                )


            print(
                "WARNING: This demonstration uses "
                "single-authority decryption."
            )

            print(
                "Threshold decryption is NOT implemented."
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
