'''
HealthSecure

A hospital wants to develop a secure patient-information management system called HealthSecure. The system has three roles: Doctor, Nurse, and Admin.

The system must ensure the confidentiality, integrity, and authenticity of patient information such as name, age,
gender, blood group, diagnosis, and other medical details.

Doctor:

The Doctor should be able to:

Enter patient information such as Name, Age, Gender, Blood Group, Diagnosis, etc.

Store the patient information in a suitable data structure such as a list, array, dictionary, or file.

Generate an RSA key pair consisting of a public key and private key.

Encrypt the patient information using RSA encryption and the Doctor's RSA public key.

Compute the SHA-256 hash of the encrypted patient information.

Digitally sign the SHA-256 hash using the Doctor's RSA private key.

Store the encrypted patient data, SHA-256 hash, digital signature, and timestamp.

View previously stored patient records.

Decrypt an encrypted patient record using the corresponding RSA private key.

Recompute the SHA-256 hash of the encrypted data and compare it with the stored hash to verify integrity.

Verify the RSA digital signature using the Doctor's public key to verify authenticity.

Display the decrypted patient information only when the integrity and signature verification are successful.


Nurse:

The Nurse should be able to:

View the available encrypted patient records.

View the filename/record ID, encrypted data, hash, signature, and timestamp as permitted.

Must not be allowed to decrypt or view the plaintext patient information.

Recompute the SHA-256 hash of the encrypted data and compare it with the stored hash to verify data integrity.

Verify the Doctor's RSA digital signature using the Doctor's public key to verify authenticity.

Display the verification result along with a timestamp.

The Nurse must not have access to the Doctor's private key.


Admin:

The Admin should be able to:

View only the patient record ID/name, SHA-256 hash, and timestamp.

Verify the Doctor's RSA digital signature using the Doctor's public key.

Display whether the digital signature is VALID or INVALID.

The Admin must not be allowed to decrypt or view the plaintext patient information.

The Admin must not have access to the Doctor's private key.


Task:

Develop a menu-driven Python program implementing the above requirements using:

RSA asymmetric encryption and decryption

RSA public and private keys

SHA-256 hashing

RSA digital signatures

Role-Based Access Control (RBAC)

Patient data handling using lists, dictionaries, arrays, or files

Timestamps

Secure storage of encrypted records, hashes, signatures, and other required information

Appropriate access restrictions for Doctor, Nurse, and Admin

The program should ensure that each role can perform only its authorized operations and that patient information remains
confidential while its integrity and authenticity can be verified.
'''
import json
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# ============================================================
#                    CONFIGURATION
# ============================================================

RECORD_FILE = "patient_records.json"
AUDIT_FILE = "healthsecure_audit.log"


# ============================================================
#                    RSA KEY GENERATION
# ============================================================
#
# RSA uses two keys:
#
#       PUBLIC KEY
#           ↓
#       Encryption
#
#       PRIVATE KEY
#           ↓
#       Decryption
#
# For digital signatures:
#
#       PRIVATE KEY
#           ↓
#       Signing
#
#       PUBLIC KEY
#           ↓
#       Verification
#
# Therefore the Doctor's private key must NEVER be given to
# the Nurse or Admin.
# ============================================================

def generate_rsa_keys():

    # Generate a 2048-bit RSA key pair.
    #
    # The same RSA key pair is used for:
    #
    #       1. Encryption/decryption
    #       2. Digital signature/verification
    #
    # For a real system, separate keys for encryption and
    # signing are generally preferable.
    key = RSA.generate(2048)


    # Export private key.
    #
    # The private key contains secret information and must
    # be protected.
    private_key = key.export_key()


    # Export only the public part.
    #
    # Public key can safely be distributed to others.
    public_key = key.publickey().export_key()


    return private_key, public_key


# ============================================================
#                 RSA ENCRYPTION
# ============================================================
#
# RSA encryption:
#
#       plaintext
#           ↓
#       Doctor's PUBLIC KEY
#           ↓
#       ciphertext
#
# IMPORTANT:
#
# RSA should NOT normally be used to encrypt arbitrary large
# patient records directly.
#
# A real system would normally use:
#
#       AES → encrypt patient data
#       RSA → encrypt AES key
#
# But the question explicitly asks for RSA encryption, so
# this implementation uses RSA directly.
#
# Because RSA can encrypt only limited-size messages, the
# program checks the message size.
# ============================================================

def rsa_encrypt(data, public_key):

    # Import public key.
    key = RSA.import_key(public_key)


    # OAEP is the appropriate RSA encryption padding used here.
    cipher = PKCS1_OAEP.new(key)


    try:

        # Encrypt the patient data.
        ciphertext = cipher.encrypt(data.encode())

        return ciphertext


    except ValueError:

        # RSA-OAEP has a maximum plaintext size.
        #
        # For a 2048-bit RSA key with SHA-1 OAEP, the limit is
        # approximately 214 bytes.
        #
        # Therefore large patient records would need hybrid
        # encryption in a real implementation.
        raise ValueError(
            "Patient data is too large for direct RSA encryption."
        )


# ============================================================
#                 RSA DECRYPTION
# ============================================================

def rsa_decrypt(ciphertext, private_key):

    # Import Doctor's private key.
    key = RSA.import_key(private_key)


    # Create RSA-OAEP decryptor.
    cipher = PKCS1_OAEP.new(key)


    # Decrypt using private key.
    plaintext = cipher.decrypt(ciphertext)


    # Convert bytes back to string.
    return plaintext.decode()


# ============================================================
#                    SHA-256 HASH
# ============================================================
#
# SHA-256 is NOT encryption.
#
# It is used to create a fixed-size fingerprint of data.
#
# Here we hash the ENCRYPTED DATA because the question says:
#
#       "Compute the SHA-256 hash of the encrypted patient
#        information."
#
# Therefore:
#
#       ciphertext → SHA-256 → hash
#
# ============================================================

def calculate_hash(data):

    # data is expected to be bytes.
    return SHA256.new(data).hexdigest()


# ============================================================
#                 RSA DIGITAL SIGNATURE
# ============================================================
#
# The Doctor signs the SHA-256 hash using the private key.
#
# Conceptually:
#
#       encrypted data
#             ↓
#          SHA-256
#             ↓
#           hash
#             ↓
#       Doctor PRIVATE KEY
#             ↓
#         signature
#
# The private key proves that the signature was generated
# using the Doctor's signing key.
# ============================================================

def sign_data(data, private_key):

    # Import Doctor's private key.
    key = RSA.import_key(private_key)


    # Calculate SHA-256.
    hash_object = SHA256.new(data)


    # Generate RSA-PSS / PKCS#1 v1.5 style signature.
    #
    # For this lab we use pkcs1_15 because it is simple and
    # widely used for demonstrating RSA signatures.
    signature = pkcs1_15.new(key).sign(hash_object)


    return signature


# ============================================================
#              RSA DIGITAL SIGNATURE VERIFICATION
# ============================================================
#
# Verification is done using the Doctor's PUBLIC key.
#
#       ciphertext
#            ↓
#         SHA-256
#            ↓
#       calculated hash
#            +
#       signature
#            +
#       Doctor PUBLIC KEY
#            ↓
#       VALID / INVALID
#
# ============================================================

def verify_signature(data, signature, public_key):

    # Import public key.
    key = RSA.import_key(public_key)


    # Recalculate SHA-256 of the data.
    hash_object = SHA256.new(data)


    try:

        # Verify signature.
        pkcs1_15.new(key).verify(
            hash_object,
            signature
        )

        return True


    except (ValueError, TypeError):

        # Invalid signature.
        return False


# ============================================================
#                     AUDIT LOG
# ============================================================
#
# Every important operation is recorded with:
#
#       Timestamp
#       Role
#       Operation
#       Status
#
# This is useful for auditing and security monitoring.
# ============================================================

def audit_log(role, operation, status):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    entry = (
        f"{timestamp} | "
        f"{role} | "
        f"{operation} | "
        f"{status}\n"
    )


    # "a" means append.
    #
    # Existing audit records are not overwritten.
    with open(AUDIT_FILE, "a") as file:

        file.write(entry)


# ============================================================
#              LOAD PATIENT RECORDS
# ============================================================

def load_records():

    try:

        with open(RECORD_FILE, "r") as file:

            return json.load(file)


    except FileNotFoundError:

        # If the file doesn't exist yet, start with an
        # empty list.
        return []


# ============================================================
#              SAVE PATIENT RECORDS
# ============================================================

def save_records(records):

    # Store all records in JSON format.
    with open(RECORD_FILE, "w") as file:

        json.dump(
            records,
            file,
            indent=4
        )


# ============================================================
#              CREATE PATIENT INFORMATION
# ============================================================
#
# Patient information is stored as a dictionary.
#
# Example:
#
# {
#     "name": "John",
#     "age": "45",
#     "gender": "Male",
#     "blood_group": "O+",
#     "diagnosis": "..."
# }
#
# The dictionary is then converted to JSON/string before
# encryption.
# ============================================================

def enter_patient_data():

    print("\n--- ENTER PATIENT INFORMATION ---")


    patient = {

        "name": input("Name: "),

        "age": input("Age: "),

        "gender": input("Gender: "),

        "blood_group": input("Blood Group: "),

        "diagnosis": input("Diagnosis: "),

        "other_details": input("Other Medical Details: ")
    }


    return patient


# ============================================================
#                    DOCTOR ROLE
# ============================================================
#
# Doctor is the most privileged role.
#
# Doctor can:
#
#       Create record
#       Encrypt
#       Hash
#       Sign
#       Store
#       View records
#       Verify
#       Decrypt
#
# ============================================================

def doctor_create_record(
    private_key,
    public_key
):

    print("\n================================")
    print("       DOCTOR - CREATE RECORD")
    print("================================")


    # --------------------------------------------------------
    # STEP 1: ENTER PATIENT DATA
    # --------------------------------------------------------

    patient = enter_patient_data()


    # Convert dictionary to JSON string.
    #
    # JSON makes the structured patient information easy to
    # serialize and reconstruct.
    patient_json = json.dumps(
        patient
    )


    # --------------------------------------------------------
    # STEP 2: RSA ENCRYPTION
    # --------------------------------------------------------
    #
    # Encrypt using Doctor's PUBLIC key.
    #
    try:

        ciphertext = rsa_encrypt(
            patient_json,
            public_key
        )


    except ValueError as e:

        print("\nEncryption failed:", e)

        return


    # --------------------------------------------------------
    # STEP 3: SHA-256 HASH
    # --------------------------------------------------------
    #
    # Hash the encrypted data.
    #
    hash_value = calculate_hash(
        ciphertext
    )


    # --------------------------------------------------------
    # STEP 4: DIGITAL SIGNATURE
    # --------------------------------------------------------
    #
    # Sign the encrypted data using Doctor's PRIVATE key.
    #
    # Since sign_data internally calculates SHA-256,
    # the signature effectively protects the hash of the
    # ciphertext.
    #
    signature = sign_data(
        ciphertext,
        private_key
    )


    # --------------------------------------------------------
    # STEP 5: CREATE RECORD ID
    # --------------------------------------------------------

    records = load_records()

    record_id = f"REC-{len(records) + 1:04d}"


    # --------------------------------------------------------
    # STEP 6: TIMESTAMP
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # --------------------------------------------------------
    # STEP 7: CREATE SECURE RECORD
    # --------------------------------------------------------
    #
    # IMPORTANT:
    #
    # Notice that plaintext patient information is NOT stored.
    #
    # Only encrypted data + security metadata are stored.
    # --------------------------------------------------------

    record = {

        "record_id": record_id,

        # Encrypted data cannot directly be placed into JSON
        # because it is bytes.
        #
        # Therefore convert it to hexadecimal.
        "encrypted_data": ciphertext.hex(),

        "sha256": hash_value,

        "signature": signature.hex(),

        "timestamp": timestamp
    }


    # Add record to list.
    records.append(record)


    # Save to file.
    save_records(records)


    # --------------------------------------------------------
    # DISPLAY SECURITY INFORMATION
    # --------------------------------------------------------

    print("\n--- RECORD CREATED SUCCESSFULLY ---")

    print("Record ID:", record_id)

    print("\nEncrypted Data:")
    print(ciphertext.hex())

    print("\nSHA-256:")
    print(hash_value)

    print("\nDigital Signature:")
    print(signature.hex())

    print("\nTimestamp:")
    print(timestamp)


    # Record the operation.
    audit_log(
        "DOCTOR",
        "CREATE RECORD",
        "SUCCESS"
    )


# ============================================================
#                 DOCTOR VIEW RECORDS
# ============================================================

def doctor_view_records():

    print("\n================================")
    print("       DOCTOR - VIEW RECORDS")
    print("================================")


    records = load_records()


    if not records:

        print("No records available.")

        return


    # Doctor can view stored encrypted records.
    for record in records:

        print("\n------------------------------")

        print(
            "Record ID:",
            record["record_id"]
        )

        print(
            "Encrypted Data:",
            record["encrypted_data"]
        )

        print(
            "SHA-256:",
            record["sha256"]
        )

        print(
            "Signature:",
            record["signature"]
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )


# ============================================================
#              DOCTOR DECRYPT RECORD
# ============================================================
#
# Decryption is allowed ONLY for Doctor.
#
# Before decrypting, Doctor must verify:
#
#       1. Hash
#       2. Digital signature
#
# If either fails:
#
#       DO NOT DECRYPT
#
# ============================================================

def doctor_decrypt_record(
    private_key,
    public_key
):

    print("\n================================")
    print("       DOCTOR - DECRYPT")
    print("================================")


    records = load_records()


    if not records:

        print("No records available.")

        return


    record_id = input(
        "Enter Record ID: "
    )


    # Find requested record.
    record = None

    for item in records:

        if item["record_id"] == record_id:

            record = item
            break


    if record is None:

        print("Record not found.")

        return


    # --------------------------------------------------------
    # CONVERT STORED HEX BACK TO BYTES
    # --------------------------------------------------------

    ciphertext = bytes.fromhex(
        record["encrypted_data"]
    )


    signature = bytes.fromhex(
        record["signature"]
    )


    # --------------------------------------------------------
    # STEP 1: RECOMPUTE SHA-256
    # --------------------------------------------------------

    calculated_hash = calculate_hash(
        ciphertext
    )


    hash_valid = (
        calculated_hash ==
        record["sha256"]
    )


    # --------------------------------------------------------
    # STEP 2: VERIFY RSA SIGNATURE
    # --------------------------------------------------------

    signature_valid = verify_signature(
        ciphertext,
        signature,
        public_key
    )


    # --------------------------------------------------------
    # DISPLAY VERIFICATION
    # --------------------------------------------------------

    print("\n--- SECURITY VERIFICATION ---")

    print(
        "SHA-256:",
        "VALID" if hash_valid else "INVALID"
    )

    print(
        "RSA Signature:",
        "VALID" if signature_valid else "INVALID"
    )


    # --------------------------------------------------------
    # SECURITY GATE
    # --------------------------------------------------------
    #
    # BOTH must be valid.
    #
    if not (hash_valid and signature_valid):

        print(
            "\nACCESS DENIED."
        )

        print(
            "Patient information will NOT be decrypted."
        )


        audit_log(
            "DOCTOR",
            "DECRYPT",
            "DENIED - VERIFICATION FAILED"
        )

        return


    # --------------------------------------------------------
    # STEP 3: DECRYPT
    # --------------------------------------------------------

    try:

        plaintext = rsa_decrypt(
            ciphertext,
            private_key
        )


        # Convert JSON string back to dictionary.
        patient = json.loads(
            plaintext
        )


        # ----------------------------------------------------
        # DISPLAY PLAINTEXT
        # ----------------------------------------------------

        print("\n--- PATIENT INFORMATION ---")

        for key, value in patient.items():

            print(
                f"{key}: {value}"
            )


        audit_log(
            "DOCTOR",
            "DECRYPT",
            "SUCCESS"
        )


    except Exception:

        print(
            "\nDecryption failed."
        )


        audit_log(
            "DOCTOR",
            "DECRYPT",
            "FAILED - DECRYPTION ERROR"
        )


# ============================================================
#                     NURSE ROLE
# ============================================================
#
# Nurse can:
#
#       View encrypted records
#       View hash
#       View signature
#       View timestamp
#       Verify hash
#       Verify signature
#
# Nurse CANNOT:
#
#       Access private key
#       Decrypt patient information
#
# ============================================================

def nurse_role(public_key):

    print("\n================================")
    print("             NURSE")
    print("================================")


    records = load_records()


    if not records:

        print("No records available.")

        return


    # --------------------------------------------------------
    # DISPLAY AVAILABLE RECORDS
    # --------------------------------------------------------

    for record in records:

        print("\n------------------------------")

        print(
            "Record ID:",
            record["record_id"]
        )

        print(
            "Encrypted Data:",
            record["encrypted_data"]
        )

        print(
            "SHA-256:",
            record["sha256"]
        )

        print(
            "Signature:",
            record["signature"]
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )


    # --------------------------------------------------------
    # SELECT RECORD FOR VERIFICATION
    # --------------------------------------------------------

    record_id = input(
        "\nEnter Record ID to verify: "
    )


    record = None

    for item in records:

        if item["record_id"] == record_id:

            record = item
            break


    if record is None:

        print("Record not found.")

        return


    # Convert encrypted data back to bytes.
    ciphertext = bytes.fromhex(
        record["encrypted_data"]
    )


    signature = bytes.fromhex(
        record["signature"]
    )


    # --------------------------------------------------------
    # HASH VERIFICATION
    # --------------------------------------------------------

    calculated_hash = calculate_hash(
        ciphertext
    )


    hash_valid = (
        calculated_hash ==
        record["sha256"]
    )


    # --------------------------------------------------------
    # SIGNATURE VERIFICATION
    # --------------------------------------------------------

    signature_valid = verify_signature(
        ciphertext,
        signature,
        public_key
    )


    # --------------------------------------------------------
    # DISPLAY RESULTS
    # --------------------------------------------------------

    print("\n--- NURSE VERIFICATION ---")

    print(
        "SHA-256:",
        "VALID" if hash_valid else "INVALID"
    )

    print(
        "RSA Signature:",
        "VALID" if signature_valid else "INVALID"
    )


    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    print(
        "Verification Timestamp:",
        timestamp
    )


    # --------------------------------------------------------
    # IMPORTANT
    # --------------------------------------------------------
    #
    # There is intentionally NO:
    #
    #       private_key
    #
    # and NO:
    #
    #       rsa_decrypt()
    #
    # inside the Nurse role.
    #
    # Therefore Nurse cannot obtain plaintext through this
    # role's authorized operations.
    # --------------------------------------------------------

    audit_log(
        "NURSE",
        "VERIFY RECORD",
        "COMPLETED"
    )


# ============================================================
#                    ADMIN ROLE
# ============================================================
#
# Admin has the most restricted access to patient information.
#
# Admin can see:
#
#       Record ID
#       SHA-256
#       Timestamp
#
# Admin can:
#
#       Verify RSA signature
#
# Admin CANNOT:
#
#       View encrypted patient data
#       View plaintext
#       Access private key
#
# ============================================================

def admin_role(public_key):

    print("\n================================")
    print("             ADMIN")
    print("================================")


    records = load_records()


    if not records:

        print("No records available.")

        return


    # --------------------------------------------------------
    # ADMIN CAN ONLY SEE LIMITED METADATA
    # --------------------------------------------------------

    for record in records:

        print("\n------------------------------")

        print(
            "Record ID:",
            record["record_id"]
        )

        print(
            "SHA-256:",
            record["sha256"]
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )


    # --------------------------------------------------------
    # SELECT RECORD FOR SIGNATURE VERIFICATION
    # --------------------------------------------------------

    record_id = input(
        "\nEnter Record ID to verify signature: "
    )


    record = None

    for item in records:

        if item["record_id"] == record_id:

            record = item
            break


    if record is None:

        print("Record not found.")

        return


    # --------------------------------------------------------
    # ADMIN NEEDS THE CIPHERTEXT TO VERIFY THE SIGNATURE.
    #
    # However, the Admin should not be shown the ciphertext.
    #
    # We internally retrieve it from storage only for the
    # cryptographic verification operation.
    # --------------------------------------------------------

    ciphertext = bytes.fromhex(
        record["encrypted_data"]
    )


    signature = bytes.fromhex(
        record["signature"]
    )


    # Verify signature using ONLY public key.
    signature_valid = verify_signature(
        ciphertext,
        signature,
        public_key
    )


    # --------------------------------------------------------
    # DISPLAY RESULT
    # --------------------------------------------------------

    print("\n--- ADMIN SIGNATURE VERIFICATION ---")

    if signature_valid:

        print(
            "Digital Signature: VALID"
        )

    else:

        print(
            "Digital Signature: INVALID"
        )


    verification_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    print(
        "Verification Timestamp:",
        verification_time
    )


    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Admin never receives:
    #
    #       private_key
    #
    # and never calls:
    #
    #       rsa_decrypt()
    #
    # --------------------------------------------------------

    audit_log(
        "ADMIN",
        "VERIFY SIGNATURE",
        "COMPLETED"
    )


# ============================================================
#                    MAIN PROGRAM
# ============================================================

def main():

    print("\n======================================")
    print("           HEALTHSECURE")
    print(" Patient Information Management")
    print("======================================")


    # --------------------------------------------------------
    # GENERATE DOCTOR'S RSA KEY PAIR
    # --------------------------------------------------------
    #
    # Doctor gets:
    #
    #       private_key
    #       public_key
    #
    # The private key stays inside the program's protected
    # Doctor-side context.
    # --------------------------------------------------------

    private_key, public_key = generate_rsa_keys()


    # --------------------------------------------------------
    # MAIN ROLE MENU
    # --------------------------------------------------------

    while True:

        print("\n--------------- MENU ---------------")

        print("1. Doctor")
        print("2. Nurse")
        print("3. Admin")
        print("4. Exit")


        choice = input(
            "\nEnter choice: "
        )


        # ====================================================
        # DOCTOR
        # ====================================================

        if choice == "1":

            while True:

                print("\n--------- DOCTOR MENU ---------")

                print("1. Add Patient Record")
                print("2. View Stored Records")
                print("3. Decrypt Patient Record")
                print("4. Back")


                doctor_choice = input(
                    "Enter choice: "
                )


                if doctor_choice == "1":

                    doctor_create_record(
                        private_key,
                        public_key
                    )


                elif doctor_choice == "2":

                    doctor_view_records()


                elif doctor_choice == "3":

                    doctor_decrypt_record(
                        private_key,
                        public_key
                    )


                elif doctor_choice == "4":

                    break


                else:

                    print("Invalid choice.")


        # ====================================================
        # NURSE
        # ====================================================

        elif choice == "2":

            nurse_role(
                public_key
            )


        # ====================================================
        # ADMIN
        # ====================================================

        elif choice == "3":

            admin_role(
                public_key
            )


        # ====================================================
        # EXIT
        # ====================================================

        elif choice == "4":

            print(
                "\nExiting HealthSecure..."
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
