'''
MediSecure
A hospital wants to develop a secure patient-record management system called MediSecure. The system has three roles: Patient, Doctor, and Auditor.
The system must ensure the confidentiality, integrity, and authenticity of patient medical records.

Patient
The Patient should be able to:
Read a medical record from a .txt file.
Encrypt the medical record using AES with a shared key and an Initialization Vector (IV) provided by the user.
Compute the SHA-256 hash of the encrypted record.
Digitally sign the hash using the Patient's RSA private key.
Store the filename, encrypted record, hash, digital signature, IV, and timestamp.
View previously uploaded encrypted records along with their hashes and timestamps.

Doctor
The Doctor should be able to:
View available uploaded records.
Select a record and decrypt it using the shared AES key and IV.
Recompute the SHA-256 hash of the encrypted record and compare it with the stored hash to verify integrity.
Verify the Patient's RSA digital signature using the Patient's RSA public key to verify authenticity.
Display the decrypted medical record only when the integrity and signature verifications are successful.
Store/display the verification result with a timestamp.

Auditor
The Auditor should be able to:
View only the filename, SHA-256 hash, and timestamp of stored medical records.
Verify the Patient's RSA digital signature using the Patient's public key.
Must not be allowed to decrypt or view the plaintext medical records.

Task:
Develop a menu-driven Python program implementing the above requirements using:
AES symmetric encryption and decryption
User-provided AES key and IV
SHA-256 hashing
RSA digital signatures
Role-based access control
.txt file handling
Timestamps
The program should securely store the required information and allow each role to perform only its authorized operations

'''
import json
import secrets
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# ============================================================
#                    CONFIGURATION
# ============================================================

RECORD_FILE = "medisecure_records.json"
AUDIT_FILE = "medisecure_audit.log"


# ============================================================
#                    RSA KEY GENERATION
# ============================================================
#
# The Patient owns an RSA key pair:
#
#       PRIVATE KEY
#           |
#           +----> Create digital signature
#
#       PUBLIC KEY
#           |
#           +----> Verify digital signature
#
# IMPORTANT:
#
# The Doctor and Auditor receive ONLY the Patient's public key.
# The Patient's private key must remain secret.
# ============================================================

def generate_rsa_keys():

    # Generate a 2048-bit RSA key pair.
    rsa_key = RSA.generate(2048)

    # Export private key.
    private_key = rsa_key.export_key()

    # Export only public portion.
    public_key = rsa_key.publickey().export_key()

    return private_key, public_key


# ============================================================
#                    AES KEY HANDLING
# ============================================================
#
# AES is a symmetric cipher.
#
# The SAME key is required for:
#
#       Encryption
#           ↓
#       Decryption
#
# The question says that the AES key and IV are provided
# by the user.
#
# AES supports different key sizes:
#
#       AES-128 -> 16 bytes
#       AES-192 -> 24 bytes
#       AES-256 -> 32 bytes
#
# We use AES-128 here for simplicity.
# ============================================================

def get_aes_key():

    while True:

        key = input(
            "Enter AES key (exactly 16 characters): "
        )

        # AES-128 requires 16 bytes.
        #
        # Using encode() rather than len() is safer because
        # encryption operates on bytes.
        if len(key.encode()) == 16:

            return key.encode()

        print(
            "AES-128 key must be exactly 16 bytes."
        )


# ============================================================
#                    USER-PROVIDED IV
# ============================================================
#
# AES-CBC requires an IV equal to the AES block size.
#
# AES block size = 16 bytes.
#
# Therefore the IV must be exactly 16 bytes.
#
# The question explicitly says:
#
#       "IV provided by the user."
#
# Therefore we do NOT generate a random IV here.
# ============================================================

def get_iv():

    while True:

        iv = input(
            "Enter IV (exactly 16 characters): "
        )

        if len(iv.encode()) == 16:

            return iv.encode()

        print(
            "AES-CBC IV must be exactly 16 bytes."
        )


# ============================================================
#                    AES ENCRYPTION
# ============================================================
#
# Encryption:
#
#       plaintext
#           +
#       AES key
#           +
#       IV
#           ↓
#       AES-CBC
#           ↓
#       ciphertext
#
# PKCS#7 padding is used because AES works on fixed-size
# 16-byte blocks.
# ============================================================

def aes_encrypt(plaintext, key, iv):

    # Create AES cipher in CBC mode.
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    # Convert plaintext to bytes.
    plaintext_bytes = plaintext.encode()

    # Add PKCS#7 padding.
    padded_data = pad(
        plaintext_bytes,
        AES.block_size
    )

    # Encrypt.
    ciphertext = cipher.encrypt(
        padded_data
    )

    return ciphertext


# ============================================================
#                    AES DECRYPTION
# ============================================================

def aes_decrypt(ciphertext, key, iv):

    # Recreate the SAME AES-CBC configuration.
    #
    # For successful decryption:
    #
    #       same key
    #       same IV
    #
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    # Decrypt ciphertext.
    padded_plaintext = cipher.decrypt(
        ciphertext
    )

    # Remove PKCS#7 padding.
    plaintext = unpad(
        padded_plaintext,
        AES.block_size
    )

    # Convert bytes back to text.
    return plaintext.decode()


# ============================================================
#                    SHA-256 HASH
# ============================================================
#
# SHA-256 is used for INTEGRITY.
#
# IMPORTANT:
#
# SHA-256 does NOT encrypt the record.
#
# We calculate:
#
#       SHA256(encrypted_record)
#
# The stored hash acts as the expected integrity value.
# ============================================================

def calculate_hash(data):

    return SHA256.new(
        data
    ).hexdigest()


# ============================================================
#                    RSA SIGNATURE
# ============================================================
#
# The question says:
#
#       "Digitally sign the hash using the Patient's RSA
#        private key."
#
# Conceptually:
#
#       encrypted record
#              ↓
#           SHA-256
#              ↓
#             hash
#              ↓
#       Patient private key
#              ↓
#          signature
#
# In the implementation below, pkcs1_15 signs the SHA-256
# digest of the encrypted data.
#
# ============================================================

def create_signature(
    encrypted_data,
    private_key
):

    # Import Patient's private key.
    key = RSA.import_key(
        private_key
    )

    # Create SHA-256 object for encrypted data.
    hash_object = SHA256.new(
        encrypted_data
    )

    # Generate RSA digital signature.
    signature = pkcs1_15.new(
        key
    ).sign(
        hash_object
    )

    return signature


# ============================================================
#                 RSA SIGNATURE VERIFICATION
# ============================================================
#
# Doctor and Auditor can verify the signature using ONLY the
# Patient's public key.
#
#       encrypted data
#              ↓
#           SHA-256
#              ↓
#       calculated digest
#
#       signature + Patient public key
#              ↓
#          verification
#
# Result:
#
#       VALID
#       INVALID
#
# ============================================================

def verify_signature(
    encrypted_data,
    signature,
    public_key
):

    # Import Patient's public key.
    key = RSA.import_key(
        public_key
    )

    # Recalculate SHA-256.
    hash_object = SHA256.new(
        encrypted_data
    )

    try:

        # Verify signature.
        pkcs1_15.new(key).verify(
            hash_object,
            signature
        )

        return True

    except (ValueError, TypeError):

        return False


# ============================================================
#                    AUDIT LOGGING
# ============================================================
#
# Every important action can be recorded with:
#
#       timestamp
#       role
#       operation
#       status
#
# ============================================================

def audit_log(
    role,
    operation,
    status
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    entry = (
        f"{timestamp} | "
        f"{role} | "
        f"{operation} | "
        f"{status}\n"
    )

    # Append to the audit file.
    with open(
        AUDIT_FILE,
        "a"
    ) as file:

        file.write(entry)


# ============================================================
#                    RECORD STORAGE
# ============================================================
#
# The encrypted record is stored in JSON.
#
# IMPORTANT:
#
# Binary data such as ciphertext, IV and signature cannot
# directly be stored in JSON.
#
# Therefore we convert them to hexadecimal strings.
#
# Stored record:
#
#       filename
#       encrypted record
#       hash
#       signature
#       IV
#       timestamp
#
# Plaintext is NOT stored.
# ============================================================

def load_records():

    try:

        with open(
            RECORD_FILE,
            "r"
        ) as file:

            return json.load(file)

    except FileNotFoundError:

        return []


def save_records(records):

    with open(
        RECORD_FILE,
        "w"
    ) as file:

        json.dump(
            records,
            file,
            indent=4
        )


# ============================================================
#                    PATIENT ROLE
# ============================================================
#
# Patient can:
#
#       1. Read .txt file
#       2. Enter AES key
#       3. Enter IV
#       4. AES encrypt
#       5. SHA-256 hash
#       6. RSA sign
#       7. Store record
#       8. View uploaded encrypted records
#
# ============================================================

def patient_upload(
    private_key
):

    print("\n================================")
    print("       PATIENT - UPLOAD")
    print("================================")


    # --------------------------------------------------------
    # STEP 1: READ .TXT FILE
    # --------------------------------------------------------

    filename = input(
        "Enter .txt filename: "
    )


    try:

        # Read the original medical record.
        with open(
            filename,
            "r"
        ) as file:

            plaintext = file.read()

    except FileNotFoundError:

        print(
            "File not found."
        )

        return


    # --------------------------------------------------------
    # STEP 2: GET AES SHARED KEY
    # --------------------------------------------------------

    aes_key = get_aes_key()


    # --------------------------------------------------------
    # STEP 3: GET USER-PROVIDED IV
    # --------------------------------------------------------

    iv = get_iv()


    # --------------------------------------------------------
    # STEP 4: AES ENCRYPTION
    # --------------------------------------------------------

    ciphertext = aes_encrypt(
        plaintext,
        aes_key,
        iv
    )


    # --------------------------------------------------------
    # STEP 5: SHA-256
    # --------------------------------------------------------
    #
    # Hash the ENCRYPTED record.
    #
    hash_value = calculate_hash(
        ciphertext
    )


    # --------------------------------------------------------
    # STEP 6: RSA DIGITAL SIGNATURE
    # --------------------------------------------------------
    #
    # Patient signs the encrypted record/hash using
    # Patient's private key.
    #
    signature = create_signature(
        ciphertext,
        private_key
    )


    # --------------------------------------------------------
    # STEP 7: TIMESTAMP
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # --------------------------------------------------------
    # STEP 8: CREATE RECORD
    # --------------------------------------------------------

    records = load_records()


    record_id = (
        f"MED-{len(records) + 1:04d}"
    )


    record = {

        "record_id": record_id,

        # Original filename.
        "filename": filename,

        # Ciphertext converted to hexadecimal.
        "encrypted_record": ciphertext.hex(),

        # SHA-256 hash.
        "sha256": hash_value,

        # RSA signature.
        "signature": signature.hex(),

        # IV is not secret.
        "iv": iv.hex(),

        # Creation/upload time.
        "timestamp": timestamp
    }


    # Add record.
    records.append(
        record
    )


    # Store it.
    save_records(
        records
    )


    # --------------------------------------------------------
    # DISPLAY SECURITY INFORMATION
    # --------------------------------------------------------

    print(
        "\n--- RECORD UPLOADED SUCCESSFULLY ---"
    )

    print(
        "Record ID:",
        record_id
    )

    print(
        "Filename:",
        filename
    )

    print(
        "\nEncrypted Record:"
    )

    print(
        ciphertext.hex()
    )

    print(
        "\nSHA-256:"
    )

    print(
        hash_value
    )

    print(
        "\nRSA Digital Signature:"
    )

    print(
        signature.hex()
    )

    print(
        "\nIV:"
    )

    print(
        iv.hex()
    )

    print(
        "\nTimestamp:"
    )

    print(
        timestamp
    )


    audit_log(
        "PATIENT",
        "UPLOAD RECORD",
        "SUCCESS"
    )


# ============================================================
#              PATIENT VIEW RECORDS
# ============================================================
#
# Patient can view previously uploaded encrypted records.
#
# We display:
#
#       filename
#       encrypted data
#       hash
#       timestamp
#
# ============================================================

def patient_view_records():

    print("\n================================")
    print("      PATIENT - RECORDS")
    print("================================")


    records = load_records()


    if not records:

        print(
            "No records uploaded."
        )

        return


    for record in records:

        print("\n------------------------------")

        print(
            "Record ID:",
            record["record_id"]
        )

        print(
            "Filename:",
            record["filename"]
        )

        print(
            "Encrypted Record:",
            record["encrypted_record"]
        )

        print(
            "SHA-256:",
            record["sha256"]
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )


# ============================================================
#                    DOCTOR ROLE
# ============================================================
#
# Doctor can:
#
#       View records
#       Select a record
#       Recalculate hash
#       Verify signature
#       Decrypt if BOTH checks pass
#
# Doctor needs:
#
#       shared AES key
#       IV
#       Patient public RSA key
#
# Doctor does NOT need Patient's private RSA key.
#
# ============================================================

def doctor_view_records():

    print("\n================================")
    print("       DOCTOR - RECORDS")
    print("================================")


    records = load_records()


    if not records:

        print(
            "No records available."
        )

        return


    for record in records:

        print("\n------------------------------")

        print(
            "Record ID:",
            record["record_id"]
        )

        print(
            "Filename:",
            record["filename"]
        )

        print(
            "Encrypted Record:",
            record["encrypted_record"]
        )

        print(
            "SHA-256:",
            record["sha256"]
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )


# ============================================================
#              DOCTOR VERIFY + DECRYPT
# ============================================================

def doctor_access_record(
    public_key
):

    print("\n================================")
    print("       DOCTOR - ACCESS")
    print("================================")


    records = load_records()


    if not records:

        print(
            "No records available."
        )

        return


    # --------------------------------------------------------
    # SELECT RECORD
    # --------------------------------------------------------

    record_id = input(
        "Enter Record ID: "
    )


    record = None


    for item in records:

        if item["record_id"] == record_id:

            record = item

            break


    if record is None:

        print(
            "Record not found."
        )

        return


    # --------------------------------------------------------
    # CONVERT STORED DATA BACK TO BYTES
    # --------------------------------------------------------

    ciphertext = bytes.fromhex(
        record["encrypted_record"]
    )

    signature = bytes.fromhex(
        record["signature"]
    )

    iv = bytes.fromhex(
        record["iv"]
    )


    # --------------------------------------------------------
    # STEP 1: HASH VERIFICATION
    # --------------------------------------------------------
    #
    # Recalculate SHA-256 from the CURRENT ciphertext.
    #
    calculated_hash = calculate_hash(
        ciphertext
    )


    # Compare with stored hash.
    hash_valid = (
        calculated_hash ==
        record["sha256"]
    )


    # --------------------------------------------------------
    # STEP 2: RSA SIGNATURE VERIFICATION
    # --------------------------------------------------------

    signature_valid = verify_signature(
        ciphertext,
        signature,
        public_key
    )


    # --------------------------------------------------------
    # DISPLAY VERIFICATION
    # --------------------------------------------------------

    print("\n--- VERIFICATION RESULTS ---")

    print(
        "SHA-256 Integrity:",
        "VALID" if hash_valid else "INVALID"
    )

    print(
        "RSA Signature:",
        "VALID" if signature_valid else "INVALID"
    )


    verification_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    print(
        "Verification Timestamp:",
        verification_time
    )


    # --------------------------------------------------------
    # SECURITY GATE
    # --------------------------------------------------------
    #
    # BOTH conditions MUST be true.
    #
    # If hash fails:
    #
    #       ciphertext may have been modified.
    #
    # If signature fails:
    #
    #       authenticity cannot be established.
    #
    # Therefore we MUST NOT decrypt.
    # --------------------------------------------------------

    if not (
        hash_valid and
        signature_valid
    ):

        print(
            "\nACCESS DENIED."
        )

        print(
            "Medical record will NOT be decrypted."
        )


        audit_log(
            "DOCTOR",
            "ACCESS RECORD",
            "DENIED - VERIFICATION FAILED"
        )

        return


    # --------------------------------------------------------
    # STEP 3: GET SHARED AES KEY
    # --------------------------------------------------------
    #
    # The Doctor must know the shared AES key.
    #
    # The question explicitly says that the record is encrypted
    # using a shared AES key.
    #
    aes_key = get_aes_key()


    # --------------------------------------------------------
    # STEP 4: AES DECRYPTION
    # --------------------------------------------------------

    try:

        plaintext = aes_decrypt(
            ciphertext,
            aes_key,
            iv
        )


        # ----------------------------------------------------
        # DISPLAY ORIGINAL MEDICAL RECORD
        # ----------------------------------------------------

        print(
            "\n--- DECRYPTED MEDICAL RECORD ---"
        )

        print(
            plaintext
        )


        audit_log(
            "DOCTOR",
            "ACCESS RECORD",
            "SUCCESS"
        )


    except Exception:

        print(
            "\nDecryption failed."
        )

        print(
            "Check the AES key and IV."
        )


        audit_log(
            "DOCTOR",
            "ACCESS RECORD",
            "FAILED - DECRYPTION ERROR"
        )


# ============================================================
#                    AUDITOR ROLE
# ============================================================
#
# Auditor has the least access.
#
# Auditor CAN:
#
#       View filename
#       View SHA-256
#       View timestamp
#       Verify RSA signature
#
# Auditor CANNOT:
#
#       View plaintext
#       Decrypt
#       Access AES key
#       Access Patient private key
#
# ============================================================

def auditor_role(
    public_key
):

    print("\n================================")
    print("          AUDITOR")
    print("================================")


    records = load_records()


    if not records:

        print(
            "No records available."
        )

        return


    # --------------------------------------------------------
    # DISPLAY ONLY PERMITTED INFORMATION
    # --------------------------------------------------------

    for record in records:

        print("\n------------------------------")

        print(
            "Record ID:",
            record["record_id"]
        )

        print(
            "Filename:",
            record["filename"]
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
        "\nEnter Record ID to verify: "
    )


    record = None


    for item in records:

        if item["record_id"] == record_id:

            record = item

            break


    if record is None:

        print(
            "Record not found."
        )

        return


    # --------------------------------------------------------
    # GET ENCRYPTED DATA INTERNALLY
    # --------------------------------------------------------
    #
    # The Auditor needs the ciphertext mathematically to
    # verify the signature.
    #
    # But we DO NOT display it.
    #
    ciphertext = bytes.fromhex(
        record["encrypted_record"]
    )


    signature = bytes.fromhex(
        record["signature"]
    )


    # --------------------------------------------------------
    # VERIFY PATIENT SIGNATURE
    # --------------------------------------------------------

    valid = verify_signature(
        ciphertext,
        signature,
        public_key
    )


    # --------------------------------------------------------
    # DISPLAY RESULT
    # --------------------------------------------------------

    verification_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    print(
        "\n--- AUDIT RESULT ---"
    )

    print(
        "RSA Digital Signature:",
        "VALID" if valid else "INVALID"
    )

    print(
        "Verification Timestamp:",
        verification_time
    )


    # --------------------------------------------------------
    # IMPORTANT
    # --------------------------------------------------------
    #
    # There is NO:
    #
    #       get_aes_key()
    #
    # and NO:
    #
    #       aes_decrypt()
    #
    # in the Auditor role.
    #
    # Therefore Auditor cannot decrypt the medical record.
    # --------------------------------------------------------

    audit_log(
        "AUDITOR",
        "VERIFY SIGNATURE",
        "VALID" if valid else "INVALID"
    )


# ============================================================
#                    MAIN PROGRAM
# ============================================================

def main():

    print("\n======================================")
    print("             MEDISECURE")
    print("       Patient Record System")
    print("======================================")


    # --------------------------------------------------------
    # GENERATE PATIENT RSA KEY PAIR
    # --------------------------------------------------------
    #
    # Patient gets:
    #
    #       private_key
    #       public_key
    #
    # Private key remains secret.
    #
    private_key, public_key = (
        generate_rsa_keys()
    )


    # --------------------------------------------------------
    # MAIN ROLE MENU
    # --------------------------------------------------------

    while True:

        print("\n--------------- MENU ---------------")

        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")


        choice = input(
            "\nEnter choice: "
        )


        # ====================================================
        # PATIENT
        # ====================================================

        if choice == "1":

            while True:

                print("\n--------- PATIENT MENU ---------")

                print("1. Upload Medical Record")
                print("2. View Uploaded Records")
                print("3. Back")


                patient_choice = input(
                    "Enter choice: "
                )


                if patient_choice == "1":

                    patient_upload(
                        private_key
                    )


                elif patient_choice == "2":

                    patient_view_records()


                elif patient_choice == "3":

                    break


                else:

                    print(
                        "Invalid choice."
                    )


        # ====================================================
        # DOCTOR
        # ====================================================

        elif choice == "2":

            while True:

                print("\n--------- DOCTOR MENU ---------")

                print("1. View Records")
                print("2. Verify and Decrypt Record")
                print("3. Back")


                doctor_choice = input(
                    "Enter choice: "
                )


                if doctor_choice == "1":

                    doctor_view_records()


                elif doctor_choice == "2":

                    doctor_access_record(
                        public_key
                    )


                elif doctor_choice == "3":

                    break


                else:

                    print(
                        "Invalid choice."
                    )


        # ====================================================
        # AUDITOR
        # ====================================================

        elif choice == "3":

            auditor_role(
                public_key
            )


        # ====================================================
        # EXIT
        # ====================================================

        elif choice == "4":

            print(
                "\nExiting MediSecure..."
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
