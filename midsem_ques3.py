'''
Perform a hospital based management system using AES-128, ELGAMAL, RSA. 
Under the following specifications 

Create a file and add content to it

Encrypt the file content using aes and store the encrypted msg in another file

Using rsa encrypt the aes key and store in another file

An authorisation code was given which was to be encrypted using elgamal under the given parameters 

Display the encrypted msg, public key, rsa values

Perform hashing on the encrypted msg of aes.

Check for validity of sender and receiver hashing

If verified, perform decryption and show all the decrypted text , aes key and the decrypted original file content

If integrity failed don't perform decryption and show error output 

For showing integrity failed, modify one character in the aes cipher text and perform hashing on it
This must thore integrity failed since tampering is done to encrypted file
'''
import os
import base64
import hashlib
import secrets

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime


# ============================================================
#                    FILE NAMES
# ============================================================

ORIGINAL_FILE = "hospital_record.txt"
ENCRYPTED_FILE = "hospital_record.enc"
AES_KEY_FILE = "aes_key.enc"
ELGAMAL_FILE = "authorization.enc"


# ============================================================
#                    AES-128
# ============================================================
#
# AES-128 uses:
#
#       128-bit key = 16 bytes
#
# We use CBC mode.
#
# AES-CBC requires:
#
#       Key = 16 bytes
#       IV  = 16 bytes
#
# The IV is not secret, so it can be stored together with the
# ciphertext.
#
# ============================================================


def generate_aes_key():

    # AES-128 requires exactly 16 random bytes.
    return secrets.token_bytes(16)


# ------------------------------------------------------------
# AES ENCRYPTION
# ------------------------------------------------------------

def aes_encrypt(data, key):

    # Generate a fresh random IV.
    #
    # AES block size is 16 bytes.
    iv = secrets.token_bytes(16)


    # Create AES cipher in CBC mode.
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )


    # CBC works with complete 16-byte blocks.
    #
    # pad() adds PKCS#7 padding when necessary.
    padded_data = pad(
        data,
        AES.block_size
    )


    # Encrypt the padded data.
    ciphertext = cipher.encrypt(
        padded_data
    )


    # We need the IV later for decryption.
    #
    # Return both.
    return iv, ciphertext


# ------------------------------------------------------------
# AES DECRYPTION
# ------------------------------------------------------------

def aes_decrypt(ciphertext, key, iv):

    # Recreate AES-CBC using the SAME:
    #
    #       key
    #       IV
    #
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )


    # Decrypt ciphertext.
    padded_data = cipher.decrypt(
        ciphertext
    )


    # Remove PKCS#7 padding.
    data = unpad(
        padded_data,
        AES.block_size
    )


    return data


# ============================================================
#                    RSA KEY GENERATION
# ============================================================
#
# RSA is NOT used to encrypt the large hospital file.
#
# Instead:
#
#       AES key
#          ↓
#       RSA encryption
#          ↓
#       encrypted AES key
#
# This is called HYBRID ENCRYPTION.
#
# AES handles the actual data.
# RSA protects the AES key.
#
# ============================================================


def generate_rsa_keys():

    # Generate a 2048-bit RSA key pair.
    rsa_key = RSA.generate(2048)


    # Private key must remain secret.
    private_key = rsa_key.export_key()


    # Public key can be distributed.
    public_key = rsa_key.publickey().export_key()


    return private_key, public_key


# ------------------------------------------------------------
# RSA ENCRYPT AES KEY
# ------------------------------------------------------------

def rsa_encrypt_aes_key(aes_key, public_key):

    # Import RSA public key.
    rsa_public_key = RSA.import_key(
        public_key
    )


    # OAEP provides secure RSA encryption padding.
    cipher = PKCS1_OAEP.new(
        rsa_public_key
    )


    # Encrypt the 16-byte AES key.
    encrypted_key = cipher.encrypt(
        aes_key
    )


    return encrypted_key


# ------------------------------------------------------------
# RSA DECRYPT AES KEY
# ------------------------------------------------------------

def rsa_decrypt_aes_key(encrypted_key, private_key):

    # Import RSA private key.
    rsa_private_key = RSA.import_key(
        private_key
    )


    # Create RSA-OAEP decryptor.
    cipher = PKCS1_OAEP.new(
        rsa_private_key
    )


    # Recover original AES key.
    aes_key = cipher.decrypt(
        encrypted_key
    )


    return aes_key


# ============================================================
#                    SHA-256 HASH
# ============================================================
#
# SHA-256 is used to detect whether the encrypted AES file
# has been modified.
#
# Important:
#
#       SHA-256 does NOT encrypt anything.
#
# It produces a fingerprint:
#
#       ciphertext
#            ↓
#          SHA-256
#            ↓
#          hash
#
# If even ONE character/byte changes:
#
#       original hash != modified hash
#
# ============================================================


def calculate_hash(data):

    return hashlib.sha256(
        data
    ).hexdigest()


# ============================================================
#                    ELGAMAL
# ============================================================
#
# The question says:
#
# "An authorization code was given which was to be encrypted
# using ElGamal under the given parameters."
#
# ElGamal encryption uses:
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
# Encryption:
#
# Choose random k
#
#       c1 = g^k mod p
#
#       c2 = m * y^k mod p
#
# Ciphertext:
#
#       (c1, c2)
#
# ============================================================


def generate_elgamal_keys():

    # Generate a prime p.
    #
    # For a lab demonstration we use 256 bits.
    p = getPrime(256)


    # Use a simple generator.
    #
    # For a properly specified exam question, replace this
    # with the given value of g.
    g = 2


    # Generate private key:
    #
    #       1 < x < p-1
    #
    x = secrets.randbelow(
        p - 2
    ) + 1


    # Generate public key:
    #
    #       y = g^x mod p
    #
    y = pow(
        g,
        x,
        p
    )


    return {
        "p": p,
        "g": g,
        "x": x,
        "y": y
    }


# ============================================================
#                 ELGAMAL ENCRYPTION
# ============================================================

def elgamal_encrypt(message, public_key):

    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]


    # Convert authorization code from string to integer.
    #
    # Example:
    #
    #       "12345"
    #
    # is converted to an integer.
    m = int.from_bytes(
        message.encode(),
        "big"
    )


    # ElGamal requires:
    #
    #       m < p
    #
    if m >= p:

        raise ValueError(
            "Authorization code is too large for ElGamal parameters."
        )


    # Generate fresh random ephemeral key k.
    #
    #       1 <= k < p-1
    #
    k = secrets.randbelow(
        p - 2
    ) + 1


    # First ElGamal ciphertext component:
    #
    #       c1 = g^k mod p
    #
    c1 = pow(
        g,
        k,
        p
    )


    # Second component:
    #
    #       c2 = m × y^k mod p
    #
    c2 = (
        m *
        pow(y, k, p)
    ) % p


    # Ciphertext is the pair:
    #
    #       (c1, c2)
    #
    return c1, c2


# ============================================================
#                 ELGAMAL DECRYPTION
# ============================================================
#
# This is included because the examiner may ask you to show
# the complete ElGamal process.
#
# Given:
#
#       c1, c2
#
# Private key:
#
#       x
#
# Calculate:
#
#       s = c1^x mod p
#
# Then:
#
#       m = c2 × s^-1 mod p
#
# ============================================================

def elgamal_decrypt(c1, c2, private_key):

    p = private_key["p"]
    x = private_key["x"]


    # Calculate shared secret:
    #
    #       s = c1^x mod p
    #
    shared_secret = pow(
        c1,
        x,
        p
    )


    # Find modular inverse:
    #
    #       s^-1 mod p
    #
    inverse = pow(
        shared_secret,
        -1,
        p
    )


    # Recover original message:
    #
    #       m = c2 × s^-1 mod p
    #
    m = (
        c2 *
        inverse
    ) % p


    # Convert integer back to bytes.
    message_bytes = m.to_bytes(
        (m.bit_length() + 7) // 8,
        "big"
    )


    return message_bytes.decode()


# ============================================================
#                    CREATE ORIGINAL FILE
# ============================================================

def create_file():

    print("\n================================")
    print("       CREATE HOSPITAL FILE")
    print("================================")


    content = input(
        "Enter hospital record content: "
    )


    # Write original plaintext into a file.
    #
    # Example:
    #
    # hospital_record.txt
    #
    # contains:
    #
    # Patient: Rahul
    # Blood Group: O+
    # Diagnosis: Fever
    #
    with open(
        ORIGINAL_FILE,
        "w"
    ) as file:

        file.write(content)


    print(
        "\nOriginal file created:",
        ORIGINAL_FILE
    )


# ============================================================
#              ENCRYPT HOSPITAL FILE
# ============================================================

def encrypt_file(
    aes_key,
    rsa_public_key
):

    print("\n================================")
    print("          FILE ENCRYPTION")
    print("================================")


    # --------------------------------------------------------
    # READ ORIGINAL FILE
    # --------------------------------------------------------

    with open(
        ORIGINAL_FILE,
        "rb"
    ) as file:

        plaintext = file.read()


    # --------------------------------------------------------
    # AES ENCRYPTION
    # --------------------------------------------------------

    iv, ciphertext = aes_encrypt(
        plaintext,
        aes_key
    )


    # --------------------------------------------------------
    # STORE IV + CIPHERTEXT
    # --------------------------------------------------------
    #
    # IV is NOT secret.
    #
    # We store:
    #
    #       IV + ciphertext
    #
    # in the encrypted file.
    #
    # base64 makes binary data safe to store/display.
    # --------------------------------------------------------

    encrypted_file_data = (
        base64.b64encode(iv) +
        b"\n" +
        base64.b64encode(ciphertext)
    )


    with open(
        ENCRYPTED_FILE,
        "wb"
    ) as file:

        file.write(
            encrypted_file_data
        )


    # --------------------------------------------------------
    # RSA ENCRYPT AES KEY
    # --------------------------------------------------------
    #
    # RSA protects the AES key.
    #
    #       AES key
    #          ↓
    #       RSA public key
    #          ↓
    #       encrypted AES key
    #
    # --------------------------------------------------------

    encrypted_aes_key = rsa_encrypt_aes_key(
        aes_key,
        rsa_public_key
    )


    # Store RSA-encrypted AES key.
    with open(
        AES_KEY_FILE,
        "wb"
    ) as file:

        file.write(
            base64.b64encode(
                encrypted_aes_key
            )
        )


    # --------------------------------------------------------
    # DISPLAY RESULTS
    # --------------------------------------------------------

    print("\nAES Ciphertext:")
    print(
        base64.b64encode(
            ciphertext
        ).decode()
    )


    print("\nAES IV:")
    print(
        base64.b64encode(
            iv
        ).decode()
    )


    print("\nRSA Encrypted AES Key:")
    print(
        base64.b64encode(
            encrypted_aes_key
        ).decode()
    )


    print(
        "\nEncrypted file saved as:",
        ENCRYPTED_FILE
    )

    print(
        "Encrypted AES key saved as:",
        AES_KEY_FILE
    )


# ============================================================
#              HASH ENCRYPTED AES FILE
# ============================================================
#
# We hash the ciphertext, NOT the plaintext.
#
# This gives us a fingerprint of the encrypted file.
#
# ============================================================

def hash_encrypted_file():

    with open(
        ENCRYPTED_FILE,
        "rb"
    ) as file:

        encrypted_data = file.read()


    hash_value = calculate_hash(
        encrypted_data
    )


    print("\n================================")
    print("         SHA-256 HASH")
    print("================================")

    print(
        "Hash of encrypted file:"
    )

    print(hash_value)


    # Store the original trusted hash.
    with open(
        "sender_hash.txt",
        "w"
    ) as file:

        file.write(
            hash_value
        )


    print(
        "\nSender hash stored in sender_hash.txt"
    )


# ============================================================
#              VERIFY FILE INTEGRITY
# ============================================================
#
# We compare:
#
#       Sender's original hash
#
#                VS
#
#       Receiver's newly calculated hash
#
# If:
#
#       same → file unchanged
#
#       different → file tampered
#
# ============================================================

def verify_integrity():

    print("\n================================")
    print("       INTEGRITY VERIFICATION")
    print("================================")


    # Read sender's trusted hash.
    with open(
        "sender_hash.txt",
        "r"
    ) as file:

        sender_hash = file.read().strip()


    # Read encrypted file currently present.
    with open(
        ENCRYPTED_FILE,
        "rb"
    ) as file:

        encrypted_data = file.read()


    # Calculate hash again.
    receiver_hash = calculate_hash(
        encrypted_data
    )


    print("\nSender Hash:")
    print(sender_hash)


    print("\nReceiver Hash:")
    print(receiver_hash)


    # --------------------------------------------------------
    # COMPARE HASHES
    # --------------------------------------------------------

    if sender_hash == receiver_hash:

        print(
            "\nINTEGRITY VERIFIED"
        )

        print(
            "Encrypted file has NOT been modified."
        )

        return True


    else:

        print(
            "\nINTEGRITY FAILED"
        )

        print(
            "Encrypted file has been modified/tampered."
        )

        return False


# ============================================================
#          MODIFY ONE CHARACTER IN CIPHERTEXT
# ============================================================
#
# This function is specifically for the exam requirement:
#
# "For showing integrity failed, modify one character in the
# AES ciphertext and perform hashing on it."
#
# We deliberately change ONE BASE64 character.
#
# Then:
#
#       original hash != modified hash
#
# ============================================================

def tamper_ciphertext():

    print("\n================================")
    print("        TAMPERING TEST")
    print("================================")


    # Read encrypted file.
    with open(
        ENCRYPTED_FILE,
        "rb"
    ) as file:

        data = file.read()


    # Convert to mutable bytearray.
    modified_data = bytearray(
        data
    )


    # --------------------------------------------------------
    # Find a character in the ciphertext portion.
    #
    # Our file format is:
    #
    #       base64(IV)
    #       newline
    #       base64(ciphertext)
    #
    # Therefore find the newline.
    # --------------------------------------------------------

    newline_position = modified_data.find(
        b"\n"
    )


    # Ciphertext begins after newline.
    ciphertext_start = (
        newline_position + 1
    )


    # Change ONE character.
    #
    # We simply change the first Base64 character.
    original_character = modified_data[
        ciphertext_start
    ]


    if original_character == ord("A"):

        modified_data[
            ciphertext_start
        ] = ord("B")

    else:

        modified_data[
            ciphertext_start
        ] = ord("A")


    # Save tampered file.
    with open(
        ENCRYPTED_FILE,
        "wb"
    ) as file:

        file.write(
            modified_data
        )


    print(
        "\nOne character in the encrypted ciphertext was modified."
    )

    print(
        "Original character:",
        chr(original_character)
    )

    print(
        "New character:",
        chr(
            modified_data[
                ciphertext_start
            ]
        )
    )


# ============================================================
#                 DECRYPT HOSPITAL FILE
# ============================================================
#
# IMPORTANT:
#
# We MUST verify integrity BEFORE decryption.
#
# If hash verification fails:
#
#       STOP
#
# and DO NOT decrypt.
#
# ============================================================

def decrypt_file(
    rsa_private_key
):

    print("\n================================")
    print("          FILE DECRYPTION")
    print("================================")


    # --------------------------------------------------------
    # STEP 1: VERIFY INTEGRITY
    # --------------------------------------------------------

    integrity_valid = verify_integrity()


    # --------------------------------------------------------
    # SECURITY CONDITION
    # --------------------------------------------------------
    #
    # If integrity failed, immediately stop.
    #
    if not integrity_valid:

        print(
            "\nERROR: Integrity verification failed."
        )

        print(
            "Decryption will NOT be performed."
        )

        return


    # --------------------------------------------------------
    # STEP 2: READ ENCRYPTED FILE
    # --------------------------------------------------------

    with open(
        ENCRYPTED_FILE,
        "rb"
    ) as file:

        encrypted_data = file.read()


    # Separate:
    #
    #       IV
    #       ciphertext
    #
    iv_b64, ciphertext_b64 = (
        encrypted_data.split(b"\n")
    )


    # Decode Base64.
    iv = base64.b64decode(
        iv_b64
    )

    ciphertext = base64.b64decode(
        ciphertext_b64
    )


    # --------------------------------------------------------
    # STEP 3: READ RSA-ENCRYPTED AES KEY
    # --------------------------------------------------------

    with open(
        AES_KEY_FILE,
        "rb"
    ) as file:

        encrypted_aes_key = base64.b64decode(
            file.read()
        )


    # --------------------------------------------------------
    # STEP 4: RSA DECRYPT AES KEY
    # --------------------------------------------------------

    aes_key = rsa_decrypt_aes_key(
        encrypted_aes_key,
        rsa_private_key
    )


    # --------------------------------------------------------
    # STEP 5: AES DECRYPTION
    # --------------------------------------------------------

    plaintext = aes_decrypt(
        ciphertext,
        aes_key,
        iv
    )


    # --------------------------------------------------------
    # DISPLAY ALL DECRYPTED INFORMATION
    # --------------------------------------------------------

    print(
        "\nIntegrity verified successfully."
    )


    print("\nAES Key:")
    print(
        aes_key.hex()
    )


    print("\nDecrypted Original File Content:")
    print(
        plaintext.decode()
    )


# ============================================================
#              ELGAMAL AUTHORIZATION CODE
# ============================================================

def encrypt_authorization_code(
    elgamal_public_key
):

    print("\n================================")
    print("       ELGAMAL AUTHORIZATION")
    print("================================")


    authorization_code = input(
        "Enter authorization code: "
    )


    # Encrypt authorization code using ElGamal.
    c1, c2 = elgamal_encrypt(
        authorization_code,
        elgamal_public_key
    )


    # Store ciphertext.
    with open(
        ELGAMAL_FILE,
        "w"
    ) as file:

        file.write(
            f"{c1}\n{c2}"
        )


    # --------------------------------------------------------
    # DISPLAY ELGAMAL VALUES
    # --------------------------------------------------------

    print("\nElGamal Public Values:")

    print(
        "p =",
        elgamal_public_key["p"]
    )

    print(
        "g =",
        elgamal_public_key["g"]
    )

    print(
        "y =",
        elgamal_public_key["y"]
    )


    print("\nEncrypted Authorization Code:")

    print(
        "c1 =",
        c1
    )

    print(
        "c2 =",
        c2
    )


    print(
        "\nAuthorization ciphertext stored in:",
        ELGAMAL_FILE
    )


# ============================================================
#                    DISPLAY RSA VALUES
# ============================================================

def display_rsa_values(
    rsa_private_key,
    rsa_public_key
):

    print("\n================================")
    print("            RSA VALUES")
    print("================================")


    public_key = RSA.import_key(
        rsa_public_key
    )

    private_key = RSA.import_key(
        rsa_private_key
    )


    print("\nRSA Public Key:")
    print(
        public_key.export_key().decode()
    )


    print("\nRSA Private Key:")
    print(
        private_key.export_key().decode()
    )


# ============================================================
#                    MAIN PROGRAM
# ============================================================

def main():

    print("\n======================================")
    print("       HOSPITAL SECURITY SYSTEM")
    print("       AES + RSA + ELGAMAL")
    print("======================================")


    # --------------------------------------------------------
    # GENERATE KEYS
    # --------------------------------------------------------

    # AES-128 key.
    aes_key = generate_aes_key()


    # RSA key pair.
    rsa_private_key, rsa_public_key = (
        generate_rsa_keys()
    )


    # ElGamal key pair.
    elgamal_keys = generate_elgamal_keys()


    # Separate public/private information.
    elgamal_public_key = {
        "p": elgamal_keys["p"],
        "g": elgamal_keys["g"],
        "y": elgamal_keys["y"]
    }


    # --------------------------------------------------------
    # MENU
    # --------------------------------------------------------

    while True:

        print("\n--------------- MENU ---------------")

        print("1. Create hospital file")
        print("2. Encrypt file using AES-128")
        print("3. Display RSA values")
        print("4. Encrypt AES key using RSA")
        print("5. Hash encrypted AES file")
        print("6. Encrypt authorization code using ElGamal")
        print("7. Verify integrity")
        print("8. Tamper with AES ciphertext")
        print("9. Decrypt if integrity is valid")
        print("10. Exit")


        choice = input(
            "\nEnter choice: "
        )


        # ----------------------------------------------------
        # CREATE FILE
        # ----------------------------------------------------

        if choice == "1":

            create_file()


        # ----------------------------------------------------
        # AES ENCRYPTION
        # ----------------------------------------------------

        elif choice == "2":

            if not os.path.exists(
                ORIGINAL_FILE
            ):

                print(
                    "Create the original file first."
                )

                continue


            encrypt_file(
                aes_key,
                rsa_public_key
            )


        # ----------------------------------------------------
        # DISPLAY RSA
        # ----------------------------------------------------

        elif choice == "3":

            display_rsa_values(
                rsa_private_key,
                rsa_public_key
            )


        # ----------------------------------------------------
        # RSA ENCRYPT AES KEY
        # ----------------------------------------------------

        elif choice == "4":

            if not os.path.exists(
                ENCRYPTED_FILE
            ):

                print(
                    "Encrypt the file using AES first."
                )

                continue


            # The AES key was already RSA-encrypted during
            # encrypt_file().
            #
            # We simply explain/display the stored value here.
            with open(
                AES_KEY_FILE,
                "rb"
            ) as file:

                encrypted_key = file.read()


            print(
                "\nRSA encrypted AES key:"
            )

            print(
                encrypted_key.decode()
            )


        # ----------------------------------------------------
        # SHA-256 HASH
        # ----------------------------------------------------

        elif choice == "5":

            if not os.path.exists(
                ENCRYPTED_FILE
            ):

                print(
                    "Encrypt the file first."
                )

                continue


            hash_encrypted_file()


        # ----------------------------------------------------
        # ELGAMAL
        # ----------------------------------------------------

        elif choice == "6":

            encrypt_authorization_code(
                elgamal_public_key
            )


        # ----------------------------------------------------
        # VERIFY INTEGRITY
        # ----------------------------------------------------

        elif choice == "7":

            if not os.path.exists(
                "sender_hash.txt"
            ):

                print(
                    "Generate the original hash first."
                )

                continue


            verify_integrity()


        # ----------------------------------------------------
        # TAMPER WITH CIPHERTEXT
        # ----------------------------------------------------

        elif choice == "8":

            if not os.path.exists(
                ENCRYPTED_FILE
            ):

                print(
                    "Encrypt the file first."
                )

                continue


            tamper_ciphertext()


        # ----------------------------------------------------
        # DECRYPT
        # ----------------------------------------------------

        elif choice == "9":

            if not os.path.exists(
                ENCRYPTED_FILE
            ):

                print(
                    "Encrypted file does not exist."
                )

                continue


            if not os.path.exists(
                "sender_hash.txt"
            ):

                print(
                    "Generate the hash first."
                )

                continue


            decrypt_file(
                rsa_private_key
            )


        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        elif choice == "10":

            print(
                "\nExiting Hospital Security System..."
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
