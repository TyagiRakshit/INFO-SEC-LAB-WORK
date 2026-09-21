import secrets
from datetime import datetime, timedelta


# ============================================================
#                 RABIN CRYPTOSYSTEM
# ============================================================
#
# Rabin is a public-key cryptosystem similar in concept to RSA.
#
# Rabin uses:
#
#       PUBLIC KEY  -> n
#       PRIVATE KEY -> (p, q)
#
# where:
#
#       n = p * q
#
# and p and q are large primes satisfying:
#
#       p ≡ 3 (mod 4)
#       q ≡ 3 (mod 4)
#
# Encryption:
#
#       c = m² mod n
#
# Decryption is slightly different from RSA because one ciphertext
# can produce FOUR possible plaintext roots.
#
# Therefore, Rabin normally needs some padding/redundancy to
# identify which root is the original message.
#
# For our LAB implementation, we simply display the possible
# decrypted messages.
# ============================================================


# ------------------------------------------------------------
# CHECK WHETHER A NUMBER IS PRIME
# ------------------------------------------------------------
def is_prime(n):

    # Numbers smaller than 2 are not prime.
    if n < 2:
        return False

    # Try dividing n by every number from 2 to sqrt(n).
    #
    # Why only sqrt(n)?
    #
    # If n has a factor greater than sqrt(n), then the other
    # factor must be smaller than sqrt(n).
    #
    # Example:
    #
    # 35 = 5 × 7
    #
    # sqrt(35) ≈ 5.91
    #
    # So checking up to sqrt(n) is sufficient.
    for i in range(2, int(n ** 0.5) + 1):

        if n % i == 0:
            return False

    return True


# ------------------------------------------------------------
# GENERATE A PRIME OF GIVEN NUMBER OF BITS
# ------------------------------------------------------------
def generate_prime(bits):

    while True:

        # Generate a random number having approximately 'bits'
        # number of bits.
        #
        # Example:
        #
        # bits = 16
        #
        # generates a random 16-bit candidate.
        p = secrets.randbits(bits)


        # ----------------------------------------------------
        # RABIN SPECIAL REQUIREMENT
        # ----------------------------------------------------
        #
        # Rabin requires:
        #
        #       p ≡ 3 (mod 4)
        #
        # A number is 3 mod 4 when its last two binary bits
        # are 11.
        #
        # OR operation with 3:
        #
        #       p |= 3
        #
        # forces the last two bits to become 11.
        #
        # Example:
        #
        # 10010000
        # OR 00000011
        # ------------
        # 10010011
        #
        # Therefore:
        #
        #       p % 4 == 3
        # ----------------------------------------------------

        p |= 3


        # Make sure the highest bit is 1.
        #
        # This guarantees that the generated number actually
        # has the requested bit length.
        #
        # For example, for 16 bits:
        #
        #       1 << 15
        #
        # sets the 16th bit.
        p |= (1 << (bits - 1))


        # Check whether the generated number is prime.
        if is_prime(p):
            return p


# ------------------------------------------------------------
# GENERATE RABIN PUBLIC AND PRIVATE KEYS
# ------------------------------------------------------------
def generate_rabin_keys(bits):

    # We want an n-bit modulus.
    #
    # Since:
    #
    #       n = p × q
    #
    # p and q are approximately half the size of n.
    #
    # Example:
    #
    # key size = 1024 bits
    #
    # p ≈ 512 bits
    # q ≈ 512 bits
    half = bits // 2


    # Generate p and q.
    p = generate_prime(half)
    q = generate_prime(half)


    # p and q must be different primes.
    while q == p:
        q = generate_prime(half)


    # Rabin modulus.
    #
    # PUBLIC KEY:
    #
    #       n
    #
    n = p * q


    # Return:
    #
    #       n -> public key
    #       p,q -> private key
    return n, p, q


# ============================================================
#                     RABIN ENCRYPTION
# ============================================================

def rabin_encrypt(message, n):

    # A string cannot directly be used in the mathematical
    # Rabin equation.
    #
    # Therefore we convert:
    #
    #       String → Bytes → Integer
    #
    # Example:
    #
    #       "ABC"
    #
    # becomes bytes and then an integer.
    m = int.from_bytes(message.encode(), "big")


    # The plaintext integer must be smaller than n.
    #
    # Because Rabin performs:
    #
    #       c = m² mod n
    #
    # If m >= n, this simple implementation cannot represent
    # the original message correctly.
    if m >= n:
        raise ValueError("Message is too large for this key.")


    # --------------------------------------------------------
    # RABIN ENCRYPTION FORMULA
    # --------------------------------------------------------
    #
    #       c = m² mod n
    #
    # Only the public key n is required for encryption.
    #
    c = (m * m) % n


    # Return ciphertext.
    return c


# ============================================================
#                     RABIN DECRYPTION
# ============================================================

def rabin_decrypt(c, p, q):

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Rabin decryption does NOT directly give one plaintext.
    #
    # Because:
    #
    #       c = m² mod n
    #
    # there can be FOUR values whose square gives c modulo n.
    #
    # Therefore Rabin decryption produces:
    #
    #       r1
    #       r2
    #       r3
    #       r4
    #
    # One of these is the original plaintext.
    # --------------------------------------------------------


    # --------------------------------------------------------
    # STEP 1: FIND ROOT MODULO p
    # --------------------------------------------------------
    #
    # Since:
    #
    #       p ≡ 3 (mod 4)
    #
    # a square root of c modulo p can be calculated using:
    #
    #       mp = c^((p+1)/4) mod p
    #
    mp = pow(c, (p + 1) // 4, p)


    # --------------------------------------------------------
    # STEP 2: FIND ROOT MODULO q
    # --------------------------------------------------------
    #
    # Similarly:
    #
    #       mq = c^((q+1)/4) mod q
    #
    mq = pow(c, (q + 1) // 4, q)


    # --------------------------------------------------------
    # STEP 3: CHINESE REMAINDER THEOREM
    # --------------------------------------------------------
    #
    # We currently have:
    #
    #       m ≡ mp (mod p)
    #
    #       m ≡ mq (mod q)
    #
    # We need to combine these two congruences to obtain
    # solutions modulo:
    #
    #       n = p × q
    #
    # This is done using the Chinese Remainder Theorem (CRT).
    # --------------------------------------------------------


    # Find:
    #
    #       inverse(p) mod q
    #
    # That means we find yp such that:
    #
    #       p × yp ≡ 1 (mod q)
    #
    yp = pow(p, -1, q)


    # Find:
    #
    #       inverse(q) mod p
    #
    # That means:
    #
    #       q × yq ≡ 1 (mod p)
    #
    yq = pow(q, -1, p)


    # Calculate n again.
    n = p * q


    # --------------------------------------------------------
    # FOUR POSSIBLE ROOTS
    # --------------------------------------------------------
    #
    # CRT gives four possible square roots.
    #
    # The first root:
    #
    #       r1 = mp*q*yp + mq*p*yq
    #
    # --------------------------------------------------------
    r1 = (mp * q * yp + mq * p * yq) % n


    # The second root is the negative of r1 modulo n:
    #
    #       r2 = -r1 mod n
    #
    # which can be written as:
    #
    #       n - r1
    #
    r2 = (n - r1) % n


    # --------------------------------------------------------
    # THIRD ROOT
    # --------------------------------------------------------
    #
    # Use the opposite sign for one of the CRT components.
    #
    r3 = (mp * q * yp - mq * p * yq) % n


    # FOURTH ROOT:
    #
    #       r4 = -r3 mod n
    #
    r4 = (n - r3) % n


    # Store all four possible roots.
    roots = [r1, r2, r3, r4]


    # --------------------------------------------------------
    # CONVERT POSSIBLE INTEGER ROOTS BACK TO STRINGS
    # --------------------------------------------------------
    messages = []


    for r in roots:

        try:

            # Convert integer back to bytes.
            #
            # bit_length() tells us approximately how many bits
            # are required to represent r.
            #
            # (bits + 7) // 8 converts the number of bits into
            # the number of bytes required.
            message = r.to_bytes(
                (r.bit_length() + 7) // 8,
                "big"
            ).decode()


            # If decoding succeeds, this root represents
            # a valid UTF-8/text message.
            messages.append(message)


        except UnicodeDecodeError:

            # Some of the four roots may not represent valid
            # text, so simply ignore those roots.
            pass


    # Return all valid possible plaintexts.
    return messages


# ============================================================
#             CENTRALIZED KEY MANAGEMENT SERVICE
# ============================================================
#
# Healthcare Inc. has multiple facilities:
#
#       Hospital A
#       Hospital B
#       Clinic C
#
# Instead of every facility managing its own keys separately,
# we create one centralized Key Management Service (KMS).
#
# The KMS is responsible for:
#
#       1. Key generation
#       2. Key distribution
#       3. Key revocation
#       4. Key renewal
#       5. Facility management
#       6. Audit logging
#
# This directly corresponds to the requirements of the
# laboratory question.
# ============================================================


class KeyManagementService:


    # --------------------------------------------------------
    # CONSTRUCTOR
    # --------------------------------------------------------
    def __init__(self, key_size):

        # Store the selected Rabin key size.
        #
        # Example:
        #
        #       16
        #       32
        #       64
        #       1024
        #
        # For an actual secure system, a much larger key size
        # and a proper cryptographic library should be used.
        self.key_size = key_size


        # Dictionary containing information about all hospitals
        # and clinics.
        #
        # Example:
        #
        # facilities = {
        #     "Hospital A": {...},
        #     "Hospital B": {...}
        # }
        self.facilities = {}


        # Store audit logs.
        #
        # In a real system these should be stored in a secure,
        # tamper-resistant logging system.
        self.logs = []


    # --------------------------------------------------------
    # AUDIT LOGGING
    # --------------------------------------------------------
    def log(self, operation, facility):

        # Generate current timestamp.
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


        # Create a readable log entry.
        entry = f"{time} | {operation} | {facility}"


        # Save log in memory.
        self.logs.append(entry)


        # Display it as well.
        print("LOG:", entry)


    # ========================================================
    # KEY GENERATION
    # ========================================================
    def generate_keys(self, facility):

        # Generate:
        #
        #       n -> public key
        #       p,q -> private key
        #
        n, p, q = generate_rabin_keys(self.key_size)


        # Store the keys and other information associated
        # with the facility.
        self.facilities[facility] = {

            # Anyone can use n to encrypt data for this facility.
            "public_key": n,


            # p and q must remain secret.
            #
            # Together they form the private key.
            "private_key": (p, q),


            # Store when the key was created.
            "created": datetime.now(),


            # True means the key can currently be used.
            "active": True
        }


        # Record the operation in the audit log.
        self.log("KEY GENERATED", facility)


    # ========================================================
    # KEY DISTRIBUTION
    # ========================================================
    def distribute_keys(self, facility):

        # Check whether the facility exists.
        if facility not in self.facilities:

            print("Facility not found.")
            return


        # Get the facility's key information.
        data = self.facilities[facility]


        # A revoked facility should not receive its keys.
        if not data["active"]:

            print("Keys have been revoked.")
            return


        # Public key can safely be distributed.
        print("\nPublic Key:")
        print(data["public_key"])


        # ----------------------------------------------------
        # LAB DEMONSTRATION ONLY
        # ----------------------------------------------------
        #
        # Here we display the private key to demonstrate
        # "key distribution".
        #
        # In a REAL healthcare system, we should NEVER simply
        # print or expose private keys like this.
        #
        # Private keys should be protected using mechanisms
        # such as HSM/KMS/secure vaults.
        # ----------------------------------------------------
        print("\nPrivate Key:")
        print(data["private_key"])


        # Record distribution.
        self.log("KEY DISTRIBUTED", facility)


    # ========================================================
    # KEY REVOCATION
    # ========================================================
    def revoke_keys(self, facility):

        # Check whether facility exists.
        if facility not in self.facilities:

            print("Facility not found.")
            return


        # Mark the key as inactive.
        #
        # We don't necessarily have to delete the key because
        # the audit/history of the key may need to be retained.
        self.facilities[facility]["active"] = False


        # Record revocation.
        self.log("KEY REVOKED", facility)


    # ========================================================
    # KEY RENEWAL
    # ========================================================
    def renew_keys(self, facility):

        # Check whether facility exists.
        if facility not in self.facilities:

            print("Facility not found.")
            return


        # Generate a completely new Rabin key pair.
        #
        # This replaces:
        #
        #       old n,p,q
        #
        # with:
        #
        #       new n,p,q
        #
        self.generate_keys(facility)


        # Record renewal separately.
        self.log("KEY RENEWED", facility)


    # ========================================================
    # AUTOMATIC KEY RENEWAL
    # ========================================================
    def automatic_renewal(self):

        # Get current date and time.
        today = datetime.now()


        # Check every registered facility.
        for facility, data in self.facilities.items():

            # Check whether the key is older than 365 days.
            #
            # The lab question says keys should automatically
            # renew every 12 months.
            #
            # 12 months is approximated here as 365 days.
            if today - data["created"] >= timedelta(days=365):

                # Generate a new key pair.
                self.renew_keys(facility)


    # ========================================================
    # DISPLAY FACILITY STATUS
    # ========================================================
    def show_facilities(self):

        print("\n--- FACILITIES ---")


        # Go through every hospital/clinic.
        for facility, data in self.facilities.items():

            # Determine whether the key is active or revoked.
            status = "ACTIVE" if data["active"] else "REVOKED"


            # Display status.
            print(f"{facility} : {status}")


    # ========================================================
    # DISPLAY AUDIT LOGS
    # ========================================================
    def show_logs(self):

        print("\n--- AUDIT LOG ---")


        # Print every recorded operation.
        for log in self.logs:

            print(log)


# ============================================================
#                       MAIN PROGRAM
# ============================================================

print(" HEALTHCARE INC. KEY MANAGEMENT")


# ------------------------------------------------------------
# ASK USER FOR RABIN KEY SIZE
# ------------------------------------------------------------
#
# Example for demonstration:
#
#       16
#       32
#       64
#
# Actual cryptographic systems should use much larger
# cryptographically appropriate parameters.
#
# The laboratory question mentions configurable key size.
# ------------------------------------------------------------
key_size = int(input("Enter Rabin key size : "))


# Create the centralized Key Management Service.
kms = KeyManagementService(key_size)


# ------------------------------------------------------------
# REGISTER HOSPITALS / CLINICS
# ------------------------------------------------------------

number = int(
    input("\nEnter number of hospitals/clinics: ")
)


# Generate keys for every facility.
for i in range(number):

    facility = input("Enter hospital/clinic name: ")


    # Generate a Rabin public/private key pair
    # for this facility.
    kms.generate_keys(facility)


# ============================================================
#                         MENU
# ============================================================

while True:

    print("\n MENU ")

    print("1. Distribute Keys")
    print("2. Encrypt Patient Data")
    print("3. Decrypt Patient Data")
    print("4. Revoke Keys")
    print("5. Renew Keys")
    print("6. Add Hospital/Clinic")
    print("7. Show Facilities")
    print("8. Show Audit Logs")
    print("9. Automatic Key Renewal")
    print("10. Exit")


    choice = input("\nEnter choice: ")


    # ========================================================
    # OPTION 1: DISTRIBUTE KEYS
    # ========================================================

    if choice == "1":

        facility = input("Enter facility name: ")


        # KMS provides the keys belonging to that facility.
        kms.distribute_keys(facility)


    # ========================================================
    # OPTION 2: ENCRYPT PATIENT DATA
    # ========================================================

    elif choice == "2":

        facility = input("Enter facility name: ")


        # Check whether facility exists.
        if facility not in kms.facilities:

            print("Facility not found.")
            continue


        # Check whether its key has been revoked.
        if not kms.facilities[facility]["active"]:

            print("Keys are revoked.")
            continue


        # Read patient information.
        message = input("Enter patient data: ")


        # Get facility's public key.
        n = kms.facilities[facility]["public_key"]


        try:

            # Encrypt using:
            #
            #       c = m² mod n
            #
            ciphertext = rabin_encrypt(message, n)


            # Display ciphertext.
            print("Encrypted data:", ciphertext)


        except ValueError as e:

            # This happens if:
            #
            #       message integer >= n
            #
            print(e)


    # ========================================================
    # OPTION 3: DECRYPT PATIENT DATA
    # ========================================================

    elif choice == "3":

        facility = input("Enter facility name: ")


        # Check whether facility exists.
        if facility not in kms.facilities:

            print("Facility not found.")
            continue


        # Retrieve facility information.
        data = kms.facilities[facility]


        # Do not allow revoked facilities to use their keys.
        if not data["active"]:

            print("Keys are revoked.")
            continue


        # Read ciphertext.
        ciphertext = int(
            input("Enter ciphertext: ")
        )


        # Retrieve private p and q.
        #
        # private_key = (p,q)
        #
        messages = rabin_decrypt(
            ciphertext,
            data["private_key"][0],
            data["private_key"][1]
        )


        # Rabin can produce FOUR possible roots.
        print("\nPossible decrypted messages:")


        for message in messages:

            print(message)


    # ========================================================
    # OPTION 4: REVOKE KEYS
    # ========================================================

    elif choice == "4":

        facility = input("Enter facility name: ")


        # Mark facility's current key as revoked.
        kms.revoke_keys(facility)


    # ========================================================
    # OPTION 5: RENEW KEYS
    # ========================================================

    elif choice == "5":

        facility = input("Enter facility name: ")


        # Generate a completely new key pair.
        kms.renew_keys(facility)


    # ========================================================
    # OPTION 6: ADD NEW HOSPITAL / CLINIC
    # ========================================================

    elif choice == "6":

        facility = input(
            "Enter new hospital/clinic name: "
        )


        # Register the new facility and generate its keys.
        kms.generate_keys(facility)


    # ========================================================
    # OPTION 7: SHOW ALL FACILITIES
    # ========================================================

    elif choice == "7":

        kms.show_facilities()


    # ========================================================
    # OPTION 8: SHOW AUDIT LOGS
    # ========================================================

    elif choice == "8":

        kms.show_logs()


    # ========================================================
    # OPTION 9: AUTOMATIC KEY RENEWAL
    # ========================================================

    elif choice == "9":

        # Check every facility.
        #
        # If its key is older than 365 days,
        # automatically generate a new key pair.
        kms.automatic_renewal()


        print("Automatic renewal check completed.")


    # ========================================================
    # OPTION 10: EXIT
    # ========================================================

    elif choice == "10":

        print(
            "Exiting Key Management Service..."
        )

        break


    # ========================================================
    # INVALID OPTION
    # ========================================================

    else:

        print("Invalid choice.")
