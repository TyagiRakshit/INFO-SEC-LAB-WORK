import secrets
import hashlib
from datetime import datetime, timedelta


# ---------------- RABIN CRYPTOSYSTEM ----------------

def is_prime(n):
    if n < 2:
        return False

    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False

    return True


def generate_prime(bits):
    while True:
        p = secrets.randbits(bits)

        # Rabin requires p = 3 (mod 4)
        p |= 3
        p |= (1 << (bits - 1))

        if is_prime(p):
            return p


def generate_rabin_keys(bits):
    half = bits // 2

    p = generate_prime(half)
    q = generate_prime(half)

    while q == p:
        q = generate_prime(half)

    n = p * q

    return n, p, q


def rabin_encrypt(message, n):
    m = int.from_bytes(message.encode(), "big")

    if m >= n:
        raise ValueError("Message is too large for this key.")

    c = (m * m) % n

    return c


def rabin_decrypt(c, p, q):
    # Four possible square roots

    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    # Chinese Remainder Theorem
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)

    r1 = (mp * q * yp + mq * p * yq) % (p * q)
    r2 = (p * q - r1) % (p * q)
    r3 = (mp * q * yp - mq * p * yq) % (p * q)
    r4 = (p * q - r3) % (p * q)

    roots = [r1, r2, r3, r4]

    messages = []

    for r in roots:
        try:
            message = r.to_bytes(
                (r.bit_length() + 7) // 8,
                "big"
            ).decode()

            messages.append(message)

        except UnicodeDecodeError:
            pass

    return messages


# ---------------- KEY MANAGEMENT SERVICE ----------------

class KeyManagementService:

    def __init__(self, key_size):
        self.key_size = key_size
        self.facilities = {}
        self.logs = []

    def log(self, operation, facility):
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        entry = f"{time} | {operation} | {facility}"

        self.logs.append(entry)

        print("LOG:", entry)

    def generate_keys(self, facility):

        n, p, q = generate_rabin_keys(self.key_size)

        self.facilities[facility] = {
            "public_key": n,
            "private_key": (p, q),
            "created": datetime.now(),
            "active": True
        }

        self.log("KEY GENERATED", facility)

    def distribute_keys(self, facility):

        if facility not in self.facilities:
            print("Facility not found.")
            return

        data = self.facilities[facility]

        if not data["active"]:
            print("Keys have been revoked.")
            return

        print("\nPublic Key:")
        print(data["public_key"])

        print("\nPrivate Key:")
        print(data["private_key"])

        self.log("KEY DISTRIBUTED", facility)

    def revoke_keys(self, facility):

        if facility not in self.facilities:
            print("Facility not found.")
            return

        self.facilities[facility]["active"] = False

        self.log("KEY REVOKED", facility)

    def renew_keys(self, facility):

        if facility not in self.facilities:
            print("Facility not found.")
            return

        self.generate_keys(facility)

        self.log("KEY RENEWED", facility)

    def automatic_renewal(self):

        today = datetime.now()

        for facility, data in self.facilities.items():

            if today - data["created"] >= timedelta(days=365):
                self.renew_keys(facility)

    def show_facilities(self):

        print("\n--- FACILITIES ---")

        for facility, data in self.facilities.items():

            status = "ACTIVE" if data["active"] else "REVOKED"

            print(f"{facility} : {status}")

    def show_logs(self):

        print("\n--- AUDIT LOG ---")

        for log in self.logs:
            print(log)


# ---------------- MAIN PROGRAM ----------------

print(" HEALTHCARE INC. KEY MANAGEMENT")


key_size = int(input("Enter Rabin key size : ")) #(e.g. 16, 32, 64):

kms = KeyManagementService(key_size)

number = int(input("\nEnter number of hospitals/clinics: "))

for i in range(number):

    facility = input("Enter hospital/clinic name: ")

    kms.generate_keys(facility)


# ---------------- MENU ----------------

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

    # DISTRIBUTE
    if choice == "1":

        facility = input("Enter facility name: ")

        kms.distribute_keys(facility)


    # ENCRYPT
    elif choice == "2":

        facility = input("Enter facility name: ")

        if facility not in kms.facilities:
            print("Facility not found.")
            continue

        if not kms.facilities[facility]["active"]:
            print("Keys are revoked.")
            continue

        message = input("Enter patient data: ")

        n = kms.facilities[facility]["public_key"]

        try:
            ciphertext = rabin_encrypt(message, n)

            print("Encrypted data:", ciphertext)

        except ValueError as e:
            print(e)


    # DECRYPT
    elif choice == "3":

        facility = input("Enter facility name: ")

        if facility not in kms.facilities:
            print("Facility not found.")
            continue

        data = kms.facilities[facility]

        if not data["active"]:
            print("Keys are revoked.")
            continue

        ciphertext = int(input("Enter ciphertext: "))

        messages = rabin_decrypt(
            ciphertext,
            data["private_key"][0],
            data["private_key"][1]
        )

        print("\nPossible decrypted messages:")

        for message in messages:
            print(message)


    # REVOKE
    elif choice == "4":

        facility = input("Enter facility name: ")

        kms.revoke_keys(facility)


    # RENEW
    elif choice == "5":

        facility = input("Enter facility name: ")

        kms.renew_keys(facility)


    # ADD FACILITY
    elif choice == "6":

        facility = input("Enter new hospital/clinic name: ")

        kms.generate_keys(facility)


    # SHOW FACILITIES
    elif choice == "7":

        kms.show_facilities()


    # LOGS
    elif choice == "8":

        kms.show_logs()


    # AUTOMATIC RENEWAL
    elif choice == "9":

        kms.automatic_renewal()

        print("Automatic renewal check completed.")


    # EXIT
    elif choice == "10":

        print("Exiting Key Management Service...")
        break


    else:

        print("Invalid choice.")