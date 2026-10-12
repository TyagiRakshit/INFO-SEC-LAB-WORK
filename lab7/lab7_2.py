import random
from Crypto.Util import number
# RSA Key Generation
def generate_rsa_keys(bits=512):
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)

    return (e, n), (d, n)


# Encryption: c = m^e mod n
def rsa_encrypt(pub_key, plaintext):
    e, n = pub_key
    return pow(plaintext, e, n)


#Decryption: m = c^d mod n
def rsa_decrypt(priv_key, ciphertext):
    d, n = priv_key
    return pow(ciphertext, d, n)


# --- Main Experiment ---
if __name__ == "__main__":
    # Generate dynamic RSA keys
    pub_key, priv_key = generate_rsa_keys(bits=512)

    # Values to test
    val1 = int(input("Enter the first integer: "))
    val2 = int(input("Enter the second integer: "))
    expected_product = val1 * val2

    print(f"Multiplying numbers: {val1} * {val2} = {expected_product}\n")

    # Step 1: Encrypt both integers
    c1 = rsa_encrypt(pub_key, val1)
    c2 = rsa_encrypt(pub_key, val2)

    print(f"Ciphertext for {val1}:")
    print(f"{c1}\n")

    print(f"Ciphertext for {val2}:")
    print(f"{c2}\n")

    # Multiplicative Homomorphic Operation
    f, n = pub_key
    c_product = (c1 * c2) % n
    print(f"Resulting Encrypted Product:\n{c_product}\n")

    # Decrypt the resulting ciphertext
    decrypted_product = rsa_decrypt(priv_key, c_product)
    print(f"Decrypted Product Value: {decrypted_product}")

    # Step 4: Verification
    if decrypted_product == expected_product:
        print("Success!")
    else:
        print("Failure.")