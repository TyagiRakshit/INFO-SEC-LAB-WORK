import hashlib
import random
from Crypto.Util import number


# PARAMETER GENERATION

def generate_domain_parameters(bits=512):
    p = number.getPrime(bits)
    g = random.randint(2, p - 2)
    return p, g



# ELGAMAL DIGITAL SIGNATURE SCHEME
def elgamal_sign_and_verify(message: str, p: int, g: int):
    x = random.randint(2, p - 2)         # Private Key
    y = pow(g, x, p)                   # Public Key

    #  Hash the message
    msg_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)

    # Generate ephemeral key k (must be coprime to p - 1)
    while True:
        k = random.randint(2, p - 2)
        if number.GCD(k, p - 1) == 1:
            break

    # Compute Signature Components (r, s)
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (msg_hash - x * r)) % (p - 1)

    # Verify Signature: g^hash ≡ (y^r * r^s) mod p
    left = pow(g, msg_hash, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    is_valid = (left == right)

    return {
        "public_key": y,
        "signature": (r, s),
        "is_valid": is_valid
    }


#SCHNORR DIGITAL SIGNATURE SCHEME

def schnorr_sign_and_verify(message: str, p: int, g: int):
    q = p - 1        # Order q
    # Key Generation
    x = random.randint(2, q - 1)   # Private Key
    y = pow(g, x, p)                          # Public Key

    # Commitment
    r = random.randint(2, q - 1)              # Ephemeral key
    x_v = pow(g, r, p)

    # Challenge e = Hash(x_v || message) mod q
    e_input = f"{x_v}{message}".encode()
    e = int(hashlib.sha256(e_input).hexdigest(), 16) % q

    #Response s = (r + x * e) mod q
    s = (r + x * e) % q

    #Verify Signature
    # Reconstruct commitment: r' = (g^s * y^-e) mod p
    y_inv = pow(y, -1, p)
    r_prime = (pow(g, s, p) * pow(y_inv, e, p)) % p

    # Recompute challenge e'
    e_prime_input = f"{r_prime}{message}".encode()
    e_prime = int(hashlib.sha256(e_prime_input).hexdigest(), 16) % q
    is_valid = (e == e_prime)

    return {
        "public_key": y,
        "signature": (e, s),
        "is_valid": is_valid
    }

if __name__ == "__main__":
    # Get dynamic input
    user_message = input("Enter a message to sign: ").strip()
    print(" DIGITAL SIGNATURE ")
    print(f"Message : '{user_message}'")

    # Generate shared domain parameters
    p, g = generate_domain_parameters(bits=512)
    print(f"Prime Modulus (p): {p}")
    print(f"Generator     (g): {g}")

    # Run ElGamal
    elgamal_res = elgamal_sign_and_verify(user_message,p, g)
    print("\n ELGAMAL SIGNATURE SCHEME")
    print(f"    Public Key (y) : {elgamal_res['public_key']}")
    print(f"    Signature (r,s): {elgamal_res['signature']}")
    print(f"    Verification   : {'SUCCESS' if elgamal_res['is_valid'] else 'FAILED'}")

    # Run Schnorr
    schnorr_res = schnorr_sign_and_verify(user_message, p, g)
    print("\n SCHNORR SIGNATURE SCHEME")
    print(f"    Public Key (y) : {schnorr_res['public_key']}")
    print(f"    Signature (e,s): {schnorr_res['signature']}")
    print(f"    Verification   : {'SUCCESS' if schnorr_res['is_valid'] else 'FAILED'}")
