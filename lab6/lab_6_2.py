import hashlib
import random
from Crypto.Util import number


# PARAMETER GENERATION
def generate_dh_parameters(bits=512):
    p = number.getPrime(bits)
    g = random.randint(2, p - 2)
    return p, g


# DIFFIE-HELLMAN KEY EXCHANGE & VERIFICATION
def diffie_hellman_exchange_and_verify(p: int, g: int):
    a_private = random.randint(2, p - 2)
    a_public = pow(g, a_private, p)

    b_private = random.randint(2, p - 2)
    b_public = pow(g, b_private, p)

    alice_derived_secret = pow(b_public, a_private, p)

    bob_derived_secret = pow(a_public, b_private, p)

    # Convert raw integer secret into a standard 256-bit AES key
    alice_key = hashlib.sha256(str(alice_derived_secret).encode()).hexdigest()
    bob_key = hashlib.sha256(str(bob_derived_secret).encode()).hexdigest()

    is_valid = (alice_derived_secret == bob_derived_secret) and (alice_key == bob_key)

    return {
        "alice_public": a_public,
        "bob_public": b_public,
        "alice_derived_key": alice_key,
        "bob_derived_key": bob_key,
        "is_valid": is_valid
    }


if __name__ == "__main__":
    print("DIFFIE-HELLMAN  ")

    # Generate dynamic parameters
    p, g = generate_dh_parameters(bits=512)
    print(f"Prime Modulus (p): {p}")
    print(f"Generator     (g): {g}\n")

    # Perform Key Exchange
    dh_res = diffie_hellman_exchange_and_verify(p, g)

    print("PUBLIC KEYS EXCHANGED OVER NETWORK")
    print(f"    Alice's Public Key (A) : {dh_res['alice_public']}")
    print(f"    Bob's Public Key   (B) : {dh_res['bob_public']}\n")

    print("INDEPENDENTLY DERIVED KEYS")
    print(f"    Alice's Symmetric Key  : {dh_res['alice_derived_key']}")
    print(f"    Bob's Symmetric Key    : {dh_res['bob_derived_key']}\n")

    print("VERIFICATION CHECK")
    print(f"    Shared Secret Verification : {'SUCCESS' if dh_res['is_valid'] else 'FAILED'}")
