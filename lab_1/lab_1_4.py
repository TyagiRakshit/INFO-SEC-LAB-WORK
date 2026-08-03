# Use a Hill cipher to encipher the message "We live in an insecure world".
# Key matrix K = [[3, 3], [2, 7]]

import math

def mod_inverse(a, m=26):
    """Calculates the modular multiplicative inverse of a mod m."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"No modular inverse exists for {a} mod {m}")

def get_matrix_inverse_2x2(key_matrix):
    """Finds the inverse of a 2x2 key matrix under modulo 26."""
    a, b = key_matrix[0][0], key_matrix[0][1]
    c, d = key_matrix[1][0], key_matrix[1][1]

    det = (a * d - b * c) % 26
    
    if math.gcd(det, 26) != 1:
        raise ValueError("Invalid key matrix: determinant is not coprime with 26.")

    det_inv = mod_inverse(det, 26)
    inv_a = (d * det_inv) % 26
    inv_b = (-b * det_inv) % 26
    inv_c = (-c * det_inv) % 26
    inv_d = (a * det_inv) % 26

    return [[inv_a, inv_b], [inv_c, inv_d]]

def prepare_text(text):
    """Cleans text to uppercase alphabetic letters and pads with 'X' if length is odd."""
    cleaned = "".join([ch.upper() for ch in text if ch.isalpha()])
    if len(cleaned) % 2 != 0:
        cleaned += 'X'  
    return cleaned

def hill_transform(text, matrix):
    """Performs matrix multiplication on 2-letter blocks."""
    result = []
    
    for i in range(0, len(text), 2):
        p1 = ord(text[i]) - ord('A')
        p2 = ord(text[i + 1]) - ord('A')

        c1 = (matrix[0][0] * p1 + matrix[0][1] * p2) % 26
        c2 = (matrix[1][0] * p1 + matrix[1][1] * p2) % 26

        result.append(chr(c1 + ord('A')))
        result.append(chr(c2 + ord('A')))

    return "".join(result)


text_input = input("Enter the plain text: ")

k00 = int(input("Enter key matrix element [0][0]: "))
k01 = int(input("Enter key matrix element [0][1]: "))
k10 = int(input("Enter key matrix element [1][0]: "))
k11 = int(input("Enter key matrix element [1][1]: "))

key_matrix = [[k00, k01], [k10, k11]]

clean_text = prepare_text(text_input)
inv_key_matrix = get_matrix_inverse_2x2(key_matrix)

cipher_text = hill_transform(clean_text, key_matrix)
decrypted_text = hill_transform(cipher_text, inv_key_matrix)

print("\n--- RESULTS ---")
print(f"Prepared Plaintext : {clean_text}")
print(f"Encrypted Ciphertext: {cipher_text}")
print(f"Decrypted Text      : {decrypted_text}")

