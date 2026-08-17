# Encrypt the message "Classified Text" using Triple DES (3DES).
# Key: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" (48 Hex chars / 24 Bytes)
# Decrypt the ciphertext to verify the original message.

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def parse_3des_key(key_input):
    if len(key_input) == 48:
        try:
            return bytes.fromhex(key_input)
        except ValueError:
            pass

    key_bytes = key_input.encode('utf-8')
    if len(key_bytes) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes (or 48 hex characters) long.")

    return key_bytes


def triple_des_encrypt(plaintext_str, key_str):
    key = parse_3des_key(key_str)
    plaintext = plaintext_str.encode('utf-8')

    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_text = pad(plaintext, DES3.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)

    return encrypted_bytes


def triple_des_decrypt(ciphertext_bytes, key_str):
    """Decrypts 3DES ciphertext and removes PKCS7 padding."""
    key = parse_3des_key(key_str)
    cipher = DES3.new(key, DES3.MODE_ECB)

    decrypted_padded = cipher.decrypt(ciphertext_bytes)
    decrypted_bytes = unpad(decrypted_padded, DES3.block_size)

    return decrypted_bytes.decode('utf-8')



text_input = input("Enter the plain text: ")
key_input = input("Enter 3DES key (24 chars or 48 hex chars): ")
cipher_bytes = triple_des_encrypt(text_input, key_input)
hex_ciphertext = cipher_bytes.hex().upper()
decrypted_text = triple_des_decrypt(cipher_bytes, key_input)

print("\n--- RESULTS ---")
print(f"Plaintext           : {text_input}")
print(f"Key                 : {key_input}")
print(f"Encrypted (Hex)     : {hex_ciphertext}")
print(f"Decrypted Text      : {decrypted_text}")
