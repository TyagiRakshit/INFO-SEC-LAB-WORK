# Encrypt the message "Sensitive Information" using AES-128.
# Key: "0123456789ABCDEF0123456789ABCDEF"
# Decrypt the ciphertext to verify the original message.

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def parse_key(key_input):
    """
    Parses key into exactly 16 bytes for AES-128.
    If 32 hex chars are passed, converts from hex to 16 raw bytes.
    If 16 text chars are passed, encodes to 16 bytes.
    """
    if len(key_input) == 32:
        try:
            return bytes.fromhex(key_input)
        except ValueError:
            pass

    key_bytes = key_input.encode('utf-8')
    if len(key_bytes) != 16:
        raise ValueError("AES-128 key must be 16 bytes (or 32 hex characters) long.")
    return key_bytes


def aes_encrypt(plaintext_str, key_str):
    """Encrypts plaintext using AES-128 ECB mode with PKCS7 padding."""
    key = parse_key(key_str)
    plaintext = plaintext_str.encode('utf-8')

    cipher = AES.new(key, AES.MODE_ECB)

    # AES block size is always 16 bytes (128 bits)
    padded_text = pad(plaintext, AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)

    return encrypted_bytes


def aes_decrypt(ciphertext_bytes, key_str):
    """Decrypts AES-128 ciphertext and removes PKCS7 padding."""
    key = parse_key(key_str)

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext_bytes)
    decrypted_bytes = unpad(decrypted_padded, AES.block_size)

    return decrypted_bytes.decode('utf-8')



text_input = input("Enter the plain text: ")
key_input = input("Enter AES-128 key (16 chars or 32 hex chars): ")

# Encryption
cipher_bytes = aes_encrypt(text_input, key_input)
hex_ciphertext = cipher_bytes.hex().upper()

# Decryption
decrypted_text = aes_decrypt(cipher_bytes, key_input)

print("\n--- RESULTS ---")
print(f"Plaintext           : {text_input}")
print(f"Key                 : {key_input}")
print(f"Encrypted (Hex)     : {hex_ciphertext}")
print(f"Decrypted Text      : {decrypted_text}")

