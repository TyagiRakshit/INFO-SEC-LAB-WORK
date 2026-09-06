# pip install cryptodome
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# --------------------------------
# DES Encryption
# --------------------------------

def des_encrypt(plaintext, key):

    plaintext = plaintext.encode()
    key = key.encode()

    cipher = DES.new(key, DES.MODE_ECB)

    padded_text = pad(plaintext, DES.block_size)

    ciphertext = cipher.encrypt(padded_text)

    return ciphertext


# --------------------------------
# DES Decryption
# --------------------------------

def des_decrypt(ciphertext, key):

    key = key.encode()

    cipher = DES.new(key, DES.MODE_ECB)

    decrypted_padded = cipher.decrypt(ciphertext)

    plaintext = unpad(decrypted_padded, DES.block_size)

    return plaintext.decode()


# --------------------------------
# Main Program
# --------------------------------

text_input = input("Enter the plain text: ")
key_input = input("Enter 8-character DES key: ")

if len(key_input) != 8:
    raise ValueError("DES key must be exactly 8 characters long.")


ciphertext = des_encrypt(text_input, key_input)

hex_ciphertext = ciphertext.hex().upper()

decrypted_text = des_decrypt(ciphertext, key_input)


# --------------------------------
# Results
# --------------------------------

print("\nRESULTS\n")
print(f"Plaintext           : {text_input}")
print(f"Key                 : {key_input}")
print(f"Encrypted (Hex)     : {hex_ciphertext}")
print(f"Decrypted Text      : {decrypted_text}")