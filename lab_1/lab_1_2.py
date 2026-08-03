
# 2. Encrypt the message "the house is being sold tonight" using one of the following ciphers.
# Ignore the space between words. Decrypt the message to get the original plaintext:
# • Vigenere cipher with key: "dollars"
# • Autokey cipher with key = 7.


# vigenere cipher

def vigenere_encrypt(text, key):
    cipher = []
    key = key.upper()
    key_length = len(key)
    key_index = 0

    for ch in text:
        if 'A' <= ch <= 'Z':
            shift = ord(key[key_index % key_length]) - ord('A')
            c = (ord(ch) - ord('A') + shift) % 26
            cipher.append(chr(c + ord('A')))
            key_index += 1
        elif 'a' <= ch <= 'z':
            shift = ord(key[key_index % key_length]) - ord('A')
            c = (ord(ch) - ord('a') + shift) % 26
            cipher.append(chr(c + ord('a')))
            key_index += 1
        else:
            cipher.append(ch)

    return "".join(cipher)

def vigenere_decrypt(text, key):
    plain = []
    key = key.upper()
    key_length = len(key)
    key_index = 0

    for ch in text:
        if 'A' <= ch <= 'Z':
            shift = ord(key[key_index % key_length]) - ord('A')
            p = (ord(ch) - ord('A') - shift) % 26
            plain.append(chr(p + ord('A')))
            key_index += 1
        elif 'a' <= ch <= 'z':
            shift = ord(key[key_index % key_length]) - ord('A')
            p = (ord(ch) - ord('a') - shift) % 26
            plain.append(chr(p + ord('a')))
            key_index += 1
        else:
            plain.append(ch)

    return "".join(plain)

# autokey cipher

def autokey_encrypt(text, key):
    cipher = []
    current_key = key

    for ch in text:
        if 'A' <= ch <= 'Z':
            p = ord(ch) - ord('A')
            c = (p + current_key) % 26
            cipher.append(chr(c + ord('A')))
            current_key = p  
        elif 'a' <= ch <= 'z':
            p = ord(ch) - ord('a')
            c = (p + current_key) % 26
            cipher.append(chr(c + ord('a')))
            current_key = p  
        else:
            cipher.append(ch)

    return "".join(cipher)

def autokey_decrypt(text, key):
    plain = []
    current_key = key

    for ch in text:
        if 'A' <= ch <= 'Z':
            c = ord(ch) - ord('A')
            p = (c - current_key) % 26
            plain.append(chr(p + ord('A')))
            current_key = p  
        elif 'a' <= ch <= 'z':
            c = ord(ch) - ord('a')
            p = (c - current_key) % 26
            plain.append(chr(p + ord('a')))
            current_key = p  
        else:
            plain.append(ch)

    return "".join(plain)

text_input = input("Enter the plain text: ")

cleaned_text = "".join(text_input.split())

vigenere_key = input("Enter string key for Vigenere Cipher: ")
autokey_key = int(input("Enter integer initial key for Autokey Cipher: "))

print("\n RESULTS :")

v_cipher = vigenere_encrypt(cleaned_text, vigenere_key)
v_plain = vigenere_decrypt(v_cipher, vigenere_key)
print(f"Vigenere Encrypted : {v_cipher}")
print(f"Vigenere Decrypted : {v_plain}\n")

a_cipher = autokey_encrypt(cleaned_text, autokey_key)
a_plain = autokey_decrypt(a_cipher, autokey_key)
print(f"Autokey Encrypted  : {a_cipher}")
print(f"Autokey Decrypted  : {a_plain}")

