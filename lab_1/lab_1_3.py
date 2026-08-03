# 3. Use the Playfair cipher to encipher the message "The key is hidden under the door pad". The
# secret key can be made by filling the first and part of the second row with the word
# "GUIDANCE" and filling the rest of the matrix with the rest of the alphabet.

def create_playfair_matrix(key):
    # Generates a 5x5  matrix using the given key (I/J combined).
    key = key.upper().replace('J', 'I')
    matrix = []
    used_letters = set()

    for char in key:
        if 'A' <= char <= 'Z' and char not in used_letters:
            matrix.append(char)
            used_letters.add(char)

    for ascii_val in range(ord('A'), ord('Z') + 1):
        char = chr(ascii_val)
        if char == 'J':
            continue
        if char not in used_letters:
            matrix.append(char)
            used_letters.add(char)

    grid = [matrix[i:i + 5] for i in range(0, 25, 5)]
    return grid

def prepare_plaintext(text):
    """Cleans text, replaces J with I, inserts X between duplicates, pads if odd."""
    text = "".join([ch.upper() for ch in text if ch.isalpha()]).replace('J', 'I')
    prepared = []
    i = 0
    while i < len(text):
        prepared.append(text[i])
        if i + 1 < len(text):
            if text[i] == text[i + 1]:
                prepared.append('X') 
            else:
                prepared.append(text[i + 1])
                i += 1
        else:
            prepared.append('X') 
        i += 1
    return "".join(prepared)

def find_position(matrix, char):
    """Returns row and column of character in 5x5 matrix."""
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None

def playfair_transform(text, matrix, mode='encrypt'):
    """Encrypts or Decrypts text using Playfair matrix rules."""
    shift = 1 if mode == 'encrypt' else -1
    result = []

    for i in range(0, len(text), 2):
        r1, c1 = find_position(matrix, text[i])
        r2, c2 = find_position(matrix, text[i + 1])

        if r1 == r2:
            result.append(matrix[r1][(c1 + shift) % 5])
            result.append(matrix[r2][(c2 + shift) % 5])
        elif c1 == c2:
            result.append(matrix[(r1 + shift) % 5][c1])
            result.append(matrix[(r2 + shift) % 5][c2])
        else:
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])

    return "".join(result)

text_input = input("Enter the plain text: ")
key_input = input("Enter secret key word for Playfair matrix: ")

matrix = create_playfair_matrix(key_input)
prepared_text = prepare_plaintext(text_input)

print("\nGenerated 5x5 Playfair Matrix:")
for row in matrix:
    print(" ".join(row))
print("-" * 30)

cipher_text = playfair_transform(prepared_text, matrix, mode='encrypt')
decrypted_prepared = playfair_transform(cipher_text, matrix, mode='decrypt')

print(f"Prepared Plaintext : {prepared_text}")
print(f"Encrypted Ciphertext: {cipher_text}")
print(f"Decrypted Text      : {decrypted_prepared}")

