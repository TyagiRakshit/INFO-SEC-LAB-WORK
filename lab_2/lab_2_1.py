

# ----------------------
# DES Tables & Constants 

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# ---------------------
# Helper Functions


def permute(block, table):
    """Permutes bits in a string according to a lookup table."""
    return "".join([block[i - 1] for i in table])

def string_to_bits(data):
    """Converts a string of characters to a string of binary bits."""
    return "".join([f"{ord(c):08b}" for c in data])

def bits_to_string(bits):
    """Converts a string of binary bits back to a character string."""
    chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8)]
    return "".join(chars)

def xor(bits1, bits2):
    """Bitwise XOR on two binary strings of equal length."""
    return "".join(['1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2)])

def left_shift(bits, num_shifts):
    """Circular left shift on a bit string."""
    return bits[num_shifts:] + bits[:num_shifts]

def generate_subkeys(key_bits):
    """Generates 16 48-bit subkeys from the 64-bit key."""
    permuted_key = permute(key_bits, PC1)
    C = permuted_key[:28]
    D = permuted_key[28:]
    subkeys = []

    for shift in SHIFTS:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        subkey = permute(C + D, PC2)
        subkeys.append(subkey)

    return subkeys

def feistel_function(R, subkey):
    """The DES F-function (Expansion -> XOR -> S-Boxes -> Permutation)."""
    expanded_R = permute(R, E)
    xored = xor(expanded_R, subkey)

    s_output = ""
    for i in range(8):
        block = xored[i * 6:(i + 1) * 6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = S_BOXES[i][row][col]
        s_output += f"{val:04b}"

    return permute(s_output, P)

def des_process_block(block_bits, subkeys):
    """Processes a single 64-bit block through 16 rounds of DES."""
    permuted = permute(block_bits, IP)
    L = permuted[:32]
    R = permuted[32:]

    for subkey in subkeys:
        next_L = R
        next_R = xor(L, feistel_function(R, subkey))
        L, R = next_L, next_R

    # Final swap and Inverse Initial Permutation
    combined = R + L
    return permute(combined, FP)

def pad_text(text):
    """Applies PKCS7 padding to ensure text is a multiple of 8 bytes."""
    pad_len = 8 - (len(text) % 8)
    return text + chr(pad_len) * pad_len

def unpad_text(text):
    """Removes PKCS7 padding."""
    pad_len = ord(text[-1])
    return text[:-pad_len]

# ----------------------------------
# Core Cipher Interfaces


def des_encrypt(plaintext, key):
    padded = pad_text(plaintext)
    key_bits = string_to_bits(key)
    subkeys = generate_subkeys(key_bits)

    ciphertext_bits = ""
    for i in range(0, len(padded), 8):
        block = padded[i:i + 8]
        block_bits = string_to_bits(block)
        ciphertext_bits += des_process_block(block_bits, subkeys)

    # Convert binary result to Hexadecimal string for output
    hex_result = f"{int(ciphertext_bits, 2):0{len(ciphertext_bits) // 4}X}"
    return ciphertext_bits, hex_result

def des_decrypt(ciphertext_bits, key):
    key_bits = string_to_bits(key)
    subkeys = generate_subkeys(key_bits)[::-1]  # Reverse subkeys for decryption

    decrypted_bits = ""
    for i in range(0, len(ciphertext_bits), 64):
        block_bits = ciphertext_bits[i:i + 64]
        decrypted_bits += des_process_block(block_bits, subkeys)

    decrypted_text = bits_to_string(decrypted_bits)
    return unpad_text(decrypted_text)



text_input = input("Enter the plain text: ")
key_input = input("Enter 8-character DES key: ")

if len(key_input) != 8:
    raise ValueError("DES key must be exactly 8 characters long.")


cipher_bits, hex_ciphertext = des_encrypt(text_input, key_input)


decrypted_text = des_decrypt(cipher_bits, key_input)

print("\nRESULTS\n")
print(f"Plaintext           : {text_input}")
print(f"Key                 : {key_input}")
print(f"Encrypted (Hex)     : {hex_ciphertext}")
print(f"Decrypted Text      : {decrypted_text}")

