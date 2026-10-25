
# ============================================================
# LAB 5 - CODE 1: DJB2 HASH FUNCTION
# ============================================================
#
# AIM:
# To implement a simple hashing algorithm using Python.
#
# WHAT IS HASHING?
# Hashing converts input data (like a string) into a number
# called a HASH VALUE.
#
# For example:
# Input  : "ABC"
# Output : 193450027
#
# We are using the DJB2 hashing algorithm.
#
# DJB2 works using three main steps:
#
# 1. Start with an initial hash value of 5381.
# 2. For every character:
#       New Hash = (Old Hash * 33) + ASCII value
# 3. Keep the hash within the 32-bit integer range.
#
# IMPORTANT:
# The same input always produces the same hash.
# Even a small change in the input may change the hash.
#
# ============================================================


# STEP 1: Define a function to calculate the hash

def djb2_hash(message):

    # DJB2 always starts with the value 5381.
    hash_value = 5381

    # This is a 32-bit mask.
    #
    # 0xFFFFFFFF is hexadecimal.
    # In binary, it contains 32 ones.
    #
    # We use it to keep our hash within 32 bits.
    #
    # Maximum possible value = 4294967295

    mask = 0xFFFFFFFF

    # STEP 2: Process each character of the message

    for char in message:

        # ord() converts a character into its numeric value.
        #
        # For ASCII characters:
        # ord('A') = 65
        # ord('B') = 66
        # ord('C') = 67

        ascii_value = ord(char)

        # STEP 3: Calculate the new hash
        #
        # Formula:
        # New Hash = (Old Hash * 33) + ASCII value
        #
        # We use a left shift instead of multiplying by 33.
        #
        # hash_value << 5 means hash_value * 32
        #
        # Adding hash_value again gives:
        #
        # hash_value * 32 + hash_value
        # = hash_value * 33

        hash_value = ((hash_value << 5) + hash_value) + ascii_value

        # STEP 4: Apply the 32-bit mask
        #
        # The hash may become very large after multiplication.
        #
        # Bitwise AND (&) with 0xFFFFFFFF keeps only
        # the lowest 32 bits of the hash.
        #
        # This prevents the hash from exceeding
        # the unsigned 32-bit range.

        hash_value = hash_value & mask

    # STEP 5: Return the final calculated hash

    return hash_value


# ============================================================
# MAIN PROGRAM
# ============================================================

# This block runs when we execute this file directly.

if __name__ == "__main__":

    # Take a string as input from the user.
    message = input("Enter a string: ")

    # Call the DJB2 function to calculate its hash.
    result = djb2_hash(message)

    # Display the hash as a decimal number.
    print("Hash in Decimal:", result)

    # hex() converts the decimal hash into hexadecimal.
    print("Hash in Hexadecimal:", hex(result))
