def djb2_hash(input_string: str) -> int:
    # Initial hash value
    hash_value = 5381

    # 32-bit mask (0xFFFFFFFF)
    MASK_32_BIT = 0xFFFFFFFF

    for char in input_string:
        # hash * 33 + ord(char)
        # (hash_value << 5) + hash_value is equivalent to hash_value * 32 + hash_value = hash_value * 33

        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        # Keep within 32-bit unsigned integer range using bitwise AND mask

        hash_value &= MASK_32_BIT

    return hash_value


if __name__ == "__main__":
    # Test with dynamic inputs
    user_input = input("Enter a string to hash: ")
    result = djb2_hash(user_input)
    print(f"Hash value (Decimal): {result}")
    print(f"Hash value (Hex): {hex(result)}")