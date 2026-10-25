
# ============================================================
# LAB 5 - CODE 3
# COMPARISON OF MD5, SHA-1 AND SHA-256 HASHING ALGORITHMS
# ============================================================
#
# AIM:
# To compare MD5, SHA-1 and SHA-256 based on:
#
# 1. Time taken to calculate hashes.
# 2. Number of hash collisions.
#
# WHAT IS A HASH COLLISION?
#
# A collision occurs when TWO DIFFERENT INPUTS
# produce the SAME HASH VALUE.
#
# Example (imaginary hashes):
#
# "Apple"  -> A123
# "Mango"  -> B456
# "Orange" -> A123
#
# Here, Apple and Orange produce the same hash.
# Therefore, a collision has occurred.
#
# ============================================================


# Import required libraries

import hashlib   # Provides MD5, SHA-1 and SHA-256 algorithms
import random    # Generates random values
import string    # Provides letters, digits and punctuation
import time      # Measures execution time


# ============================================================
# STEP 1: GENERATE RANDOM STRINGS
# ============================================================

def generate_random_strings(count):

    # Create a collection of possible characters.
    #
    # ascii_letters = abc...xyzABC...XYZ
    # digits        = 0123456789
    # punctuation   = !@#$%^&* etc.
    #
    # We combine all three to create random strings.

    characters = (
        string.ascii_letters
        + string.digits
        + string.punctuation
    )

    # Empty list to store the generated strings
    dataset = []

    # Generate 'count' number of strings
    #
    # Example:
    # If count = 50, this loop runs 50 times.

    for i in range(count):

        # Select a random string length between 20 and 80
        #
        # Example: 35 characters

        length = random.randint(20, 80)

        # Select 'length' random characters
        #
        # random.choices() returns a list of characters.
        #
        # Example:
        # ['A', 'b', '7', '@']
        #
        # "".join() combines them into one string.
        #
        # Result: "Ab7@"

        random_string = "".join(
            random.choices(characters, k=length)
        )

        # Add the generated string to the dataset
        dataset.append(random_string)

    # Return the complete list of random strings
    return dataset


# ============================================================
# STEP 2: TEST A HASHING ALGORITHM
# ============================================================

def test_hash_algorithm(algorithm, dataset):

    # Start the timer before hashing begins.
    #
    # perf_counter() gives a high-resolution time value.
    # We use it to measure how long the process takes.

    start_time = time.perf_counter()

    # Dictionary to store:
    #
    # Hash value -> Original input string
    #
    # Example:
    # {
    #     "A123": "Apple",
    #     "B456": "Mango"
    # }
    #
    # This helps us detect actual collisions.

    seen_hashes = {}

    # Initially, no collisions have been found
    collisions = 0

    # Process every string in the dataset
    for item in dataset:

        # ----------------------------------------------------
        # STEP 3: CONVERT STRING INTO BYTES
        # ----------------------------------------------------

        # Hashing functions work with bytes.
        #
        # encode("utf-8") converts a string into bytes.
        #
        # Example:
        # "ABC" -> b'ABC'

        data = item.encode("utf-8")


        # ----------------------------------------------------
        # STEP 4: CREATE THE HASH OBJECT
        # ----------------------------------------------------

        # hashlib.new() selects a hashing algorithm.
        #
        # If algorithm = "md5", MD5 is selected.
        # If algorithm = "sha1", SHA-1 is selected.
        # If algorithm = "sha256", SHA-256 is selected.

        hasher = hashlib.new(algorithm)


        # ----------------------------------------------------
        # STEP 5: CALCULATE THE HASH
        # ----------------------------------------------------

        # update() passes the data to the hash function.

        hasher.update(data)

        # hexdigest() returns the hash as a hexadecimal string.
        #
        # MD5    -> 32 hexadecimal characters
        # SHA-1  -> 40 hexadecimal characters
        # SHA-256 -> 64 hexadecimal characters

        hash_value = hasher.hexdigest()


        # ----------------------------------------------------
        # STEP 6: CHECK FOR HASH COLLISIONS
        # ----------------------------------------------------

        # Check if this hash was already generated.

        if hash_value in seen_hashes:

            # If the hash exists, check whether the
            # original input string is different.
            #
            # Same hash + different input = collision.
            # Same hash + same input = NOT a collision.

            if seen_hashes[hash_value] != item:
                collisions += 1

        else:

            # If this hash is new, store it along
            # with its original input string.

            seen_hashes[hash_value] = item


    # ========================================================
    # STEP 7: CALCULATE TOTAL EXECUTION TIME
    # ========================================================

    # Record time after processing all strings
    end_time = time.perf_counter()

    # Calculate elapsed time in seconds
    elapsed_time = end_time - start_time

    # Convert seconds into milliseconds
    #
    # 1 second = 1000 milliseconds

    time_ms = elapsed_time * 1000

    # Return the execution time and collision count
    return time_ms, collisions


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    # Generate a random number between 50 and 100.
    #
    # This determines how many strings we will test.

    count = random.randint(50, 100)

    print("Number of random strings:", count)

    # Generate the dataset using our function
    dataset = generate_random_strings(count)

    # Algorithms we want to compare
    algorithms = ["md5", "sha1", "sha256"]

    # Print table headings
    print("\nAlgorithm | Time (ms) | Collisions")
    print("------------------------------------")

    # Test each algorithm one by one
    for algorithm in algorithms:

        # Call the testing function.
        #
        # It returns:
        # 1. Time taken
        # 2. Number of collisions

        time_taken, collisions = test_hash_algorithm(
            algorithm, dataset
        )

        # Display results
        #
        # upper() converts md5 -> MD5
        # .4f displays 4 digits after the decimal point

        print(
            f"{algorithm.upper():<10} | "
            f"{time_taken:<9.4f} | "
            f"{collisions}"
        )
