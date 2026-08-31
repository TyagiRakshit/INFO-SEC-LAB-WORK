import hashlib
import random
import string
import time


# 1. Generate random strings dynamically
def get_random_strings(count):
    chars = string.ascii_letters + string.digits + string.punctuation
    dataset = []

    for _ in range(count):
        # Pick a random length for each string (between 20 and 80 chars)
        length = random.randint(20, 80)
        rand_str = "".join(random.choices(chars, k=length))
        dataset.append(rand_str)

    return dataset


# 2. Benchmark a specific hashing algorithm
def test_hash_algo(algo_name, dataset):
    start = time.perf_counter()

    seen_hashes = set()
    collisions = 0

    for item in dataset:
        data_bytes = item.encode("utf-8")

        # Dynamically create the hash object (MD5, SHA1, SHA256)
        hasher = hashlib.new(algo_name)
        hasher.update(data_bytes)
        digest = hasher.hexdigest()

        # Check for collisions
        if digest in seen_hashes:
            collisions += 1
        else:
            seen_hashes.add(digest)

    end = time.perf_counter()

    # Time in milliseconds
    total_time = (end - start) * 1000

    return total_time, collisions


# --- Main Script ---
if __name__ == "__main__":
    # Pick a random number of test strings between 50 and 100
    num_items = random.randint(50, 100)
    print(f"Testing with {num_items} dynamically generated strings...\n")

    test_data = get_random_strings(num_items)
    algorithms = ["md5", "sha1", "sha256"]

    print("Algorithm  |  Time Taken (ms)  |  Collisions Found")
    print("-" * 50)

    for algo in algorithms:
        time_taken, collisions = test_hash_algo(algo, test_data)
        print(f"{algo.upper():<10} |  {time_taken:<16.4f} |  {collisions}")