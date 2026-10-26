
# ============================================================
# INFORMATION SECURITY EXAM TOOLKIT
# FILE: utils.py
#
# TOPIC: COMMON UTILITY FUNCTIONS
#
# ============================================================
#
# AIM:
# To provide reusable helper functions for:
#
# 1. Validating integer inputs.
# 2. Generating timestamps.
# 3. Displaying hexadecimal data.
# 4. Measuring algorithm execution time.
# 5. Calculating file hashes.
#
# WHY DO WE NEED THIS FILE?
#
# In scenario-based exams, many questions require
# common operations such as:
#
# - Taking valid numerical input
# - Recording submission time
# - Displaying data in hexadecimal
# - Comparing algorithm performance
# - Checking file integrity
#
# Instead of rewriting these functions every time,
# we import them from utils.py.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT REQUIRED LIBRARIES
# ============================================================

# time:
# Used to measure how long a function takes to execute.

import time

# hashlib:
# Provides hashing algorithms such as:
# MD5, SHA-1, SHA-256 and SHA-512.

import hashlib

# datetime:
# Provides date and time functions.
#
# timezone:
# Allows us to use UTC time.

from datetime import datetime, timezone


# ============================================================
# PART 1: INTEGER INPUT VALIDATION
# ============================================================
#
# WHAT IS INPUT VALIDATION?
#
# Input validation checks whether the user has entered
# acceptable data.
#
# Example:
#
# A grant amount should be a nonnegative integer.
#
# Valid:
# 1000
# 5000
# 0
#
# Invalid:
# abc
# 12.5
# -100 (when minimum = 0)
#
# ============================================================


def ask_int(prompt, minimum=None, maximum=None):

    # PARAMETERS:
    #
    # prompt:
    #   Message displayed to the user.
    #
    # minimum:
    #   Smallest allowed integer.
    #
    # maximum:
    #   Largest allowed integer.
    #
    # Example:
    #
    # ask_int("Enter amount: ", minimum=0)
    #
    # Accepts:
    # 0, 1, 2, 3, ...
    #
    # Rejects:
    # Negative numbers and non-integer input.


    # --------------------------------------------------------
    # STEP 1: KEEP ASKING UNTIL VALID INPUT
    # --------------------------------------------------------

    # while True creates a loop that continues
    # until we explicitly return a valid value.

    while True:

        try:

            # ------------------------------------------------
            # STEP 2: TAKE USER INPUT
            # ------------------------------------------------

            # input() always returns a string.
            #
            # int() converts that string into an integer.
            #
            # Example:
            # "100" -> 100
            #
            # If input is "abc", int() raises ValueError.

            value = int(input(prompt))


            # ------------------------------------------------
            # STEP 3: CHECK MINIMUM VALUE
            # ------------------------------------------------

            # If minimum is provided, reject values
            # smaller than the minimum.
            #
            # Example:
            #
            # minimum = 0
            # value = -10
            #
            # Invalid input.

            if minimum is not None:

                if value < minimum:
                    raise ValueError


            # ------------------------------------------------
            # STEP 4: CHECK MAXIMUM VALUE
            # ------------------------------------------------

            # If maximum is provided, reject values
            # greater than the maximum.

            if maximum is not None:

                if value > maximum:
                    raise ValueError


            # ------------------------------------------------
            # STEP 5: RETURN VALID INTEGER
            # ------------------------------------------------

            # If no error occurred, return the integer.
            #
            # This exits the while loop automatically.

            return value


        except ValueError:

            # If input is invalid, display a message
            # and repeat the loop.

            print(
                "Invalid integer, please retry."
            )


# ============================================================
# PART 2: UTC TIMESTAMP
# ============================================================
#
# WHAT IS A TIMESTAMP?
#
# A timestamp records the date and time of an event.
#
# Example:
#
# A voter submits a ballot.
#
# We store:
#
# Submission Time = 2026-10-26T10:30:00+00:00
#
# UTC = Coordinated Universal Time.
#
# WHY USE UTC?
#
# UTC provides a consistent time reference
# across different geographical locations.
#
# ============================================================


def utc_timestamp():

    # datetime.now(timezone.utc):
    # Gets the current UTC date and time.
    #
    # isoformat():
    # Converts the datetime object into ISO 8601 text.
    #
    # Example:
    # "2026-10-26T10:30:00+00:00"

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    return timestamp


# ============================================================
# PART 3: HEXADECIMAL DUMP
# ============================================================
#
# WHAT IS A HEX DUMP?
#
# A hex dump displays binary data in hexadecimal form.
#
# Each byte is represented by two hexadecimal digits.
#
# Example:
#
# Text: ABC
#
# ASCII:
# A = 65
# B = 66
# C = 67
#
# Hexadecimal:
# A = 41
# B = 42
# C = 43
#
# Hex dump:
#
# 00000000  41 42 43
#
# ============================================================


def hex_dump(data, width=16):

    # PARAMETERS:
    #
    # data:
    #   Bytes that we want to display.
    #
    # width:
    #   Number of bytes displayed per line.
    #
    # Default width = 16 bytes.
    #
    # Example:
    #
    # data = b"ABC"
    #
    # Output:
    # 00000000  41 42 43


    # --------------------------------------------------------
    # STEP 1: PROCESS DATA IN CHUNKS
    # --------------------------------------------------------

    # range(0, len(data), width):
    #
    # Starts from 0.
    # Increases by width each time.
    #
    # Example:
    #
    # len(data) = 40
    # width = 16
    #
    # Starting positions:
    # 0, 16, 32

    lines = []

    for i in range(0, len(data), width):

        # ----------------------------------------------------
        # STEP 2: EXTRACT ONE CHUNK
        # ----------------------------------------------------

        # data[i:i+width] extracts up to width bytes.

        chunk = data[i:i + width]


        # ----------------------------------------------------
        # STEP 3: CONVERT CHUNK TO HEXADECIMAL
        # ----------------------------------------------------

        # hex(" ") converts bytes to hexadecimal text
        # with spaces between bytes.
        #
        # Example:
        # b"ABC" -> "41 42 43"

        hex_values = chunk.hex(" ")


        # ----------------------------------------------------
        # STEP 4: FORMAT BYTE OFFSET
        # ----------------------------------------------------

        # f"{i:08x}" displays the starting byte offset
        # as an 8-digit hexadecimal number.
        #
        # Example:
        #
        # i = 0  -> 00000000
        # i = 16 -> 00000010
        # i = 32 -> 00000020

        offset = f"{i:08x}"


        # ----------------------------------------------------
        # STEP 5: ADD FORMATTED LINE
        # ----------------------------------------------------

        line = f"{offset}  {hex_values}"

        lines.append(line)


    # --------------------------------------------------------
    # STEP 6: JOIN ALL LINES
    # --------------------------------------------------------

    # "\n".join(lines) joins all lines using
    # newline characters.

    return "\n".join(lines)


# ============================================================
# PART 4: PERFORMANCE BENCHMARKING
# ============================================================
#
# WHAT IS BENCHMARKING?
#
# Benchmarking measures how long an operation takes.
#
# Example:
#
# Compare execution time of:
#
# MD5
# SHA-1
# SHA-256
#
# We use time.perf_counter() because it is suitable
# for measuring elapsed execution time.
#
# ============================================================


def benchmark(fn, repeats=5):

    # PARAMETERS:
    #
    # fn:
    #   Function we want to measure.
    #
    # repeats:
    #   Number of times the function is executed.
    #
    # Default = 5.
    #
    # WHY REPEAT?
    #
    # A single timing result can be affected by:
    #
    # - Operating system scheduling
    # - Background programs
    # - CPU activity
    #
    # Repeating measurements gives us a more
    # useful comparison.


    # --------------------------------------------------------
    # STEP 1: CREATE EMPTY LIST
    # --------------------------------------------------------

    # Stores execution time of each run.

    samples = []


    # --------------------------------------------------------
    # STEP 2: EXECUTE FUNCTION MULTIPLE TIMES
    # --------------------------------------------------------

    for _ in range(repeats):

        # Record start time.

        start = time.perf_counter()


        # Call the function being benchmarked.
        #
        # Example:
        #
        # fn = lambda: hash_text("Hello", "sha256")

        fn()


        # Record end time.

        end = time.perf_counter()


        # ----------------------------------------------------
        # STEP 3: CALCULATE ELAPSED TIME
        # ----------------------------------------------------

        # end - start gives seconds.
        #
        # Multiply by 1000 to convert into milliseconds.

        elapsed_ms = (end - start) * 1000


        # Store the measured time.

        samples.append(elapsed_ms)


    # --------------------------------------------------------
    # STEP 4: SORT MEASUREMENTS
    # --------------------------------------------------------

    # sorted() arranges times from smallest to largest.

    sorted_samples = sorted(samples)


    # --------------------------------------------------------
    # STEP 5: RETURN MIDDLE MEASUREMENT
    # --------------------------------------------------------

    # len(samples) // 2 gives the middle index.
    #
    # Example:
    #
    # samples = [2, 5, 3, 4, 1]
    #
    # sorted = [1, 2, 3, 4, 5]
    #
    # middle = 3
    #
    # This is the median for an odd number of repeats.
    #
    # For an even number of repeats, this implementation
    # returns the upper middle value rather than the
    # conventional average of the two middle values.

    middle_index = len(sorted_samples) // 2

    return sorted_samples[middle_index]


# ============================================================
# PART 5: FILE HASHING
# ============================================================
#
# WHAT IS FILE HASHING?
#
# File hashing calculates a digest of an entire file.
#
# Useful for:
#
# 1. Detecting file modification.
# 2. Checking file integrity.
# 3. Verifying downloaded or transferred files.
# 4. Generating file digests for digital signatures.
#
# EXAMPLE:
#
# Original file -> SHA-256 -> Hash A
#
# Received file -> SHA-256 -> Hash B
#
# If Hash A != Hash B:
# The file contents are different.
#
# IMPORTANT:
# A plain hash does not authenticate the sender.
#
# ============================================================


def hash_file(path, algo="sha256"):

    # PARAMETERS:
    #
    # path:
    #   Path of file to hash.
    #
    # algo:
    #   Hashing algorithm.
    #
    # Examples:
    # "md5"
    # "sha1"
    # "sha256"
    # "sha512"


    # --------------------------------------------------------
    # STEP 1: CREATE HASH OBJECT
    # --------------------------------------------------------

    # hashlib.new() creates the selected hash algorithm.

    hasher = hashlib.new(algo)


    # --------------------------------------------------------
    # STEP 2: OPEN FILE IN BINARY MODE
    # --------------------------------------------------------

    # "rb" = Read Binary.
    #
    # This works for text files, PDFs, images,
    # documents and other binary files.

    with open(path, "rb") as file:


        # ----------------------------------------------------
        # STEP 3: READ FILE IN CHUNKS
        # ----------------------------------------------------

        # Read 65536 bytes (64 KiB) at a time.
        #
        # This avoids loading the entire file
        # into memory.

        for chunk in iter(
            lambda: file.read(65536),
            b""
        ):

            # Add each chunk to the hash calculation.

            hasher.update(chunk)


    # --------------------------------------------------------
    # STEP 4: RETURN FINAL DIGEST
    # --------------------------------------------------------

    # hexdigest() returns hexadecimal text.

    return hasher.hexdigest()
