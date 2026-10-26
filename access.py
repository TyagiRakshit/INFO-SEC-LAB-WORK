
# ============================================================
# INFORMATION SECURITY EXAM TOOLKIT
# FILE: access.py
# TOPIC: ROLE-BASED ACCESS CONTROL (RBAC)
#        AND PASSWORD HASHING
# LAB 4 - ACCESS CONTROL AND KEY MANAGEMENT
# ============================================================
#
# AIM:
# To control which operations different users can perform
# and to securely store and verify user passwords.
#
# ------------------------------------------------------------
# WHAT IS ROLE-BASED ACCESS CONTROL (RBAC)?
# ------------------------------------------------------------
#
# RBAC is a security mechanism where permissions are
# assigned according to the ROLE of a user.
#
# Different users can perform different operations.
#
# EXAMPLE: GRANT EXPENSE PORTAL
#
# RESEARCHER:
#   - Submit grant records
#   - View their own records
#
# REVIEWER:
#   - Search grant records
#   - Verify digital signatures
#   - View decrypted descriptions
#
# FINANCE OFFICER:
#   - Calculate total expenditure
#   - Verify records
#
# ADMIN:
#   - Perform all operations
#   - Manage cryptographic keys
#
# IMPORTANT:
# RBAC follows the PRINCIPLE OF LEAST PRIVILEGE.
#
# This means a user should receive only the permissions
# needed to perform their assigned tasks.
#
# ------------------------------------------------------------
# WHAT IS PASSWORD HASHING?
# ------------------------------------------------------------
#
# Password hashing converts a password into a hash value.
#
# Instead of storing:
#
# password = "hello123"
#
# We store:
#
# salt   = Random hexadecimal value
# digest = Derived password hash
#
# During login, we calculate the hash again and compare
# it with the stored value.
#
# This program uses:
#
# PBKDF2-HMAC-SHA256
#
# PBKDF2 = Password-Based Key Derivation Function 2
# HMAC   = Hash-based Message Authentication Code
# SHA256 = Secure Hash Algorithm producing 256-bit output
#
# ============================================================


# ============================================================
# STEP 1: IMPORT REQUIRED LIBRARIES
# ============================================================

# hashlib provides cryptographic hashing algorithms
# and password-based key derivation functions.

import hashlib

# hmac provides a secure comparison function.
#
# compare_digest() helps reduce timing-based information
# leakage during password hash comparison.

import hmac

# secrets generates cryptographically secure
# random numbers and bytes.
#
# We use it to generate a random password salt.

import secrets


# ============================================================
# STEP 2: DEFINE ROLE PERMISSIONS
# ============================================================

# PERMISSIONS is a Python dictionary.
#
# Dictionary format:
#
# role_name : {allowed_actions}
#
# Each role is mapped to a SET of permissions.
#
# A set stores unique values and supports fast membership
# checking using the 'in' operator.

PERMISSIONS = {

    # Researcher can submit records and view own records.
    "researcher": {
        "submit",
        "list_own"
    },

    # Reviewer can search records, verify signatures,
    # and view authorized decrypted descriptions.
    "reviewer": {
        "search",
        "verify",
        "view_description"
    },

    # Finance officer can calculate encrypted totals
    # and verify records.
    "finance": {
        "aggregate",
        "verify"
    },

    # Admin has all listed application permissions.
    "admin": {
        "submit",
        "list_own",
        "search",
        "verify",
        "view_description",
        "aggregate",
        "manage_keys"
    },

    # Voter can cast a vote.
    "voter": {
        "cast"
    },

    # Election Commission can verify, search,
    # and aggregate encrypted votes.
    "commission": {
        "verify",
        "search",
        "aggregate"
    }
}


# ============================================================
# STEP 3: CHECK WHETHER A ROLE HAS PERMISSION
# ============================================================

def allowed(role, action):

    # role   = User's assigned role
    # action = Operation the user wants to perform
    #
    # Example:
    #
    # role   = "researcher"
    # action = "submit"
    #
    # PERMISSIONS.get(role, set()) does the following:
    #
    # 1. Searches for the role in PERMISSIONS.
    # 2. Returns its permissions if the role exists.
    # 3. Returns an empty set if the role does not exist.
    #
    # Example:
    #
    # PERMISSIONS.get("researcher", set())
    #
    # Returns:
    # {"submit", "list_own"}
    #
    # The 'in' operator checks whether the requested
    # action exists in the role's permission set.
    #
    # Returns:
    # True  -> Permission is available.
    # False -> Permission is not available.

    return action in PERMISSIONS.get(role, set())


# ============================================================
# STEP 4: ENFORCE ROLE PERMISSIONS
# ============================================================

def require(role, action):

    # This function checks whether a user is allowed
    # to perform the requested operation.
    #
    # It calls the allowed() function defined above.

    if not allowed(role, action):

        # If permission is denied, raise an exception.
        #
        # PermissionError is a built-in Python exception.
        #
        # Example:
        #
        # require("voter", "manage_keys")
        #
        # Output:
        # PermissionError: voter cannot manage_keys

        raise PermissionError(
            f"{role} cannot {action}"
        )

    # If the permission exists, the function finishes
    # normally without raising an error.
    #
    # The calling program can then continue.


# ============================================================
# STEP 5: HASH A PASSWORD
# ============================================================

def password_hash(password):

    # This function converts a plaintext password
    # into a securely derived password hash.
    #
    # Example:
    #
    # Input:
    # "hello123"
    #
    # Output:
    # {
    #     "salt": "...",
    #     "digest": "..."
    # }
    #
    # The original password is NOT returned or stored.


    # --------------------------------------------------------
    # GENERATE RANDOM SALT
    # --------------------------------------------------------

    # Generate 16 random bytes.
    #
    # 16 bytes = 128 bits.
    #
    # A salt is a random value added to the password
    # hashing process.
    #
    # WHY USE A SALT?
    #
    # Suppose two users have the same password:
    #
    # User A: "hello123"
    # User B: "hello123"
    #
    # Without different salts, their password hashes
    # would be identical.
    #
    # With different random salts, their derived hashes
    # will normally be different.
    #
    # Salt does NOT need to be secret.

    salt = secrets.token_bytes(16)


    # --------------------------------------------------------
    # DERIVE PASSWORD HASH USING PBKDF2
    # --------------------------------------------------------

    # hashlib.pbkdf2_hmac() repeatedly applies a
    # password-based key derivation process.
    #
    # Parameters:
    #
    # 'sha256'          -> Hash algorithm
    # password.encode() -> Convert password into bytes
    # salt              -> Random salt generated above
    # 250000            -> Number of iterations
    #
    # WHY 250000 ITERATIONS?
    #
    # Repeated calculations make password guessing
    # more computationally expensive.
    #
    # The iteration count is a configuration choice,
    # not a universal security guarantee.

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        250000
    )


    # --------------------------------------------------------
    # RETURN SALT AND PASSWORD HASH
    # --------------------------------------------------------

    # salt and digest are currently byte strings.
    #
    # .hex() converts bytes into hexadecimal strings.
    #
    # Hexadecimal strings can be stored easily in JSON.
    #
    # We store BOTH:
    #
    # 1. Salt
    # 2. Derived password hash
    #
    # We do NOT store the plaintext password.

    return {
        "salt": salt.hex(),
        "digest": digest.hex()
    }


# ============================================================
# STEP 6: VERIFY PASSWORD DURING LOGIN
# ============================================================

def password_check(password, record):

    # This function checks whether an entered password
    # matches a previously stored password hash.
    #
    # Parameters:
    #
    # password -> Password entered during login.
    #
    # record   -> Dictionary containing stored
    #             salt and password digest.
    #
    # Example:
    #
    # record = {
    #     "salt": "...",
    #     "digest": "..."
    # }


    # --------------------------------------------------------
    # RECOVER THE STORED SALT
    # --------------------------------------------------------

    # The salt was stored as hexadecimal text.
    #
    # bytes.fromhex() converts it back into bytes.

    salt = bytes.fromhex(record["salt"])


    # --------------------------------------------------------
    # HASH THE ENTERED PASSWORD AGAIN
    # --------------------------------------------------------

    # Use the SAME:
    #
    # - SHA-256 algorithm
    # - Stored salt
    # - 250000 iterations
    #
    # If the password is correct, the derived digest
    # will match the stored digest.

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        250000
    )


    # --------------------------------------------------------
    # COMPARE THE HASHES SECURELY
    # --------------------------------------------------------

    # Convert the stored hexadecimal digest into bytes.

    stored_digest = bytes.fromhex(record["digest"])

    # hmac.compare_digest() compares both digests
    # using a comparison designed to reduce timing leaks.
    #
    # Returns:
    #
    # True  -> Password is correct.
    # False -> Password is incorrect.

    return hmac.compare_digest(
        digest,
        stored_digest
    )
