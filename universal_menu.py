
# ============================================================
# INFORMATION SECURITY EXAM TOOLKIT
# FILE: universal_menu.py
#
# TOPIC:
# REUSABLE MENU-DRIVEN APPLICATION TEMPLATE
#
# ============================================================
#
# AIM:
#
# To create a reusable menu-driven Python application
# that can be modified for different exam questions.
#
# ------------------------------------------------------------
# WHY DO WE NEED THIS FILE?
# ------------------------------------------------------------
#
# In scenario-based lab exams, questions may combine:
#
# AES / DES / RSA / ECC
# Hashing / Digital Signatures
# Paillier / Searchable Encryption
# File Storage / Access Control
#
# Instead of writing a new menu system every time,
# we reuse this structure.
#
# We only modify:
#
# 1. User roles
# 2. Input fields
# 3. Cryptographic operations
# 4. Menu options
# 5. Output requirements
#
# ------------------------------------------------------------
# IMPORTANT:
# ------------------------------------------------------------
#
# This is a SKELETON, not a complete secure application.
#
# The original template stores plaintext descriptions
# and amounts.
#
# Encryption, hashing, signatures and Paillier
# operations must be inserted where indicated.
#
# The role menu is demonstration-only.
# Choosing a role does not authenticate a real user.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT LIBRARIES
# ============================================================

# Path:
# Used to create paths for storing JSON files.

from pathlib import Path


# Import functions from storage.py.
#
# load():
# Reads previously saved records.
#
# save():
# Saves records persistently.
#
# audit():
# Records actions in an audit log.

from storage import load, save, audit


# Import permission-checking function from access.py.
#
# require(role, action):
# Checks whether a role is allowed to perform an action.
#
# Raises PermissionError if access is denied.

from access import require


# Import utility functions from utils.py.
#
# ask_int():
# Takes integer input and validates its minimum value.
#
# utc_timestamp():
# Returns current UTC date and time.

from utils import ask_int, utc_timestamp


# ============================================================
# STEP 2: DEFINE STORAGE FILE PATHS
# ============================================================

# __file__ represents the current Python file.
#
# Path(__file__).parent gives its folder.
#
# This ensures records are saved beside the program.

ROOT = Path(__file__).parent


# File used to store application records.
#
# Example:
# Grant IDs and their associated data.

DATA = ROOT / "demo_records.json"


# File used to store audit logs.
#
# Example:
# Researcher submitted record G101.

AUDIT = ROOT / "demo_audit.json"


# ============================================================
# PART 1: SUBMIT A RECORD
# ============================================================

def submit(role):

    # This function allows an authorized user
    # to create and save a new record.
    #
    # CURRENT BEHAVIOR:
    #
    # 1. Check permission.
    # 2. Load existing records.
    # 3. Take record ID.
    # 4. Take description and amount.
    # 5. Save the record.
    # 6. Record the action in the audit log.
    #
    # FOR CRYPTOGRAPHIC QUESTIONS:
    #
    # Add encryption, hashing and signatures
    # before saving the record.


    # --------------------------------------------------------
    # STEP 1: CHECK PERMISSION
    # --------------------------------------------------------

    # Check whether this role can submit records.
    #
    # Example:
    #
    # require("researcher", "submit")
    #
    # Allowed.
    #
    # require("reviewer", "submit")
    #
    # Raises PermissionError.

    require(role, "submit")


    # --------------------------------------------------------
    # STEP 2: LOAD EXISTING RECORDS
    # --------------------------------------------------------

    # Load records from JSON file.
    #
    # If file does not exist, load() returns {}.

    records = load(DATA)


    # --------------------------------------------------------
    # STEP 3: TAKE RECORD ID
    # --------------------------------------------------------

    record_id = input(
        "Enter Record ID: "
    ).strip()


    # --------------------------------------------------------
    # STEP 4: VALIDATE RECORD ID
    # --------------------------------------------------------

    # Reject empty or duplicate IDs.
    #
    # Example:
    #
    # If G101 already exists, another G101
    # cannot be added.

    if not record_id or record_id in records:

        print("Invalid or duplicate Record ID.")
        return


    # --------------------------------------------------------
    # STEP 5: TAKE RECORD DETAILS
    # --------------------------------------------------------

    description = input(
        "Enter Description: "
    ).strip()


    # ask_int() ensures valid integer input.
    #
    # minimum=0 prevents negative values.

    amount = ask_int(
        "Enter Amount: ",
        minimum=0
    )


    # ========================================================
    # STEP 6: INSERT CRYPTOGRAPHIC OPERATIONS HERE
    # ========================================================
    #
    # THIS IS THE MOST IMPORTANT CUSTOMIZATION AREA.
    #
    # Depending on the question, you may need:
    #
    # AES / DES:
    #   Encrypt the description.
    #
    # PAILLIER:
    #   Encrypt the amount.
    #
    # MD5 / SHA-256:
    #   Calculate record hash.
    #
    # RSA / ELGAMAL:
    #   Digitally sign the record.
    #
    # EXAMPLE FOR GRANT PORTAL:
    #
    # encrypted_description, _ = symmetric_encrypt(
    #     description.encode(),
    #     "AES",
    #     192,
    #     "GCM",
    #     aes_key
    # )
    #
    # encrypted_amount = paillier_public.encrypt(amount)
    #
    # record_hash = hash_bytes(record_bytes, "md5")
    #
    # signature = rsa_sign(
    #     record_bytes,
    #     rsa_private
    # )
    #
    # IMPORTANT:
    # The variables above are examples.
    # Keys and record_bytes must be defined before use.


    # --------------------------------------------------------
    # STEP 7: CREATE RECORD
    # --------------------------------------------------------

    # This is the original PLAINTEXT demonstration.
    #
    # Replace plaintext fields with encrypted fields
    # when the question requires confidentiality.

    record = {
        "description": description,
        "amount": amount,
        "timestamp": utc_timestamp()
    }


    # --------------------------------------------------------
    # STEP 8: ADD RECORD TO DICTIONARY
    # --------------------------------------------------------

    records[record_id] = record


    # --------------------------------------------------------
    # STEP 9: SAVE RECORDS
    # --------------------------------------------------------

    # Save records persistently.
    #
    # They remain available after program restart.

    save(
        DATA,
        records
    )


    # --------------------------------------------------------
    # STEP 10: RECORD AUDIT EVENT
    # --------------------------------------------------------

    # Store:
    #
    # Actor = Role
    # Action = Submit
    # Record ID = Current record

    audit(
        AUDIT,
        role,
        "submit",
        record_id
    )


    # --------------------------------------------------------
    # STEP 11: DISPLAY RESULT
    # --------------------------------------------------------

    print(
        "Record saved successfully:",
        record_id
    )


# ============================================================
# PART 2: SEARCH A RECORD
# ============================================================

def search(role):

    # This function searches for a stored record
    # using its unique Record ID.
    #
    # CURRENT BEHAVIOR:
    #
    # 1. Check search permission.
    # 2. Take Record ID.
    # 3. Load saved records.
    # 4. Find matching record.
    # 5. Display record.
    #
    # FOR CRYPTOGRAPHIC QUESTIONS:
    #
    # Verify hash and signature before decrypting
    # sensitive fields.


    # --------------------------------------------------------
    # STEP 1: CHECK PERMISSION
    # --------------------------------------------------------

    require(role, "search")


    # --------------------------------------------------------
    # STEP 2: TAKE RECORD ID
    # --------------------------------------------------------

    record_id = input(
        "Enter Record ID to search: "
    ).strip()


    # --------------------------------------------------------
    # STEP 3: LOAD AND SEARCH RECORDS
    # --------------------------------------------------------

    # load(DATA) returns dictionary of records.
    #
    # .get(record_id) returns:
    #
    # Stored record if ID exists.
    #
    # None if ID does not exist.

    records = load(DATA)

    record = records.get(record_id)


    # --------------------------------------------------------
    # STEP 4: CHECK WHETHER RECORD EXISTS
    # --------------------------------------------------------

    if record is None:

        print("Record not found.")
        return


    # ========================================================
    # STEP 5: INSERT VERIFICATION AND DECRYPTION HERE
    # ========================================================
    #
    # EXAMPLE:
    #
    # 1. Recalculate hash.
    # 2. Compare with stored hash.
    # 3. Verify digital signature.
    # 4. Decrypt authorized fields.
    #
    # Possible functions:
    #
    # hash_bytes()
    # rsa_verify()
    # symmetric_decrypt()
    #
    # Do not display sensitive plaintext fields
    # until authorization and verification succeed.


    # --------------------------------------------------------
    # STEP 6: DISPLAY FOUND RECORD
    # --------------------------------------------------------

    # The original skeleton prints the stored record.
    #
    # For encrypted applications, print only
    # permitted fields or decrypted authorized data.

    print(
        "Found Record:",
        record_id,
        record
    )


# ============================================================
# PART 3: AGGREGATE SELECTED RECORDS
# ============================================================

def aggregate(role):

    # This function calculates a total for
    # selected records.
    #
    # CURRENT BEHAVIOR:
    #
    # Uses normal plaintext addition.
    #
    # FOR HOMOMORPHIC QUESTIONS:
    #
    # Replace this with Paillier encrypted addition.


    # --------------------------------------------------------
    # STEP 1: CHECK PERMISSION
    # --------------------------------------------------------

    require(role, "aggregate")


    # --------------------------------------------------------
    # STEP 2: TAKE RECORD IDS
    # --------------------------------------------------------

    # Example input:
    #
    # G101,G102,G103

    user_input = input(
        "Enter Record IDs separated by commas: "
    )


    # --------------------------------------------------------
    # STEP 3: CONVERT INPUT INTO LIST
    # --------------------------------------------------------

    # split(","):
    # Separates IDs by commas.
    #
    # strip():
    # Removes extra spaces.
    #
    # Example:
    #
    # "G101, G102"
    #
    # becomes:
    # ["G101", "G102"]

    selected_ids = [
        item.strip()
        for item in user_input.split(",")
        if item.strip()
    ]


    # --------------------------------------------------------
    # STEP 4: LOAD EXISTING RECORDS
    # --------------------------------------------------------

    records = load(DATA)


    # --------------------------------------------------------
    # STEP 5: VALIDATE SELECTED IDS
    # --------------------------------------------------------

    # Reject:
    #
    # 1. Empty selection.
    # 2. Duplicate IDs.
    # 3. Missing IDs.

    if (
        not selected_ids
        or len(selected_ids) != len(set(selected_ids))
        or any(item not in records for item in selected_ids)
    ):

        print("Invalid selection.")
        return


    # ========================================================
    # STEP 6: INSERT HOMOMORPHIC ADDITION HERE
    # ========================================================
    #
    # FOR PAILLIER:
    #
    # 1. Verify all selected records.
    #
    # 2. Load encrypted amounts.
    #
    # 3. Add encrypted values.
    #
    # 4. Decrypt only the final total.
    #
    # EXAMPLE:
    #
    # encrypted_amounts = [
    #     paillier_unpack(
    #         paillier_public,
    #         records[i]["amount"]
    #     )
    #     for i in selected_ids
    # ]
    #
    # encrypted_total = paillier_sum(
    #     paillier_public,
    #     encrypted_amounts
    # )
    #
    # final_total = paillier_private.decrypt(
    #     encrypted_total
    # )
    #
    # IMPORTANT:
    # The variables paillier_public and paillier_private
    # must be loaded or generated in the application.
    #
    # This code is only an insertion example.


    # --------------------------------------------------------
    # STEP 7: DEMONSTRATION PLAINTEXT TOTAL
    # --------------------------------------------------------

    # The original skeleton uses normal addition.
    #
    # This does NOT satisfy a homomorphic
    # aggregation requirement.

    total = sum(
        records[item]["amount"]
        for item in selected_ids
    )

    print(
        "DEMO PLAINTEXT TOTAL:",
        total
    )

    print(
        "Replace this function with Paillier for "
        "homomorphic encryption questions."
    )


# ============================================================
# PART 4: MAIN MENU
# ============================================================

def main():

    # This function controls the complete application.
    #
    # It displays:
    #
    # 1. Main role menu.
    # 2. Role-specific action menu.
    #
    # It continues running until the user exits.


    # --------------------------------------------------------
    # MAIN LOOP
    # --------------------------------------------------------

    while True:

        print("\n========== UNIVERSAL EXAM MENU ==========")
        print("1. Researcher")
        print("2. Reviewer")
        print("3. Finance Officer")
        print("0. Exit")

        choice = input(
            "Choose role: "
        ).strip()


        # ----------------------------------------------------
        # EXIT PROGRAM
        # ----------------------------------------------------

        if choice == "0":
            break


        # ----------------------------------------------------
        # CONVERT MENU CHOICE INTO ROLE
        # ----------------------------------------------------

        # Dictionary maps menu number to role name.

        roles = {
            "1": "researcher",
            "2": "reviewer",
            "3": "finance"
        }

        role = roles.get(choice)


        # ----------------------------------------------------
        # VALIDATE ROLE
        # ----------------------------------------------------

        if not role:

            print("Invalid role.")
            continue


        # ====================================================
        # ROLE-SPECIFIC MENU
        # ====================================================

        while True:

            print(
                f"\n========== {role.upper()} MENU =========="
            )


            # ------------------------------------------------
            # DISPLAY ACTIONS FOR SELECTED ROLE
            # ------------------------------------------------

            if role == "researcher":

                print("1. Submit Record")
                print("0. Back")

            elif role == "reviewer":

                print("1. Search Record")
                print("0. Back")

            else:

                print("1. Aggregate Records")
                print("0. Back")


            # ------------------------------------------------
            # TAKE USER ACTION
            # ------------------------------------------------

            action = input(
                "Choose action: "
            ).strip()


            # ------------------------------------------------
            # GO BACK TO MAIN MENU
            # ------------------------------------------------

            if action == "0":
                break


            # ------------------------------------------------
            # VALIDATE MENU OPTION
            # ------------------------------------------------

            if action != "1":

                print("Invalid option.")
                continue


            # ------------------------------------------------
            # CALL CORRESPONDING FUNCTION
            # ------------------------------------------------

            try:

                if role == "researcher":

                    submit(role)

                elif role == "reviewer":

                    search(role)

                else:

                    aggregate(role)


            # ------------------------------------------------
            # HANDLE COMMON ERRORS
            # ------------------------------------------------

            # ValueError:
            # Invalid input or conversion.
            #
            # KeyError:
            # Missing dictionary key.
            #
            # PermissionError:
            # User role does not have permission.

            except (
                ValueError,
                KeyError,
                PermissionError
            ) as error:

                print(
                    "Operation failed:",
                    error
                )


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    main()
