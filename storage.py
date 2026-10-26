
# ============================================================
# INFORMATION SECURITY EXAM TOOLKIT
# FILE: storage.py
#
# TOPIC:
# 1. JSON File Storage
# 2. Persistent Records
# 3. Unique Record IDs
# 4. Audit Logging
#
# ============================================================
#
# AIM:
#
# To create reusable functions for storing and retrieving
# data from JSON files.
#
# WHAT IS PERSISTENT STORAGE?
#
# Normally, Python variables exist only while a program
# is running.
#
# Example:
#
# records = {"G101": "Research Grant"}
#
# If the program closes, this variable disappears.
#
# To preserve the data, we save it into a file.
#
# When the program starts again, we load the saved file.
#
# This is called PERSISTENT STORAGE.
#
# ------------------------------------------------------------
# WHAT IS JSON?
# ------------------------------------------------------------
#
# JSON = JavaScript Object Notation
#
# It stores structured data using key-value pairs,
# lists, strings, numbers and other JSON types.
#
# Example:
#
# {
#     "G101": {
#         "description": "Research Equipment",
#         "amount": 15000
#     }
# }
#
# Python dictionaries can be converted into JSON files.
#
# ------------------------------------------------------------
# WHAT IS AUDIT LOGGING?
# ------------------------------------------------------------
#
# Audit logging means recording important activities.
#
# Example:
#
# Researcher submitted Grant G101.
# Reviewer verified Grant G101.
# Finance Officer aggregated selected grants.
#
# Each audit entry records:
#
# - Timestamp
# - Actor
# - Action
# - Record ID
# - Outcome
#
# IMPORTANT:
#
# This module does NOT encrypt stored data.
# It also does not authenticate users or enforce roles.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT REQUIRED LIBRARIES
# ============================================================

# json:
# Converts Python objects into JSON and vice versa.

import json

# os:
# Provides operating system functions.
#
# We use it for file replacement, synchronization
# and temporary-file cleanup.

import os

# tempfile:
# Creates temporary files safely.
#
# We use temporary files to avoid directly overwriting
# the original JSON file while saving.

import tempfile

# Path:
# Makes working with file paths easier.

from pathlib import Path

# datetime:
# Provides current date and time.
#
# timezone:
# Allows us to record timestamps in UTC.

from datetime import datetime, timezone


# ============================================================
# PART 1: LOAD JSON DATA
# ============================================================

def load(path, default=None):

    # PARAMETERS:
    #
    # path:
    #   Location of the JSON file.
    #
    # default:
    #   Value to return if the file does not exist.
    #
    # Example:
    #
    # load("records.json")
    #
    # If the file exists:
    # Return its stored data.
    #
    # If the file does not exist:
    # Return an empty dictionary by default.


    # --------------------------------------------------------
    # STEP 1: CONVERT PATH INTO PATH OBJECT
    # --------------------------------------------------------

    # Path() makes file handling easier.
    #
    # Example:
    #
    # "data/records.json"
    #
    # becomes a Path object representing that location.

    file_path = Path(path)


    # --------------------------------------------------------
    # STEP 2: CHECK WHETHER FILE EXISTS
    # --------------------------------------------------------

    if file_path.exists():

        # Read the complete file as UTF-8 text.
        #
        # Example JSON text:
        #
        # {"G101": {"amount": 15000}}

        json_text = file_path.read_text(
            encoding="utf-8"
        )


        # ----------------------------------------------------
        # STEP 3: CONVERT JSON INTO PYTHON OBJECT
        # ----------------------------------------------------

        # json.loads() converts JSON text into Python data.
        #
        # Example:
        #
        # JSON object -> Python dictionary
        #
        # JSON array -> Python list

        return json.loads(json_text)


    # --------------------------------------------------------
    # STEP 4: RETURN DEFAULT IF FILE IS MISSING
    # --------------------------------------------------------

    # If default is None, return an empty dictionary.
    #
    # Otherwise, return the supplied default.
    #
    # Example:
    #
    # load("records.json", [])
    #
    # Returns [] when the file does not exist.

    if default is None:
        return {}

    return default


# ============================================================
# PART 2: SAVE JSON DATA
# ============================================================

def save(path, data):

    # PARAMETERS:
    #
    # path:
    #   File where data should be saved.
    #
    # data:
    #   Python dictionary, list or other JSON-compatible
    #   object that we want to store.
    #
    # WHY USE A TEMPORARY FILE?
    #
    # Directly overwriting records.json can be risky.
    #
    # If the program crashes halfway through writing,
    # the original file may become incomplete.
    #
    # Therefore:
    #
    # 1. Write data into a temporary file.
    # 2. Flush and synchronize the temporary file.
    # 3. Replace the original file.
    #
    # This is safer than writing directly to the
    # original file.


    # --------------------------------------------------------
    # STEP 1: CONVERT PATH INTO PATH OBJECT
    # --------------------------------------------------------

    file_path = Path(path)


    # --------------------------------------------------------
    # STEP 2: CREATE PARENT DIRECTORY
    # --------------------------------------------------------

    # Example:
    #
    # path = "data/grants/records.json"
    #
    # The program creates the folders if missing.
    #
    # parents=True:
    # Creates all required parent directories.
    #
    # exist_ok=True:
    # Does not raise an error if they already exist.

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )


    # --------------------------------------------------------
    # STEP 3: CREATE TEMPORARY FILE
    # --------------------------------------------------------

    # tempfile.mkstemp() creates a temporary file.
    #
    # It returns:
    #
    # fd:
    #   File descriptor identifying the open file.
    #
    # temp_path:
    #   Path of the temporary file.
    #
    # dir:
    #   Store temporary file in the same directory
    #   as the destination file.
    #
    # prefix:
    #   Temporary filename starts with ".saving-".

    fd, temp_path = tempfile.mkstemp(
        dir=str(file_path.parent),
        prefix=".saving-"
    )


    # --------------------------------------------------------
    # STEP 4: WRITE DATA TO TEMPORARY FILE
    # --------------------------------------------------------

    try:

        # os.fdopen() converts a file descriptor
        # into a Python file object.
        #
        # "w" means write mode.

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as file:


            # ------------------------------------------------
            # CONVERT PYTHON DATA INTO JSON
            # ------------------------------------------------

            # json.dump() writes Python data as JSON.
            #
            # indent=2 makes the JSON readable.
            #
            # Example:
            #
            # {
            #   "G101": {
            #     "amount": 15000
            #   }
            # }

            json.dump(
                data,
                file,
                indent=2
            )


            # ------------------------------------------------
            # FLUSH PYTHON BUFFER
            # ------------------------------------------------

            # flush() moves buffered data from Python's
            # file object to the operating system.

            file.flush()


            # ------------------------------------------------
            # SYNCHRONIZE FILE DATA
            # ------------------------------------------------

            # os.fsync() asks the operating system
            # to synchronize file contents to storage.
            #
            # This helps reduce the chance of data loss
            # if the system crashes.

            os.fsync(
                file.fileno()
            )


        # ----------------------------------------------------
        # STEP 5: REPLACE ORIGINAL FILE
        # ----------------------------------------------------

        # os.replace() replaces the destination file
        # with the temporary file.
        #
        # Because the temporary file is created in
        # the same directory, this is normally an
        # atomic replacement operation on local
        # filesystems that support it.
        #
        # It does not provide multi-user locking or
        # guarantee complete crash durability.

        os.replace(
            temp_path,
            file_path
        )


    # --------------------------------------------------------
    # STEP 6: CLEAN UP TEMPORARY FILE
    # --------------------------------------------------------

    finally:

        # If the temporary file still exists,
        # remove it.
        #
        # This can happen if an error occurs
        # before os.replace() succeeds.

        if os.path.exists(temp_path):

            os.unlink(temp_path)


# ============================================================
# PART 3: ADD A NEW RECORD
# ============================================================

def add_record(path, record_id, record):

    # PARAMETERS:
    #
    # path:
    #   JSON file containing existing records.
    #
    # record_id:
    #   Unique identifier for the new record.
    #
    # record:
    #   Data to store under that ID.
    #
    # EXAMPLE:
    #
    # record_id = "G101"
    #
    # record = {
    #     "description": "Equipment",
    #     "amount": 15000
    # }
    #
    # This function prevents duplicate IDs.


    # --------------------------------------------------------
    # STEP 1: LOAD EXISTING RECORDS
    # --------------------------------------------------------

    # If the file does not exist, load() returns {}.

    records = load(path)


    # --------------------------------------------------------
    # STEP 2: VALIDATE RECORD ID
    # --------------------------------------------------------

    # Reject:
    #
    # 1. Empty IDs
    # 2. Duplicate IDs
    #
    # Example:
    #
    # If G101 already exists, we cannot add another
    # record using G101.

    if not record_id or record_id in records:

        raise ValueError(
            "Empty or duplicate ID"
        )


    # --------------------------------------------------------
    # STEP 3: ADD RECORD TO DICTIONARY
    # --------------------------------------------------------

    # Example:
    #
    # records["G101"] = {
    #     "description": "Equipment",
    #     "amount": 15000
    # }

    records[record_id] = record


    # --------------------------------------------------------
    # STEP 4: SAVE UPDATED RECORDS
    # --------------------------------------------------------

    # Save all records back to JSON.
    #
    # The new record will remain available
    # after the program restarts.

    save(
        path,
        records
    )


# ============================================================
# PART 4: AUDIT LOGGING
# ============================================================

def audit(
    path,
    actor,
    action,
    record_id="",
    outcome="ok"
):

    # PARAMETERS:
    #
    # path:
    #   Audit log JSON file.
    #
    # actor:
    #   User or role performing the action.
    #
    # action:
    #   Operation being performed.
    #
    # record_id:
    #   Optional ID of the affected record.
    #
    # outcome:
    #   Result of the operation.
    #
    # Example:
    #
    # actor = "reviewer"
    # action = "verify"
    # record_id = "G101"
    # outcome = "success"


    # --------------------------------------------------------
    # STEP 1: LOAD EXISTING AUDIT LOG
    # --------------------------------------------------------

    # Use [] as default because an audit log
    # contains a list of events.

    log = load(
        path,
        []
    )


    # --------------------------------------------------------
    # STEP 2: CREATE TIMESTAMP
    # --------------------------------------------------------

    # datetime.now(timezone.utc):
    # Gets current UTC date and time.
    #
    # isoformat():
    # Converts datetime into ISO 8601 format.
    #
    # Example:
    #
    # 2026-10-26T10:30:00+00:00
    #
    # UTC avoids ambiguity between time zones.

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()


    # --------------------------------------------------------
    # STEP 3: CREATE AUDIT ENTRY
    # --------------------------------------------------------

    # Each entry is a dictionary containing
    # information about the activity.

    entry = {
        "time": timestamp,
        "actor": actor,
        "action": action,
        "record_id": record_id,
        "outcome": outcome
    }


    # --------------------------------------------------------
    # STEP 4: ADD ENTRY TO LOG
    # --------------------------------------------------------

    # append() adds the new entry at the end of the list.

    log.append(entry)


    # --------------------------------------------------------
    # STEP 5: SAVE UPDATED AUDIT LOG
    # --------------------------------------------------------

    save(
        path,
        log
    )
