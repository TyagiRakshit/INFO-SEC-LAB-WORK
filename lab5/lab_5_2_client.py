
# ============================================================
# LAB 5 - CODE 2: CLIENT SIDE
# HASHING USING SOCKET PROGRAMMING
# ============================================================
#
# AIM:
# To send a message to the server and verify its integrity
# by comparing the local hash with the server's hash.
#
# CLIENT FLOW:
#
# 1. Take a message from the user.
# 2. Calculate the DJB2 hash locally.
# 3. Create a TCP socket.
# 4. Connect to the server.
# 5. Send the message to the server.
# 6. Receive the hash calculated by the server.
# 7. Compare both hash values.
# 8. Display whether the integrity check passed.
#
# ============================================================


# Import socket library
import socket


# ============================================================
# STEP 1: DJB2 HASH FUNCTION
# ============================================================

# Same function used in Code 1 and the server program

def djb2_hash(message):

    # Initial hash value
    hash_value = 5381

    # Process every character
    for char in message:

        # Convert character into its numeric value
        ascii_value = ord(char)

        # New hash = Old hash * 33 + character value
        hash_value = ((hash_value << 5) + hash_value) + ascii_value

        # Keep only the lowest 32 bits
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


# ============================================================
# STEP 2: CREATE THE CLIENT
# ============================================================

def start_client():

    # Server IP address
    host = "127.0.0.1"

    # Must be the SAME port as the server
    port = 65432

    # Take message from the user
    message = input("Enter a message: ")


    # ========================================================
    # STEP 3: CALCULATE LOCAL HASH
    # ========================================================

    # Calculate hash before sending the message
    #
    # This hash will be compared with the server's hash.

    local_hash = djb2_hash(message)

    print("Local Hash:", local_hash)


    # ========================================================
    # STEP 4: CREATE SOCKET AND CONNECT TO SERVER
    # ========================================================

    # Create an IPv4 TCP socket
    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    try:

        # Connect to the server using its IP and port
        client_socket.connect((host, port))

        print("Connected to server.")


        # ====================================================
        # STEP 5: SEND MESSAGE
        # ====================================================

        # Convert message into bytes using encode()
        #
        # Example:
        # "ABC" becomes b'ABC'
        #
        # sendall() sends the message to the server.

        client_socket.sendall(
            message.encode("utf-8")
        )

        print("Message sent to server.")


        # ====================================================
        # STEP 6: RECEIVE HASH FROM SERVER
        # ====================================================

        # Receive up to 1024 bytes from server
        received_hash = client_socket.recv(1024)

        # Convert received bytes into a string
        #
        # Example:
        # b'193450027' becomes '193450027'

        received_hash = received_hash.decode("utf-8")

        # Convert string into integer using int()
        #
        # Example:
        # '193450027' becomes 193450027

        server_hash = int(received_hash)

        print("Server Hash:", server_hash)


        # ====================================================
        # STEP 7: VERIFY DATA INTEGRITY
        # ====================================================

        # Compare the locally calculated hash
        # with the hash received from the server.

        if local_hash == server_hash:

            # Both hashes are equal
            print("Integrity Verified!")
            print("Data was received without a detected change.")

        else:

            # Hashes are different
            print("Integrity Check Failed!")
            print("Data may have been modified.")


    except Exception as e:

        # Display error if connection or communication fails
        print("Error:", e)

    finally:

        # Close the client socket after communication
        client_socket.close()


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":
    start_client()
