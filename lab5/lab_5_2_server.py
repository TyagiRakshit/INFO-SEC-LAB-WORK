
# ============================================================
# LAB 5 - CODE 2: SERVER SIDE
# HASHING USING SOCKET PROGRAMMING
# ============================================================
#
# AIM:
# To receive a message from the client, calculate its
# DJB2 hash, and send the hash back to the client.
#
# SERVER FLOW:
#
# 1. Create a TCP socket.
# 2. Bind the socket to an IP address and port.
# 3. Listen for client connections.
# 4. Accept a client connection.
# 5. Receive the client's message.
# 6. Calculate the DJB2 hash of the message.
# 7. Send the calculated hash back to the client.
# 8. Close the client connection.
#
# ============================================================


# Import socket library for network communication
import socket


# ============================================================
# STEP 1: DJB2 HASH FUNCTION
# ============================================================

# This is the SAME hashing function from Code 1.

def djb2_hash(message):

    # Initial value used by DJB2
    hash_value = 5381

    # Process each character of the message
    for char in message:

        # Convert character into its numeric value
        ascii_value = ord(char)

        # Multiply old hash by 33 and add character value
        #
        # (hash_value << 5) means hash_value * 32
        # Adding hash_value makes it hash_value * 33

        hash_value = ((hash_value << 5) + hash_value) + ascii_value

        # Keep the hash within the unsigned 32-bit range
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


# ============================================================
# STEP 2: CREATE THE SERVER
# ============================================================

def start_server():

    # IP address of our computer (localhost)
    host = "127.0.0.1"

    # Port number used for communication
    port = 65432

    # Create a TCP socket
    #
    # AF_INET     = Use IPv4 addresses
    # SOCK_STREAM = Use TCP protocol

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # Allow the server to reuse its address after restarting
    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    # Bind the server to its IP address and port
    server_socket.bind((host, port))

    # Start listening for client connections
    #
    # 1 = requested backlog of pending connections
    server_socket.listen(1)

    print("Server is waiting for a client...")


    # ========================================================
    # STEP 3: ACCEPT AND HANDLE CLIENT CONNECTIONS
    # ========================================================

    # Keep the server running for multiple clients
    while True:

        # Wait until a client connects
        #
        # conn = socket used to communicate with the client
        # addr = address of the connected client

        conn, addr = server_socket.accept()

        print("\nClient connected:", addr)

        try:

            # Receive up to 1024 bytes from the client
            #
            # recv() returns bytes, not a normal string

            received_data = conn.recv(1024)

            # Check if the client sent any data
            if not received_data:
                print("No data received.")
                continue

            # Convert bytes into a normal Python string
            #
            # Example:
            # b'ABC' becomes 'ABC'

            message = received_data.decode("utf-8")

            print("Received message:", message)


            # =================================================
            # STEP 4: CALCULATE HASH
            # =================================================

            # Calculate the DJB2 hash of the received message
            hash_value = djb2_hash(message)

            print("Calculated Hash:", hash_value)


            # =================================================
            # STEP 5: SEND HASH BACK TO CLIENT
            # =================================================

            # The hash is an integer.
            #
            # First convert integer into string using str().
            # Then convert string into bytes using encode().
            #
            # sendall() sends all supplied bytes unless
            # a network error occurs.

            conn.sendall(
                str(hash_value).encode("utf-8")
            )

            print("Hash sent to client.")

        except Exception as e:

            # Display an error if communication fails
            print("Error:", e)

        finally:

            # Close the connection with this client
            #
            # The main server socket remains open
            # and can accept another client.

            conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================

# Run the server when this file is executed directly

if __name__ == "__main__":
    start_server()
