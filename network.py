
# ============================================================
# INFORMATION SECURITY EXAM TOOLKIT
# FILE: network.py
#
# TOPIC: TCP SOCKET PROGRAMMING AND MESSAGE FRAMING
#
# LAB 5 - NETWORK COMMUNICATION
# ============================================================
#
# AIM:
# To send and receive complete messages between
# a client and server using TCP socket programming.
#
# WHAT IS SOCKET PROGRAMMING?
#
# Socket programming allows two programs to
# communicate over a network.
#
# CLIENT:
#   Connects to the server and sends requests.
#
# SERVER:
#   Listens for connections, receives requests,
#   processes them and sends responses.
#
# WHAT IS TCP?
#
# TCP = Transmission Control Protocol
#
# TCP provides:
#
# 1. Reliable byte-stream delivery.
# 2. Ordered delivery of bytes.
# 3. Detection and retransmission of lost segments.
#
# IMPORTANT:
# TCP is a BYTE STREAM, not a message-based protocol.
#
# One recv() call may receive only PART of a message.
#
# Therefore, we use MESSAGE FRAMING.
#
# ------------------------------------------------------------
# WHAT IS MESSAGE FRAMING?
# ------------------------------------------------------------
#
# We send:
#
# [4-byte message length] + [Actual message bytes]
#
# Example:
#
# Message = "HELLO"
#
# Length = 5 bytes
#
# Send:
# 00 00 00 05 + HELLO
#
# Receiver:
#
# 1. Reads 4 bytes to find the message length.
# 2. Reads exactly that many message bytes.
#
# This prevents incomplete-message problems.
#
# ============================================================


# ============================================================
# STEP 1: IMPORT REQUIRED LIBRARIES
# ============================================================

# socket:
# Provides TCP/IP networking functions.

import socket

# struct:
# Converts Python values into binary formats.
#
# We use it to store message length as 4 bytes.

import struct

# json:
# Converts Python dictionaries into JSON strings
# and converts received JSON back into dictionaries.

import json


# ============================================================
# STEP 2: DEFINE MAXIMUM MESSAGE SIZE
# ============================================================

# Maximum allowed message size = 32 MiB.
#
# 1 MiB = 1024 * 1024 bytes.
#
# This prevents the receiver from accepting
# an arbitrarily large message.
#
# It is a simple resource limit, not complete
# protection against denial-of-service attacks.

MAX_MESSAGE = 32 * 1024 * 1024


# ============================================================
# PART 1: RECEIVE EXACT NUMBER OF BYTES
# ============================================================

def receive_exact(sock, n):

    # PARAMETERS:
    #
    # sock:
    #   Connected TCP socket.
    #
    # n:
    #   Exact number of bytes we want to receive.
    #
    # WHY IS THIS FUNCTION NEEDED?
    #
    # sock.recv(n) does NOT guarantee n bytes.
    #
    # Example:
    #
    # We request 100 bytes.
    #
    # First recv() may return 40 bytes.
    # Second recv() may return 30 bytes.
    # Third recv() may return 30 bytes.
    #
    # We must combine all received parts.


    # --------------------------------------------------------
    # STEP 1: CREATE EMPTY BYTE BUFFER
    # --------------------------------------------------------

    # bytearray() creates a mutable byte buffer.
    #
    # Unlike bytes, bytearray can be extended easily.

    result = bytearray()


    # --------------------------------------------------------
    # STEP 2: RECEIVE DATA UNTIL COMPLETE
    # --------------------------------------------------------

    # Keep receiving until we have n bytes.

    while len(result) < n:

        # Calculate how many bytes are still required.

        remaining = n - len(result)

        # Receive up to 65536 bytes at a time.
        #
        # min() selects the smaller value.
        #
        # This avoids requesting more bytes
        # than the remaining message size.

        block = sock.recv(
            min(65536, remaining)
        )


        # ----------------------------------------------------
        # CHECK FOR CLOSED CONNECTION
        # ----------------------------------------------------

        # If recv() returns b"", the peer has closed
        # its sending side.
        #
        # If we still need bytes, the message is incomplete.

        if not block:

            raise ConnectionError(
                "Peer closed connection early"
            )


        # ----------------------------------------------------
        # APPEND RECEIVED DATA
        # ----------------------------------------------------

        # extend() adds the received bytes to our buffer.

        result.extend(block)


    # --------------------------------------------------------
    # STEP 3: RETURN COMPLETE MESSAGE
    # --------------------------------------------------------

    # Convert bytearray into immutable bytes.

    return bytes(result)


# ============================================================
# PART 2: SEND A FRAMED MESSAGE
# ============================================================

def send_message(sock, data):

    # PARAMETERS:
    #
    # sock:
    #   Connected TCP socket.
    #
    # data:
    #   Message bytes to send.


    # --------------------------------------------------------
    # STEP 1: CHECK MESSAGE SIZE
    # --------------------------------------------------------

    # Reject messages larger than 32 MiB.

    if len(data) > MAX_MESSAGE:

        raise ValueError(
            "Message too large"
        )


    # --------------------------------------------------------
    # STEP 2: CONVERT MESSAGE LENGTH INTO 4 BYTES
    # --------------------------------------------------------

    # struct.pack() converts values into binary data.
    #
    # Format:
    #
    # "!I"
    #
    # ! = Network byte order (big-endian)
    # I = Unsigned 32-bit integer
    #
    # Example:
    #
    # Message length = 5
    #
    # struct.pack("!I", 5)
    #
    # Result:
    # b'\x00\x00\x00\x05'

    length_header = struct.pack(
        "!I",
        len(data)
    )


    # --------------------------------------------------------
    # STEP 3: SEND LENGTH + MESSAGE
    # --------------------------------------------------------

    # Combine:
    #
    # 4-byte header + actual message.
    #
    # sendall() attempts to send all supplied bytes
    # or raises an error.

    sock.sendall(
        length_header + data
    )


# ============================================================
# PART 3: RECEIVE A FRAMED MESSAGE
# ============================================================

def receive_message(sock):

    # --------------------------------------------------------
    # STEP 1: RECEIVE 4-BYTE LENGTH HEADER
    # --------------------------------------------------------

    # Read exactly four bytes.
    #
    # These bytes contain the message size.

    header = receive_exact(sock, 4)


    # --------------------------------------------------------
    # STEP 2: DECODE MESSAGE LENGTH
    # --------------------------------------------------------

    # struct.unpack() converts binary data
    # back into Python values.
    #
    # "!I" means a big-endian unsigned integer.
    #
    # unpack() returns a tuple.
    #
    # [0] extracts the first value.

    size = struct.unpack(
        "!I",
        header
    )[0]


    # --------------------------------------------------------
    # STEP 3: VALIDATE MESSAGE SIZE
    # --------------------------------------------------------

    if size > MAX_MESSAGE:

        raise ValueError(
            "Message too large"
        )


    # --------------------------------------------------------
    # STEP 4: RECEIVE COMPLETE MESSAGE
    # --------------------------------------------------------

    # Now we know the exact message length.
    #
    # Read exactly that many bytes.

    return receive_exact(
        sock,
        size
    )


# ============================================================
# PART 4: SEND JSON DATA
# ============================================================
#
# WHAT IS JSON?
#
# JSON = JavaScript Object Notation
#
# It is a text format used to store and transfer
# structured data.
#
# Example Python dictionary:
#
# {
#     "name": "Alice",
#     "message": "Hello"
# }
#
# JSON is useful for transmitting:
#
# 1. Encrypted message envelopes.
# 2. Hashes and digital signatures.
# 3. Grant records.
# 4. Voting records.
# 5. File metadata.
#
# IMPORTANT:
# JSON does not directly support Python bytes.
# Convert bytes to Base64 before sending.
#
# ============================================================


def send_json(sock, obj):

    # Convert Python object into a JSON string.
    #
    # json.dumps():
    # Python object -> JSON string

    json_text = json.dumps(obj)

    # Convert JSON string into UTF-8 bytes.

    data = json_text.encode("utf-8")

    # Send using our framed-message function.

    send_message(sock, data)


# ============================================================
# PART 5: RECEIVE JSON DATA
# ============================================================

def receive_json(sock):

    # Receive complete framed message.

    data = receive_message(sock)

    # Convert bytes into a JSON string.

    json_text = data.decode("utf-8")

    # Convert JSON string into Python object.
    #
    # json.loads():
    # JSON string -> Python object

    return json.loads(json_text)


# ============================================================
# PART 6: TCP SERVER
# ============================================================
#
# SERVER FLOW:
#
# 1. Create socket.
# 2. Bind IP and port.
# 3. Listen for connections.
# 4. Accept client.
# 5. Receive JSON request.
# 6. Process request using handler().
# 7. Send JSON response.
# 8. Close client connection.
# 9. Wait for next client.
#
# ============================================================


def server_once(
    handler,
    host="127.0.0.1",
    port=65432
):

    # PARAMETERS:
    #
    # handler:
    #   A function that processes client requests.
    #
    # host:
    #   IP address where the server listens.
    #
    # 127.0.0.1 = Localhost (same computer).
    #
    # port:
    #   Port number used for communication.


    # --------------------------------------------------------
    # STEP 1: CREATE TCP SERVER SOCKET
    # --------------------------------------------------------

    # AF_INET:
    #   Use IPv4.
    #
    # SOCK_STREAM:
    #   Use TCP.

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as server_socket:


        # ----------------------------------------------------
        # STEP 2: ALLOW ADDRESS REUSE
        # ----------------------------------------------------

        # SO_REUSEADDR helps reuse a local address
        # when restarting a server after shutdown.
        #
        # It does not normally permit two active
        # servers on the same IP and port.

        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )


        # ----------------------------------------------------
        # STEP 3: BIND SERVER
        # ----------------------------------------------------

        # Associate socket with IP address and port.

        server_socket.bind(
            (host, port)
        )


        # ----------------------------------------------------
        # STEP 4: LISTEN FOR CLIENTS
        # ----------------------------------------------------

        # 5 is the requested backlog for pending
        # connection attempts.

        server_socket.listen(5)

        print(
            "Listening on",
            host,
            port
        )


        # ----------------------------------------------------
        # STEP 5: KEEP SERVER RUNNING
        # ----------------------------------------------------

        # The original function name is server_once(),
        # but it actually handles multiple connections
        # sequentially in an infinite loop.

        while True:


            # ------------------------------------------------
            # ACCEPT CLIENT CONNECTION
            # ------------------------------------------------

            # accept() waits for a client.
            #
            # conn = Connected client socket.
            # addr = Client address information.

            conn, addr = server_socket.accept()


            # ------------------------------------------------
            # HANDLE CLIENT
            # ------------------------------------------------

            # with conn:
            # Automatically closes the client socket
            # when the block finishes.

            with conn:

                try:

                    # Receive JSON request from client.

                    request = receive_json(conn)

                    # Pass request to handler function.
                    #
                    # The handler contains application logic.
                    #
                    # Example:
                    #
                    # - Calculate SHA-256 hash.
                    # - Verify digital signature.
                    # - Decrypt encrypted message.
                    # - Search records.

                    response = handler(request)

                    # Send handler result back to client.

                    send_json(
                        conn,
                        response
                    )

                except Exception as error:

                    # If processing fails, send an
                    # error response to the client.
                    #
                    # NOTE:
                    # Sending an error can itself fail
                    # if the connection has closed.

                    send_json(
                        conn,
                        {
                            "error": str(error)
                        }
                    )


# ============================================================
# PART 7: TCP CLIENT
# ============================================================
#
# CLIENT FLOW:
#
# 1. Connect to server.
# 2. Convert request into JSON.
# 3. Send framed JSON request.
# 4. Receive framed JSON response.
# 5. Return response to caller.
#
# ============================================================


def client_request(
    obj,
    host="127.0.0.1",
    port=65432
):

    # --------------------------------------------------------
    # STEP 1: CONNECT TO SERVER
    # --------------------------------------------------------

    # socket.create_connection() creates and connects
    # a TCP socket.
    #
    # timeout=10:
    # The connection attempt has a 10-second timeout.
    #
    # The socket also retains this timeout for
    # subsequent operations unless changed.

    with socket.create_connection(
        (host, port),
        timeout=10
    ) as client_socket:


        # ----------------------------------------------------
        # STEP 2: SEND JSON REQUEST
        # --------------------------------------------------------

        send_json(
            client_socket,
            obj
        )


        # ----------------------------------------------------
        # STEP 3: RECEIVE JSON RESPONSE
        # --------------------------------------------------------

        response = receive_json(
            client_socket
        )

        return response
