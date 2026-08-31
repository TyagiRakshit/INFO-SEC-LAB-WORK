import socket


def djb2_hash(input_string: str) -> int:
    """Computes 32-bit DJB2 hash value."""
    hash_value = 5381
    MASK_32_BIT = 0xFFFFFFFF
    for char in input_string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value &= MASK_32_BIT
    return hash_value


def start_server(host='127.0.0.1', port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow socket address reuse immediately after shutdown
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[SERVER] Listening on {host}:{port}...")

    while True:
        conn, addr = server_socket.accept()
        print(f"\n[SERVER] Connected by {addr}")

        try:
            # Receive data payload from client
            raw_data = conn.recv(1024)
            if not raw_data:
                break

            data_str = raw_data.decode('utf-8')
            print(f"[SERVER] Received payload: '{data_str}'")

            # Compute hash on received data
            computed_hash = djb2_hash(data_str)
            print(f"[SERVER] Computed Hash: {computed_hash} ({hex(computed_hash)})")

            # Send computed hash back to client as string
            conn.sendall(str(computed_hash).encode('utf-8'))
            print("[SERVER] Sent hash back to client.")

        except Exception as e:
            print(f"[SERVER] Error handling request: {e}")
        finally:
            conn.close()


if __name__ == "__main__":
    start_server()