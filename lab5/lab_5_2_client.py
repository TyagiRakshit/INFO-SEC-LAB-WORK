import socket


def djb2_hash(input_string: str) -> int:
    """Computes 32-bit DJB2 hash value."""
    hash_value = 5381
    MASK_32_BIT = 0xFFFFFFFF
    for char in input_string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value &= MASK_32_BIT
    return hash_value


def send_and_verify(message: str, simulate_tampering: bool = False, host='127.0.0.1', port=65432):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    print(f"\n--------------------------------------------------")
    print(f"[CLIENT] Original Message: '{message}'")

    # Calculate local expected hash BEFORE transmission
    local_expected_hash = djb2_hash(message)
    print(f"[CLIENT] Local Expected Hash: {local_expected_hash}")

    # Prepare message payload to send
    payload_to_send = message
    if simulate_tampering:
        # Simulate data corruption in transit (e.g., bit flip / unauthorized edit)
        payload_to_send += " [TAMPERED]"
        print(f"[NETWORK CORRUPTION SIMULATED] Message corrupted in transit to: '{payload_to_send}'")

    # Send payload over network socket
    client_socket.sendall(payload_to_send.encode('utf-8'))

    # Receive server's hash response
    server_hash_bytes = client_socket.recv(1024)
    server_computed_hash = int(server_hash_bytes.decode('utf-8'))
    print(f"[CLIENT] Received Hash from Server: {server_computed_hash}")

    # VERIFICATION STEP
    if local_expected_hash == server_computed_hash:
        print("[CLIENT VERIFICATION] SUCCESS: Data integrity intact! Hash values match.")
    else:
        print("[CLIENT VERIFICATION] FAILED: Data corruption or tampering detected!")
        print(f"                       Expected: {local_expected_hash}")
        print(f"                       Received: {server_computed_hash}")

    client_socket.close()


if __name__ == "__main__":
    original_data = input("Enter message to send over network: ")
    if not original_data:
        original_data = "Transfer $1000 to Account #4829"

    # Test Case 1: Normal execution (No tampering)
    print("\n--- TEST CASE 1: Normal Transmission ---")
    send_and_verify(original_data, simulate_tampering=False)

    # Test Case 2: Data Tampering execution
    print("\n--- TEST CASE 2: Corrupted/Tampered Transmission ---")
    send_and_verify(original_data, simulate_tampering=True)