import hashlib
import random
import socket


def run_dh_client(host="127.0.0.1", port=65432):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"[CLIENT] Connected to Server at {host}:{port}")

    try:
        #Receive (p, g, A) from Server
        raw_payload = client_socket.recv(4096).decode("utf-8")
        p_str, g_str, a_pub_str = raw_payload.split("|")

        p = int(p_str)
        g = int(g_str)
        a_public = int(a_pub_str)

        print("\n[CLIENT] Received parameters from Server.")
        print(f"  Prime (p): {p}")
        print(f"  Generator (g): {g}")
        print(f"  Server Public Key (A): {a_public}")

        #Generate Client's Private (b) and Public Key (B = g^b mod p)
        b_private = random.randint(2, p - 2)
        b_public = pow(g, b_private, p)

        print(f"\n[CLIENT] Generated Public Key B: {b_public}")

        # Send Public Key B to Server
        client_socket.sendall(str(b_public).encode("utf-8"))
        print("[CLIENT] Sent Public Key B to Server.")

        #Compute Shared Secret (S = A^b mod p)
        client_secret = pow(a_public, b_private, p)
        client_aes_key = hashlib.sha256(str(client_secret).encode()).hexdigest()
        print(f"[CLIENT] Computed Shared Secret: {client_secret}")
        print(f"[CLIENT] Derived Symmetric Key (SHA-256): {client_aes_key}")

        #Receive Server's key verification tag
        server_key_tag = client_socket.recv(1024).decode("utf-8")

        #Verification Check
        print("\nVERIFICATION RESULT")
        if client_aes_key == server_key_tag:
            print("[SUCCESS] Shared secrets MATCH! Secure channel established.")
        else:
            print("[FAILED] Shared secrets DO NOT MATCH! Possible network tampering.")

    finally:
        client_socket.close()


if __name__ == "__main__":
    run_dh_client()