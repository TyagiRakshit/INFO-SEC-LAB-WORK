import hashlib
import random
import socket
from Crypto.Util import number


def run_dh_server(host="127.0.0.1", port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"[SERVER] Listening on {host}:{port}...")
    conn, addr = server_socket.accept()
    print(f"[SERVER] Connected to client at {addr}")

    try:
        #Generate dynamic parameters (p, g)
        p = number.getPrime(512)
        g = random.randint(2, p - 2)

        #Generate Server's Private (a) and Public Key (A = g^a mod p)
        a_private = random.randint(2, p - 2)
        a_public = pow(g, a_private, p)

        print("\n[SERVER] Step 1: Generated domain parameters and public key.")
        print(f"  Prime (p): {p}")
        print(f"  Generator (g): {g}")
        print(f"  Server Public Key (A): {a_public}")

        # Send (p, g, A) to client delimited by '|'
        param_payload = f"{p}|{g}|{a_public}"
        conn.sendall(param_payload.encode("utf-8"))
        print("[SERVER] Sent parameters and Public Key A to Client.")

        #Receive Client's Public Key (B)
        b_public_data = conn.recv(1024).decode("utf-8")
        b_public = int(b_public_data)
        print(f"\n[SERVER] Step 2: Received Client's Public Key B: {b_public}")

        #Compute Shared Secret (S = B^a mod p)
        server_secret = pow(b_public, a_private, p)
        server_aes_key = hashlib.sha256(str(server_secret).encode()).hexdigest()
        print(f"[SERVER] Step 3: Computed Shared Secret: {server_secret}")
        print(f"[SERVER] Derived Symmetric Key (SHA-256): {server_aes_key}")

        # Send derived key back to client for integrity verification
        conn.sendall(server_aes_key.encode("utf-8"))

    finally:
        conn.close()
        server_socket.close()


if __name__ == "__main__":
    run_dh_server()