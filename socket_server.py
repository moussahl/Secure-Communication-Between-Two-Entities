import socket
from rsa import RSA
from feistel import decrypt_message

def run_server():
    print("--- SERVER STARTING ---")
    rsa = RSA(512)
    pub_key, priv_key = rsa.generate_keys()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 65432))
    server_socket.listen(1)
    
    print("[2] Status: Waiting for connection...")
    conn, addr = server_socket.accept()
    
    # Send Public Key
    conn.sendall(f"{pub_key[0]},{pub_key[1]}".encode())
    print("[3] Handshake: Sent Public Key to Client.")

    # [4] Receive using Length Header
    header = conn.recv(4)
    if not header: return
    key_size = int.from_bytes(header, 'big')
    
    enc_key_bytes = conn.recv(key_size)
    print(f"[4] Received Encrypted Session Key (RSA).")
    
    # Receive the rest (the ciphertext)
    ciphertext = conn.recv(4096)
    print(f"[5] Received Ciphertext (Feistel): {ciphertext.hex()[:50]}...")

    # [6] Decrypt Session Key
    enc_key_int = int.from_bytes(enc_key_bytes, 'big')
    session_key_int = rsa.decrypt_number(enc_key_int, priv_key)
    session_key = session_key_int.to_bytes(64, 'big')
    print(f"[6] Decrypted Session Key: {session_key.hex()[:32]}...")

    # [7] Decrypt Message and Handle Output
    try:
        final_msg = decrypt_message(ciphertext, session_key)
        # We use 'replace' to avoid crashing if there are stray bytes
        decoded_text = final_msg.decode('utf-8', errors='replace')
        print(f"\n[7] FINAL RESULT: {decoded_text}")
    except Exception as e:
        print(f"\n[!] Decryption Error: {e}")
        print("Hint: Check if the padding or key generation is consistent.")
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    run_server()