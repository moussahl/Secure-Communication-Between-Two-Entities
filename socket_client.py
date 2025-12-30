import socket
import os
from rsa import RSA
from feistel import encrypt_message

def run_client():
    print("--- CLIENT STARTING ---")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 65432))

    # [1] Get Public Key
    pub_data = client_socket.recv(1024).decode().split(',')
    pub_key = (int(pub_data[0]), int(pub_data[1]))
    print(f"[1] Received Server Public Key (n): {str(pub_key[1])[:50]}...")

    # [2] Generate and Synchronize Session Key
    raw_bytes = os.urandom(64)
    # CRITICAL FIX: The key must be < n. We apply modulo and then 
    # use THOSE specific bytes for the Feistel encryption.
    session_key_int = int.from_bytes(raw_bytes, 'big') % pub_key[1]
    session_key = session_key_int.to_bytes(64, 'big') 
    
    print(f"[2] Synchronized 512-bit Session Key: {session_key.hex()[:32]}...")

    # [3] Encrypt Session Key with RSA
    rsa_tool = RSA(512)
    enc_key_int = rsa_tool.encrypt_number(session_key_int, pub_key)
    enc_key_bytes = enc_key_int.to_bytes((enc_key_int.bit_length() + 7) // 8, 'big')
    
    # Prepare key size header (4 bytes)
    key_size_header = len(enc_key_bytes).to_bytes(4, 'big')
    print(f"[3] Encrypted Session Key (RSA): {enc_key_bytes.hex()[:50]}...")

    # [4] Encrypt Message with Feistel
    message = b"Project 2: Hybrid Cryptosystem Test"
    print(f"[4] Original Message: {message.decode()}")
    ciphertext = encrypt_message(message, session_key)
    print(f"[5] Ciphertext (Feistel): {ciphertext.hex()[:50]}...")

    # [5] Send data with length prefixing to prevent stream mixing
    client_socket.sendall(key_size_header) 
    client_socket.sendall(enc_key_bytes)   
    client_socket.sendall(ciphertext)      
    print("[6] Data sent to server.")

    client_socket.close()

if __name__ == "__main__":
    run_client()