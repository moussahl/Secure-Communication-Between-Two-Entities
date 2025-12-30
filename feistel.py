import hashlib

# ==========================================
# 1. CONSTANTS & CONFIG
# ==========================================
ROUNDS = 16
BLOCK_SIZE = 64   # 512 bits
MASK_256 = (1 << 256) - 1

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def pad(data):
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    if padding_len > BLOCK_SIZE: return data # Safety check
    return data[:-padding_len]

# ==========================================
# 3. FIXED CORE LOGIC
# ==========================================

def F_function(right_half, subkey):
    """
    Improved Round Function for high diffusion (Avalanche Effect).
    """
    # 1. XOR with subkey
    mixed = (right_half ^ subkey) & MASK_256
    
    # 2. Use a SHA-256 hash as a non-linear S-Box. 
    # This is a very common technique in custom ciphers to ensure 
    # that every bit depends on every other bit.
    h = hashlib.sha256(mixed.to_bytes(32, 'big')).digest()
    return int.from_bytes(h, 'big') & MASK_256

def generate_subkeys(main_key):
    """
    Strong Key Schedule: Generates 16 unique 256-bit subkeys.
    If even 1 bit of main_key changes, all subkeys change completely.
    """
    subkeys = []
    for i in range(ROUNDS):
        # Use a hash of the key + round index to get the subkey
        key_material = main_key + bytes([i])
        subkey_hash = hashlib.sha256(key_material).digest()
        subkeys.append(int.from_bytes(subkey_hash, 'big'))
    return subkeys

def feistel_block(block_int, subkeys):
    # Split 512-bit block into two 256-bit halves
    L = (block_int >> 256) & MASK_256
    R = block_int & MASK_256

    for i in range(ROUNDS):
        temp_R = R
        # L XOR F(R, K)
        R = L ^ F_function(R, subkeys[i])
        L = temp_R

    # Final Swap
    return (R << 256) | L

# ==========================================
# 4. ENCRYPT / DECRYPT
# ==========================================

def encrypt_message(plaintext_bytes, key_bytes):
    subkeys = generate_subkeys(key_bytes)
    padded_msg = pad(plaintext_bytes)
    
    output = bytearray()
    for i in range(0, len(padded_msg), BLOCK_SIZE):
        block = padded_msg[i : i + BLOCK_SIZE]
        b_int = int.from_bytes(block, 'big')
        e_int = feistel_block(b_int, subkeys)
        output.extend(e_int.to_bytes(BLOCK_SIZE, 'big'))
    return bytes(output)

def decrypt_message(ciphertext_bytes, key_bytes):
    subkeys = generate_subkeys(key_bytes)
    subkeys_reversed = subkeys[::-1] # Reverse keys for decryption
    
    output = bytearray()
    for i in range(0, len(ciphertext_bytes), BLOCK_SIZE):
        block = ciphertext_bytes[i : i + BLOCK_SIZE]
        b_int = int.from_bytes(block, 'big')
        d_int = feistel_block(b_int, subkeys_reversed)
        output.extend(d_int.to_bytes(BLOCK_SIZE, 'big'))
    
    return unpad(bytes(output))