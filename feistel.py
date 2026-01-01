from hash_function import SHA256

# Initialisation globale de ton hacheur personnalisé
hasher = SHA256()

# ==========================================
# 1. CONSTANTES & CONFIG
# ==========================================
ROUNDS = 16
BLOCK_SIZE = 64   # 512 bits
MASK_256 = (1 << 256) - 1

# ==========================================
# 2. FONCTIONS DE PADDING
# ==========================================
def pad(data):
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    if padding_len > BLOCK_SIZE: return data 
    return data[:-padding_len]

# ==========================================
# 3. LOGIQUE CORE (CHANGEMENTS ICI)
# ==========================================

def F_function(right_half, subkey):
    """Utilise ton SHA256 comme boîte de substitution non-linéaire."""
    mixed = (right_half ^ subkey) & MASK_256
    
    # Appel à TON hacheur (retourne une string hex)
    h_hex = hasher.hash(mixed.to_bytes(32, 'big'))
    
    # Conversion Hex -> Int pour les calculs XOR
    return int(h_hex, 16) & MASK_256

def generate_subkeys(main_key):
    """Génère les 16 sous-clés via ton hacheur."""
    subkeys = []
    print(f"\n[KEY SCHEDULE] Génération des {ROUNDS} clés de round...")
    for i in range(ROUNDS):
        key_material = main_key + bytes([i])
        # Utilisation de ton hash
        subkey_hex = hasher.hash(key_material)
        val = int(subkey_hex, 16) & MASK_256
        subkeys.append(val)
        
        # Affichage terminal pour debug
        if i < 2 or i == ROUNDS - 1:
            print(f"  → Clé K{i:02}: {subkey_hex[:16]}...")
            
    return subkeys

def feistel_block(block_int, subkeys):
    L = (block_int >> 256) & MASK_256
    R = block_int & MASK_256

    for i in range(ROUNDS):
        temp_R = R
        R = L ^ F_function(R, subkeys[i])
        L = temp_R

    return (R << 256) | L

# ==========================================
# 4. ENCRYPT / DECRYPT (LOGS DANS LE TERMINAL)
# ==========================================

def encrypt_message(plaintext_bytes, key_bytes):
    print("\n" + "="*60)
    print("🔒 DÉBUT DU CHIFFREMENT FEISTEL (CLIENT)")
    print("="*60)
    
    subkeys = generate_subkeys(key_bytes)
    padded_msg = pad(plaintext_bytes)
    
    output = bytearray()
    for i in range(0, len(padded_msg), BLOCK_SIZE):
        block = padded_msg[i : i + BLOCK_SIZE]
        b_int = int.from_bytes(block, 'big')
        
        print(f"\n[BLOC {i//BLOCK_SIZE + 1}]")
        print(f"  Entrée : {block.hex()[:32]}...")
        
        e_int = feistel_block(b_int, subkeys)
        cipher_block = e_int.to_bytes(BLOCK_SIZE, 'big')
        
        print(f"  Sortie chiffrée : {cipher_block.hex()[:32]}...")
        output.extend(cipher_block)
        
    return bytes(output)

def decrypt_message(ciphertext_bytes, key_bytes):
    print("\n" + "="*60)
    print("🔓 DÉBUT DU DÉCHIFFREMENT FEISTEL (SERVEUR)")
    print("="*60)
    
    subkeys = generate_subkeys(key_bytes)
    subkeys_reversed = subkeys[::-1] # Inversion pour déchiffrer
    
    output = bytearray()
    for i in range(0, len(ciphertext_bytes), BLOCK_SIZE):
        block = ciphertext_bytes[i : i + BLOCK_SIZE]
        b_int = int.from_bytes(block, 'big')
        
        print(f"\n[BLOC {i//BLOCK_SIZE + 1}]")
        print(f"  Cipher reçu : {block.hex()[:32]}...")
        
        d_int = feistel_block(b_int, subkeys_reversed)
        plain_block = d_int.to_bytes(BLOCK_SIZE, 'big')
        
        print(f"  Plain déchiffré : {plain_block.hex()[:32]}...")
        output.extend(plain_block)
    
    final_data = unpad(bytes(output))
    print(f"\n✅ Message final reconstruit : {final_data.decode('utf-8', errors='ignore')}")
    return final_data