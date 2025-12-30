import utils


class RSA:
    
    def __init__(self, key_size=512):
      
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    def generate_keys(self):
       
        print(f"Generating {self.key_size}-bit RSA keys...")
        
        # Step 1: Generate two distinct prime numbers
        print("  → Generating prime p...")
        p = utils.generate_prime(self.key_size // 2)
        
        print("  → Generating prime q...")
        q = utils.generate_prime(self.key_size // 2)
        
        # Ensure p and q are different
        while p == q:
            q = utils.generate_prime(self.key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        
        # Ensure gcd(e, φ(n)) = 1 (e and φ(n) must be coprime)
        while utils.gcd(e, phi) != 1:
            e += 2  # Try next odd number
        d = utils.mod_inverse(e, phi)
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        print(f"  ✓ Keys generated successfully")
        print(f"    Public key:  (e={e}, n={n})")
        print(f"    Private key: (d={d}, n={n})")
        
        return self.public_key, self.private_key
    
    def encrypt(self, message, public_key):
        e, n = public_key
        message_bytes = message.encode('utf-8')
        m = int.from_bytes(message_bytes, byteorder='big')
        
        # Check if message is too large for this key
        if m >= n:
            raise ValueError(f"Message too large for key size. "
                           f"Message value: {m}, Modulus n: {n}")
        c = pow(m, e, n)
        
        return c
    
    def decrypt(self, ciphertext, private_key):
        d, n = private_key
        
        # RSA decryption: m = c^d mod n
        m = pow(ciphertext, d, n)
        
        # Convert integer back to string
        # Calculate how many bytes we need
        byte_length = (m.bit_length() + 7) // 8
        
        # Convert to bytes then decode to string
        message_bytes = m.to_bytes(byte_length, byteorder='big')
        message = message_bytes.decode('utf-8')
        
        return message
    
    def get_public_key(self):
        """Get the public key"""
        if self.public_key is None:
            raise ValueError("Keys not generated yet. Call generate_keys() first.")
        return self.public_key
    
    def get_private_key(self):
        """Get the private key"""
        if self.private_key is None:
            raise ValueError("Keys not generated yet. Call generate_keys() first.")
        return self.private_key
    
    def encrypt_number(self, number, public_key):
        e, n = public_key
        
        if number >= n:
            raise ValueError(f"Number too large for key size. Number: {number}, Modulus: {n}")
        
        return pow(number, e, n)
    
    def decrypt_number(self, ciphertext, private_key):
        d, n = private_key
        return pow(ciphertext, d, n)


def demonstrate_rsa():
    """Demonstrate RSA encryption/decryption"""
    print("\n" + "="*70)
    print("RSA ALGORITHM DEMONSTRATION")
    print("="*70 + "\n")
    
    # Create RSA instance with 512-bit keys (fast for demo)
    rsa = RSA(key_size=512)
    
    # Generate keys
    print("STEP 1: Key Generation")
    print("-" * 70)
    public_key, private_key = rsa.generate_keys()
    print()
    
    # Test with a message
    print("STEP 2: Message Encryption")
    print("-" * 70)
    message = "Hello RSA! This is a secret message."
    print(f"Original message: '{message}'")
    print(f"Message length: {len(message)} characters")
    
    encrypted = rsa.encrypt(message, public_key)
    print(f"\nEncrypted ciphertext (integer): {encrypted}")
    print(f"Ciphertext size: {encrypted.bit_length()} bits")
    print()
    
    # Decrypt the message
    print("STEP 3: Message Decryption")
    print("-" * 70)
    decrypted = rsa.decrypt(encrypted, private_key)
    print(f"Decrypted message: '{decrypted}'")
    
    # Verify
    print(f"\n✓ Encryption/Decryption successful: {message == decrypted}")
    print()
    
    # Test with different messages
    print("STEP 4: Testing Multiple Messages")
    print("-" * 70)
    test_messages = [
        "A",
        "Hello",
        "This is a longer test message!",
        "123456789",
        "Special chars: !@#$%^&*()"
    ]
    
    all_passed = True
    for i, msg in enumerate(test_messages, 1):
        enc = rsa.encrypt(msg, public_key)
        dec = rsa.decrypt(enc, private_key)
        passed = msg == dec
        all_passed = all_passed and passed
        
        status = "✓" if passed else "✗"
        print(f"  {status} Test {i}: '{msg}' → {enc} → '{dec}'")
    
    print(f"\n{'✓' if all_passed else '✗'} All tests passed: {all_passed}")
    
    print("\n" + "="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70 + "\n")


if __name__ == "__main__":
    # Run demonstration when file is executed directly
    demonstrate_rsa()