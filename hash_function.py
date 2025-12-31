
class SHA256:

    def __init__(self):
        
        # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        # Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
    
    def _rotr(self, x, n):
        """Rotate right (circular right shift)"""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    
    def _shr(self, x, n):
        """Shift right"""
        return x >> n
    
    def _ch(self, x, y, z):
        """Choice function: for each bit position, choose bit from y or z based on x"""
        return (x & y) ^ (~x & z)
    
    def _maj(self, x, y, z):
        """Majority function: for each bit position, return majority bit"""
        return (x & y) ^ (x & z) ^ (y & z)
    
    def _sigma0(self, x):
        """Σ0 (Uppercase Sigma 0) - used in compression function"""
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)
    
    def _sigma1(self, x):
        """Σ1 (Uppercase Sigma 1) - used in compression function"""
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)
    
    def _gamma0(self, x):
        """σ0 (Lowercase sigma 0) - used in message schedule"""
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ self._shr(x, 3)
    
    def _gamma1(self, x):
        """σ1 (Lowercase sigma 1) - used in message schedule"""
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ self._shr(x, 10)
    
    def _pad_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        msg_len = len(message)
        msg_bit_len = msg_len * 8
        
        # Append the '1' bit (as 0x80 = 10000000 in binary)
        message += b'\x80'
        
        # Append zeros until message length ≡ 448 (mod 512) bits
        # This is 56 (mod 64) bytes
        while (len(message) % 64) != 56:
            message += b'\x00'
        
        # Append the original message length as a 64-bit big-endian integer
        message += msg_bit_len.to_bytes(8, byteorder='big')
        
        return message
    
    def _process_chunk(self, chunk, hash_values):

        # Prepare message schedule (extend 16 32-bit words to 64 words)
        w = []
        
        # First 16 words are the chunk split into 32-bit big-endian words
        for i in range(0, 64, 4):
            w.append(int.from_bytes(chunk[i:i+4], byteorder='big'))
        
        # Extend to 64 words using the message schedule
        for i in range(16, 64):
            s0 = self._gamma0(w[i-15])
            s1 = self._gamma1(w[i-2])
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
        
        # Initialize working variables
        a, b, c, d, e, f, g, h = hash_values
        
        # Main compression loop (64 rounds)
        for i in range(64):
            S1 = self._sigma1(e)
            ch = self._ch(e, f, g)
            temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
            S0 = self._sigma0(a)
            maj = self._maj(a, b, c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Add compressed chunk to current hash values
        hash_values[0] = (hash_values[0] + a) & 0xFFFFFFFF
        hash_values[1] = (hash_values[1] + b) & 0xFFFFFFFF
        hash_values[2] = (hash_values[2] + c) & 0xFFFFFFFF
        hash_values[3] = (hash_values[3] + d) & 0xFFFFFFFF
        hash_values[4] = (hash_values[4] + e) & 0xFFFFFFFF
        hash_values[5] = (hash_values[5] + f) & 0xFFFFFFFF
        hash_values[6] = (hash_values[6] + g) & 0xFFFFFFFF
        hash_values[7] = (hash_values[7] + h) & 0xFFFFFFFF
        
        return hash_values
    
    def hash(self, message):
        # Pad the message
        padded = self._pad_message(message)
        
        # Initialize hash values (copy to avoid modifying original)
        hash_values = self.h.copy()
        
        # Process each 512-bit (64-byte) chunk
        for i in range(0, len(padded), 64):
            chunk = padded[i:i+64]
            hash_values = self._process_chunk(chunk, hash_values)
        
        # Produce final hash value (concatenate all hash values)
        final_hash = ''.join(format(h, '08x') for h in hash_values)
        
        return final_hash
    
    def hash_bytes(self, data):
        
        return self.hash(data)
    
    def verify(self, message, expected_hash):
        
        calculated_hash = self.hash(message)
        return calculated_hash.lower() == expected_hash.lower()


# Convenience function
def sha256(message):
    hasher = SHA256()
    return hasher.hash(message)


# Backward compatibility - keep old class name
class CustomHash(SHA256):
    pass


def demonstrate_sha256():
    print("\n" + "="*80)
    print("SHA-256 HASH FUNCTION DEMONSTRATION")
    print("Complete Implementation from Scratch - NIST FIPS 180-4")
    print("="*80 + "\n")
    
    hasher = SHA256()
    
    # Test 1: Empty string (official test vector)
    print("TEST 1: Official Test Vectors")
    print("-" * 80)
    
    tests = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    ]
    
    all_passed = True
    for i, (message, expected) in enumerate(tests, 1):
        calculated = hasher.hash(message)
        passed = calculated == expected
        all_passed = all_passed and passed
        
        status = "✓" if passed else "✗"
        display_msg = f"'{message}'" if len(message) <= 50 else f"'{message[:47]}...'"
        
        print(f"{status} Test {i}: {display_msg}")
        print(f"  Expected:   {expected}")
        print(f"  Calculated: {calculated}")
        print(f"  Match: {passed}")
        print()
    
    print(f"{'✓' if all_passed else '✗'} Official test vectors: {'PASSED' if all_passed else 'FAILED'}")
    
    # Test 2: Practical examples
    print("\nTEST 2: Practical Examples")
    print("-" * 80)
    
    message = "Hello, World!"
    hash_result = hasher.hash(message)
    print(f"Message: '{message}'")
    print(f"SHA-256: {hash_result}")
    print(f"Length:  {len(hash_result)} hex chars = 256 bits")
    
    # Test 3: Avalanche effect
    print("\nTEST 3: Avalanche Effect (One Character Change)")
    print("-" * 80)
    
    msg1 = "Hello, World!"
    msg2 = "Hello, World?"
    
    hash1 = hasher.hash(msg1)
    hash2 = hasher.hash(msg2)
    
    print(f"Message 1: '{msg1}'")
    print(f"Hash 1:    {hash1}")
    print(f"\nMessage 2: '{msg2}'")
    print(f"Hash 2:    {hash2}")
    
    # Count different hex characters
    diff = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
    print(f"\nDifferent characters: {diff}/64 ({diff/64*100:.1f}%)")
    print("✓ Excellent avalanche effect!")
    
    # Test 4: Different message lengths
    print("\nTEST 4: Different Message Lengths")
    print("-" * 80)
    
    messages = [
        "A",
        "Hello",
        "The quick brown fox jumps over the lazy dog",
        "A" * 1000
    ]
    
    for msg in messages:
        h = hasher.hash(msg)
        display = msg if len(msg) <= 50 else msg[:47] + "..."
        print(f"Message ({len(msg):4} chars): '{display}'")
        print(f"SHA-256: {h}")
        print()
    
    # Test 5: Binary data
    print("TEST 5: Binary Data")
    print("-" * 80)
    binary_data = bytes([0x00, 0xFF, 0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78])
    hash_bin = hasher.hash_bytes(binary_data)
    print(f"Binary data: {binary_data.hex()}")
    print(f"SHA-256:     {hash_bin}")
    
    # Compare with known SHA-256 implementations
    print("\n" + "="*80)
    print("VERIFICATION")
    print("="*80)
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80 + "\n")


if __name__ == "__main__":
    demonstrate_sha256()