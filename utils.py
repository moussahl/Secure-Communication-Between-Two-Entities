import random


def generate_prime(bits):
    while True:
        # Generate random odd number with correct bit length
        num = random.getrandbits(bits)
        
        # Set MSB to 1 to ensure correct bit length
        num |= (1 << bits - 1)
        
        # Set LSB to 1 to ensure it's odd
        num |= 1
        
        # Test if it's prime
        if is_prime(num):
            return num


def is_prime(n, k=5):
    # Handle small cases
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop - test k times
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    def extended_gcd(a, b):
        """Extended Euclidean Algorithm"""
        if a == 0:
            return b, 0, 1
        
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd_val, x, y
    
    gcd_val, x, _ = extended_gcd(e, phi)
    
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    
    # Make sure result is positive
    return (x % phi + phi) % phi


def fast_power(base, exponent, modulus):
    result = 1
    base = base % modulus
    
    while exponent > 0:
        # If exponent is odd, multiply base with result
        if exponent % 2 == 1:
            result = (result * base) % modulus
        
        # exponent must be even now
        exponent = exponent >> 1  # Divide by 2
        base = (base * base) % modulus
    
    return result


def bytes_to_int(bytes_data):
    return int.from_bytes(bytes_data, byteorder='big')


def int_to_bytes(number, length):
    return number.to_bytes(length, byteorder='big')

