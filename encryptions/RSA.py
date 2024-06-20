import random
import math

def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
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

def generate_prime_candidate(length):
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime(length=16):
    while True:
        p = generate_prime_candidate(length)
        if is_prime(p):
            return p

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keypair(length=16):
    p = generate_prime(length)
    
    while True:
        q = generate_prime(length)
        if q != p:
            break
    
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = random.randrange(2, phi)
        if math.gcd(e, phi) == 1:
            break

    d = modinv(e, phi)
    return (n, e), (n, d)

def encrypt(message_bytes, public_key):
    n, e = public_key
    encrypted = [pow(byte, e, n) for byte in message_bytes]
    encrypted_bytes = b''.join(x.to_bytes((n.bit_length() + 7) // 8, byteorder='big') for x in encrypted)
    return encrypted_bytes

def decrypt(encrypted_bytes, private_key):
    n, d = private_key
    byte_length = (n.bit_length() + 7) // 8
    encrypted_integers = [int.from_bytes(encrypted_bytes[i:i + byte_length], byteorder='big') for i in range(0, len(encrypted_bytes), byte_length)]
    decrypted = [pow(byte, d, n) for byte in encrypted_integers]
    decrypted_bytes = bytes(decrypted)
    return decrypted_bytes.decode()

if __name__ == "__main__":
    public_key, private_key = generate_keypair(16)
    message = "Hello, RSA!"
    print(generate_keypair())
    encrypted_message = encrypt(message.encode(), public_key)
    decrypted_message = decrypt(encrypted_message, private_key)
    print("Encrypted message:", encrypted_message)
    print("Decrypted message:", decrypted_message)
