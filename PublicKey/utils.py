import secrets

# Use Fermat primality test with k iterations
def is_prime(n: int, k: int = 5) -> bool:
    for _ in range(k):
        a = secrets.randbelow(n)
        if pow(a, n-1, n) != 1:
            return False

    return True

# Generate a random n-bit prime
# Assumes n > 1
def generate_prime(n: int) -> int:
    res = 4

    # according to the distribution of primes, this should be approximately linear with respect to n
    while not is_prime(res):
        # the (1 << n-1) ensures the prime requires n bits, the final 1 ensures the generated number is odd since all primes (except 2) are odd
        res = (1 << n-1) + (secrets.randbits(n-2) << 1) + 1

    return res

# Convert a string to an int for use in cryptography
def str_to_num(msg: str) -> int:
    return int.from_bytes(msg.encode('utf-8'), byteorder='big')

# Convert an int back into a string after encrypting/decrypting
# size is how long the resulting string should be, in bytes
# throws error is size is too small
def num_to_str(msg: int, size: int) -> str:
    return msg.to_bytes(length=size, byteorder='big').decode('utf-8')
