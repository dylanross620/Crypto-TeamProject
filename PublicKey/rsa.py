import PublicKey.utils as utils
import hash
from math import gcd

# Load public and private keys from a file, if possible.
# If there's an error, generate keys and save to the file.
#
# filename is the file to load from/save to
# bitsize is the desired size of N if the keys must be generated, and should be a 
#   power of 2
# return will be in form (public key, private key) where public key is (N, e)
#   and private key is (N, d)
def load_keys(filename: str, bitsize: int) -> tuple:
    try:
        f = open(filename, 'r')
        lines = f.readlines()
        
        n = int(lines[0])
        e = int(lines[1])
        d = int(lines[2])

        f.close()
        return ((n, e), (n, d))
    except:
        pub_key, priv_key = generate_keys(bitsize)
        f = open(filename, 'w')
        lines = [pub_key[0], pub_key[1], priv_key[1]]
        f.writelines([str(l) + '\n' for l in lines])
        
        f.close()
        return (pub_key, priv_key)

# Generate keys where n has bitsize bits
# return in form (public key, private key) where public key is (N, e) and
#   private key is (N, d)
def generate_keys(bitsize: int) -> tuple:
    e = 65537
    n = 1

    # while loop shouldn't be needed here, but doesn't hurt
    while n < 2**(bitsize-1) or n >= 2**bitsize:
        p = e+1
        while gcd(p-1, e) != 1 or gcd(p, e) != 1: # gcd(p, e) != 1 can factor n
            p = utils.generate_prime(bitsize//2)
        q = p
        while q == p or gcd(e, q-1) != 1 or gcd(e, q) != 1: # gcd(q, e) != 1 can factor n
            q = utils.generate_prime(bitsize//2)

        phi = (p-1) * (q-1)
        d = pow(e, -1, phi)
        n = p * q

        # ensure d isn't too large or too small (for Wiener's attack)
        if d >= n or (3*d)**4 < n: # re-wrote Wiener's attack bound to prevent taking root of large number causing overflow
            n = 1 # causes loop to continue

    pub_key = (n, e)
    priv_key = (n, d)
    return (pub_key, priv_key)


# Encrypt a message using the provided public key.
# Assumes msg < N for both N in public key and private key (if provided)
def encrypt(msg: str, pub_key: tuple) -> int:
    msg = utils.str_to_num(msg)

    return pow(msg, pub_key[1], pub_key[0])

# Decrypt a message using the provided private key.
def decrypt(msg: int, priv_key: tuple) -> str:
    decrypted = pow(msg, priv_key[1], priv_key[0])

    return utils.num_to_str(decrypted, priv_key[0].bit_length())

# Generate a signature for the given message
def sign(msg: str, priv_key: tuple) -> int:
    hashed = int(hash.sha256(msg), 16)

    return pow(hashed, priv_key[1], priv_key[0])

# Verify a signature for the given message
# returns true iff the signature is valid
def verify_signature(signature: int, msg: str, pub_key: tuple) -> bool:
    hashed = int(hash.sha256(msg), 16)

    return hashed == pow(signature, pub_key[1], pub_key[0])
