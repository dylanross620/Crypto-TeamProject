import utils
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

def generate_keys(bitsize: int) -> tuple:
    e = 65537
    n = 1

    # while loop shouldn't be needed here, but doesn't hurt
    while n < 2**(bitsize-1) or n >= 2**bitsize:
        p = e+1
        while gcd(p-1, e) != 1:
            p = utils.generate_prime(bitsize//2)
        q = p
        while q == p or gcd(e, q-1) != 1:
            q = utils.generate_prime(bitsize//2)

        phi = (p-1) * (q-1)
        d = pow(e, -1, phi)
        n = p * q

        # ensure d isn't too large or too small (for Wiener's attack)
        if d >= n or d < (1/3) * n**(1/4):
            n = 1 # causes loop to continue

    pub_key = (n, e)
    priv_key = (n, d)
    return (pub_key, priv_key)


# Encrypt a message using the provided public key.
# If private key is provided, the message will be signed first, and then encrypted.
# Assumes msg < N for both N in public key and private key (if provided)
def encrypt(msg: str, pub_key: tuple, priv_key: tuple = None) -> int:
    msg = utils.str_to_num(msg)

    if priv_key is not None and priv_key[0] != pub_key[0]: # checking to see if coincidentally have same key
        msg = pow(msg, priv_key[1], priv_key[0])

    return pow(msg, pub_key[1], pub_key[0])

# Decrypt a message using the provided private key.
# If public key is provided, it will decrypt and then use public key to remove a signature
def decrypt(msg: int, priv_key: tuple, pub_key: tuple = None) -> str:
    decrypted = pow(msg, priv_key[1], priv_key[0])

    if pub_key is not None and pub_key[0] != priv_key[0]:
        decrypted = pow(decrypted, pub_key[1], pub_key[0])

    return utils.num_to_str(decrypted, priv_key[0].bit_length())
