import PublicKey.utils as utils
import secrets

# Load keys from a given file, generating them if they don't exist
# In the case that keys must be generated, it will generate such that
#   the bitlength of prime p is bitsize.
# The return will be in the form (public key, a) where public key
#   is (p, alpha, beta)
def load_keys(filename: str, bitsize: int) -> tuple:
    try:
        f = open(filename, 'r')
        lines = f.readlines()

        p = int(lines[0])
        alpha = int(lines[1])
        beta = int(lines[2])
        a = int(lines[3])

        pub_key = (p, alpha, beta)
        return (pub_key, a)
    except:
        pub_key, a = generate_keys(bitsize)

        f = open(filename, 'w')
        lines = [pub_key[0], pub_key[1], pub_key[2], a]
        f.writelines([str(l) + '\n' for l in lines])
        
        f.close()
        return (pub_key, a)

# Generate keys where p has bitsize bits
# Return is in the form (public key, a) where public key is
#   (p, alpha, beta)
def generate_keys(bitsize: int) -> tuple:
    # Generate group Zp
    p = 4
    while not utils.is_prime(p) or p >= 2**bitsize or p < 2**(bitsize-1):
        p = 2 * utils.generate_prime(bitsize-1) + 1

    # Calculate generator (alpha) for the group
    phi = p-1
    phi_factors = [2, phi//2]
    alpha = 2 # default value
    for i in range(2, p):
        if pow(i, phi//phi_factors[0], p) != 1 and pow(i, phi//phi_factors[1], p) != 1:
            alpha = i
            break

    # Generate private key and beta
    a = 0
    while a < 1: # ensure a isn't randomly selected to be 1
        a = secrets.randbelow(p-1)
    beta = pow(alpha, a, p)
    
    pub_key = (p, alpha, beta)
    return (pub_key, a)

# Encrypts a message using the specified public key, where
# the public key is in the form (p, alpha, beta)
def encrypt(msg: str, pub_key: tuple) -> int:
    pass

# Decrypts a message using the specified private key
def decrypt(msg: int, priv_key: int) -> str:
    pass

if __name__ == '__main__':
    print(generate_keys(512))
