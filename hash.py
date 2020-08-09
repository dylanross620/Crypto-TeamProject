from math import log2
import secrets

# This file is essentially just an implementation of FIPS 202
# where the specifications for SHA3 are stated. I tried to keep
# the code and naming as close as possible to the paper

def string_to_binary(s: str) -> list:
    bitstring = []
    for c in s:
        byte = format(ord(c), '08b')
        for bit in byte:
            bitstring.append(int(bit))

    return bitstring

def binary_to_string(b: list) -> str:
    res = ''
    for i in range(0, len(b), 4):
        word = [str(bit) for bit in b[i:i+4]]
        res += hex(int(''.join(word), 2))[2:] # convert to hex string, skipping the 0x
    return res

# Convert a bitstring to 3d matrix of bits for sha3
# assumes bit-length of s is a mutiple of 25
def string_to_mat(bitstring: list) -> list:
    b = len(bitstring)
    w = b // 25

    # Fill matrix according to sha3 paper
    A = []
    for x in range(5):
        A.append([])

        for y in range(5):
            A[x].append([])

            for z in range(w):
                A[x][y].append(bitstring[w * (5*y + x) + z])

    return A

# Convert a 3d matrix of bits into a bitstring
def mat_to_string(mat: list) -> list:
    bitstring = []

    # Unpack matrix into bitstring
    for y in range(5):
        for x in range(5):
            for bit in mat[x][y]:
                bitstring.append(bit)

    return bitstring

# theta function from the sha3 paper
# assumes mat is properly initialized
def theta(mat: list) -> list:
    w = len(mat[0][0])

    # Define and fill C
    C = []
    for x in range(5):
        C.append([])

        for z in range(w):
            C[x].append(mat[x][0][z] ^ mat[x][1][z] ^ mat[x][2][z] ^ mat[x][3][z] ^ mat[x][4][z])

    # Define and fill D
    D = []
    for x in range(5):
        D.append([])

        for z in range(w):
            D[x].append(C[(x-1) % 5][z] ^ C[(x+1) % 5][(z-1) % w])

    # Define and fill final matrix
    Ap = []
    for x in range(5):
        Ap.append([])

        for y in range(5):
            Ap[x].append([])

            for z in range(w):
                Ap[x][y].append(mat[x][y][z] ^ D[x][z])

    return Ap

# rho function from sha3 paper
# assumes mat is properly initialized
def rho(mat: list) -> list:
    w = len(mat[0][0])

    # Initialize A' to be the same as given
    Ap = []
    for x in range(5):
        Ap.append([])

        for y in range(5):
            Ap[x].append([])

            for b in mat[x][y]:
                Ap[x][y].append(b)

    # Don't have to fill first slice since already done above

    # Run loop to pivot
    x, y = 1, 0

    for t in range(24):
        for z in range(w):
            Ap[x][y][z] = mat[x][y][(z - (t+1) * (t+2) // 2) % w]
            x = y
            y = (2*x + 3*y) % 5
    
    return Ap
    
# pi function from sha3 paper
# assumes mat is properly initialized
def pi(mat: list) -> list:
    w = len(mat[0][0])

    Ap = []
    for x in range(5):
        Ap.append([])

        for y in range(5):
            Ap[x].append([])

            for z in range(w):
                Ap[x][y].append(mat[(x + 3*y) % 5][x][z])

    return Ap

# chi function from sha3 paper
# assumes mat is properly initialized
def chi(mat: list) -> list:
    w = len(mat[0][0])

    Ap = []

    for x in range(5):
        Ap.append([])

        for y in range(5):
            Ap[x].append([])

            for z in range(w):
                Ap[x][y].append(mat[x][y][z] ^ ((mat[(x+1) % 5][y][z] ^ 1) * mat[(x+2) % 5][y][z]))

    return Ap

# rc function from sha3 paper
# used as a helper function in iota function
def rc(t: int) -> int:
    if t % 255 == 0:
        return 1

    R = [1, 0, 0, 0, 0, 0, 0, 0]

    for _ in range((t % 255) + 1):
        R = [0] + R
        R[0] = R[0] ^ R[8]
        R[4] = R[4] ^ R[8]
        R[5] = R[5] ^ R[8]
        R[6] = R[6] ^ R[8]
        R = R[:8]

    return R[0]

# iota function from sha3 paper
# assumes mat is properly initialized and index is positive
def iota(mat: list, index: int) -> list:
    w = len(mat[0][0])

    # Initialize Ap to equal A
    Ap = []
    for x in range(5):
        Ap.append([])

        for y in range(5):
            Ap[x].append([])

            for z in mat[x][y]:
                Ap[x][y].append(z)

    # Generate RC using the round index and helper function
    RC = [0] * w
    for j in range(int(log2(w)) + 1):
        RC[2**j - 1] = rc(j + 7*index)

    # Modify top lane according to RC
    for z in range(w):
        Ap[0][0][z] = Ap[0][0][z] ^ RC[z]

    return Ap

# keccak-p function from sha3 paper
# assumes msg has a bitlength divisible by 25
def keccak_p(msg: list, num_rounds: int) -> list:
    state_array = string_to_mat(msg)
    l = int(log2(len(state_array[0][0])))

    for i in range(12 + 2*l - num_rounds, 12 + 2*l):
        state_array = iota(chi(pi(rho(theta(state_array)))), i) # round function

    return mat_to_string(state_array)

# implementation of the pad10*1 padding algorithm from sha3 paper
# returns a string such that m + bit_length(P) is a positive multiple of target
def pad101(target: int, m: int) -> list:
    j = (-m - 2) % target
    return [1] + [0]*j + [1]

# sponge function provided in sha3 paper
def sponge(msg: list, desired_length: int) -> list:
    r = 1600 - 512 # defined in paper for sha3-256
    b = 1600 # example value given in paper

    P = msg + pad101(r, len(msg)) # pad message
    n = len(P) // r
    c = b - r

    S = [0]*b
    for i in range(n):
        p_extended = P + [0]*c
        xor = [a ^ b for a, b in zip(S, p_extended)]
        S = keccak_p(xor, 24)

    Z = S[:r]
    while desired_length > len(Z):
        S = keccak_p(S, 24)
        Z = Z + S[:r]
    
    return Z[:desired_length]

# Use SHA3-256 to hash msg
def sha256(msg: str) -> str:
    msg = string_to_binary(msg)

    res = sponge(msg + [0,1], 256)

    return binary_to_string(res)

hmac_keys = {}

# Use HMAC to generate a mac for the given string
# msg is a plaintext string
# key is a hex string
def hmac(msg: str, key: str) -> str:
    B = 32

    # Ensure key is right size
    if len(key) > 2*B: # 2B because each byte in hex is 2 characters
        key = sha256(key)
    while len(key) < 2*B:
        key += '00'
    
    # Check if key has been used before. If so, don't need to recalculate ipad and opad xors
    if key in hmac_keys:
        x_ipad, x_opad = hmac_keys[key]
    else:
        ipad = [0x36]*B
        opad = [0x5c]*B
        key_bytes = [int(key[i:i+2], 16) for i in range(0, len(key), 2)]
        x_ipad = ''.join([format(a ^ b, '02x') for a, b in zip(ipad, key_bytes)])
        x_opad = ''.join([format(a ^ b, '02x') for a, b in zip(opad, key_bytes)])

        hmac_keys[key] = (x_ipad, x_opad)

    return sha256(x_opad + sha256(x_ipad + msg))

# Generate an authentication key to be used by hmac
def generate_mac_key():
    return format(secrets.randbits(32*8), '064x')
