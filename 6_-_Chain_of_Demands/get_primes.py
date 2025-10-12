import hashlib
from Crypto.Util.number import isPrime
import platform
from Crypto.PublicKey import RSA

class LCGOracle:
    def __init__(self, multiplier, increment, modulus, initial_seed):
        self.multiplier = multiplier
        self.increment = increment
        self.modulus = modulus
        self.state = initial_seed
    def get_next(self, counter):
        # print(f'''\n[+] Calling nextVal() with _currentState={self.state}''')
        self.state = (self.multiplier*self.state + self.increment) % self.modulus
        # print(f'''  _counter = {counter}: Result = {self.state}''')
        return self.state

def _get_system_artifact_hash():
    artifact = platform.node().encode('utf-8')
    hash_val = hashlib.sha256(artifact).digest()
    seed_hash = int.from_bytes(hash_val, 'little')
    print(f'''[SETUP]  - Generated Seed {seed_hash}...''')
    return seed_hash

def _generate_primes_from_hash(seed_hash):
    primes = []
    current_hash_byte_length = (seed_hash.bit_length() + 7) // 8
    current_hash = seed_hash.to_bytes(current_hash_byte_length, 'little')
    print('[SETUP] Generating LCG parameters from system artifact...')
    iteration_limit = 10000
    iterations = 0
    while len(primes) < 3 and iterations < iteration_limit:
        current_hash = hashlib.sha256(current_hash).digest()
        candidate = int.from_bytes(current_hash, "little")
        iterations += 1
        if candidate.bit_length() == 256 and isPrime(candidate):
            primes.append(candidate)
            print(f"Found parameter {len(primes)}: {candidate}")

    if len(primes) != 3:
        print("Not found!")

def generate_rsa_key_from_lcg():
    print('[RSA] Generating RSA key from on-chain LCG primes...')
    m = 110283618870338064626531490251795414335143054807338925132407172237502097193299
    c = 61077733451871028544335625522563534065222147972493076369037987394712960199707
    n = 98931271253110664660254761255117471820360598758511684442313187065390755933409
    seed_hash = 80631529052001100272845413254760303954872303349693249834992925889079643767931
    lcg_for_rsa = LCGOracle(m, c, n, seed_hash)
    # lcg_for_rsa.deploy_lcg_contract()
    primes_arr = []
    rsa_msg_count = 0
    iteration_limit = 10000
    iterations = 0
    while len(primes_arr) < 8 and iterations < iteration_limit:
        candidate = lcg_for_rsa.get_next(rsa_msg_count)
        rsa_msg_count += 1
        iterations += 1
        if candidate.bit_length() == 256 and isPrime(candidate):
            primes_arr.append(candidate)
            print(f"[RSA]  - Found 256-bit prime #{len(primes_arr)}: {candidate}")

    # print error messages...
    print("Primes:", primes_arr)

    n = 1
    for p_val in primes_arr:
        n *= p_val

    phi = 1
    for p_val in primes_arr:
        phi *= (p_val - 1)

    print("Phi:", phi)
    print("N:", n)

    e = 65537

    rsa_key = RSA.construct((n, e))

    with open("out.pem", "wb") as outfile:
        outfile.write(rsa_key.export_key())

    print("Done!")

    # write to pem file



if __name__ == "__main__":
    # _generate_primes_from_hash(_get_system_artifact_hash())
    # _generate_primes_from_hash(80631529052001100272845413254760303954872303349693249834992925889079643767931)
    generate_rsa_key_from_lcg()