# 6 - Chain of Demands
## Explanation
For this challenge, we are given an ELF binary.
```sh
$ pwn checksec --file chat_client
[*] '/home/kali/Flareon/chat_client'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
```
I had a bit of PTSD from level 5 looking at the size of the binary (~30MB), but when I opened it in IDA it analyzed it extremely fast. Looking a bit further we see that it is compiled using PyInstaller.

Using `pyinstxtractor` to extract, we get the following few interesting files:
- `challenge_to_compile.pyc`
- `chat_log.json`
- `public.pem`

Using `pycdc` to decompile `challenge_to_compile.pyc`, we see that this challenge is meant to simulate "secure" communication on ethereum blockchain.

At the end of the json file, there is ciphertext encrypted using RSA, without the plaintext. Hence the objective is to decrypt the ciphertext.

## Solution
Looking at the python file, we see that there are 3 main classes being used to handle encryption:
1. `LCGOracle` - A Linear congruential generator (LCG) used to generate pseudorandom numbers
2. `TripleXOROracle` - Used for simple encryption paired with `LCGOracle`
3. `ChatLogic` - Handles how the oracles are initialised, as well as creating the RSA keys.

However, some parts are left out of the decompilation, meaning we need to look at the disassembled pyc for more details. This can be extracted using `dis.dis` and is found in `challenge_to_compile.txt`.

In particular, the part we want to focus on is`generate_rsa_key_from_lcg` -- How the RSA primes are generated.

After analyzing the disassembly, we get this code:
```py
class ChatLogic:
    # ...
    def generate_rsa_key_from_lcg(self):
        print('[RSA] Generating RSA key from on-chain LCG primes...')
        lcg_for_rsa = LCGOracle(self.lcg_oracle.multiplier, self.lcg_oracle.increment, self.lcg_oracle.modulus, self.seed_hash)
        lcg_for_rsa.deploy_lcg_contract()
        primes_arr = []
        rsa_msg_count = 0
        iteration_limit = 10000
        iterations = 0
        # WARNING: Decompyle incomplete

        # added by me
        while len(primes_arr) < 8 and iterations < iteration_limit:
            candidate = lcg_for_rsa.get_next(rsa_msg_count)
            rsa_msg_count += 1
            iterations += 1
            if candidate.bit_length() == 256 and isPrime(candidate):
                primes_arr.append(candidate)
                print(f"[RSA]  - Found 256-bit prime #{len(primes_arr)}: {candidate}")

        # print error messages...

        n = 1
        for p_val in primes_arr:
            n *= p_val

        phi = 1
        for p_val in primes_arr:
            phi *= (p_val - 1)

        e = 65537

        self.rsa_key = RSA.construct((e, n))
        # write to pem file
```

For the RSA, there are 8 primes involved, which are all obtained from `LCGOracle`! So if we are able to crack LCG, we can obtain the private key.

Also, the actual code for `TripleXOROracle.encrypt` and `LCGOracle.get_next` are actually in the eth bytecode. We can decompile it using https://ethervm.io/decompile. But luckily they are not too complicated, and act as how we expect.
- `LCGOracle.get_next`: Conventional LCG
- `TripleXOROracle.encrypt`: Pads plaintext to 32 bytes by adding null bytes on the right. Encrypts using `ct = pt ^ conversation_time ^ prime_from_lcg` 


This allows to formulate our **game plan**:

Step 1: Obtain the outputs of `LCGOracle`

Using the chatlogs with `"mode": "LCG-XOR"`, we are able to extract the LCG numbers using `lcg = ct ^ pt ^ conversation_time`.

This gives us 7 numbers generated using LCG.

Step 2: Crack LCG

We can use the code from https://github.com/TomasGlgg/LCGHack to obtained the values (m, c, n)

We need at least 6 numbers to obtain the modulus. Luckily we are given 7!
This allows us to replicate the exact LCG used to generate the primes.

Extracted LCG params:
```
Modulus: 98931271253110664660254761255117471820360598758511684442313187065390755933409
Multiplier: 11352347617227399966276728996677942514782456048827240690093985172111341259890
Increment: 61077733451871028544335625522563534065222147972493076369037987394712960199707
```

Step 3: Obtain the primes

Run the function `generate_rsa_key_from_lcg` to deterministically generate primes from the LCGOracle. 
Helper script used is `get_primes.py`

As PoC, write into a file `out.pem` and compare it to `public.pem`. They indeed match!

Use phi to RSA decrypt communication
```
Actually what's your email?
It's W3b3_i5_Gr8@flare-on.com
```

## Others
This challenge would've been a lot harder if they
1. Didn't use such readable variable names
2. Made use of the eth bytecode more. I'm pretty sure that's much harder to analyze than python bytecode. Maybe do some variation on encryption rather than making it easily guessable

Overall, it's quite an intimidating challenge with the number of files and modules, but didn't turn out to be as hard as I expected.