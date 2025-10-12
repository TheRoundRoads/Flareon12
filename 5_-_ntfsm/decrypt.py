from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def sha256(data: bytes) -> bytes:
    h = SHA256.new()
    h.update(data)
    return h.digest()

def aes_cbc_decrypt(ciphertext, key, iv):
    """
    Decrypts data using AES in CBC mode.

    Args:
        ciphertext (bytes): The encrypted data.
        key (bytes): The secret key used for encryption (16, 24, or 32 bytes).
        iv (bytes): The initialization vector used during encryption (16 bytes).

    Returns:
        bytes: The decrypted plaintext.
    """
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_padded_data, AES.block_size)
        return plaintext
    except ValueError as e:
        # print(f"Decryption error: {e}")
        return None
    
flag = bytes.fromhex("9cafad1c6f8ef523f1b890adb4d71e66625f85f80ff61e27d3909c0da8a05dee12555fd4e6726c220b22709ff1676721")

iv = bytes.fromhex("81a829124fa62d0dfb28e5f1783d5c69")

with open("out.txt", "r") as infile:
    for row in infile:
        key = sha256(row.strip().encode())
        result = aes_cbc_decrypt(flag, key, iv)
        if result != None and b"flare" in result:
            print("Password:", row.strip())
            print(result)