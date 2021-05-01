from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
import os

read_file = open('./encrypted_file.txt', 'r')
cipher = read_file.readlines()
cipher1 = cipher[0].rstrip('\n')
cipher2 = cipher[1]

cipher1 = bytes.fromhex(cipher1)
cipher2 = bytes.fromhex(cipher2)

print(cipher1)
print(cipher2)

# RSA Decryption Process
with open('./private_key.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(), password=None)
public_key = private_key.public_key()

plaintext = private_key.decrypt(
    cipher2,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# DES Decryption Process
generated_key_hex = plaintext.hex()
half_generated_key_hex = generated_key_hex[:32]
half_generated_key = bytes.fromhex(half_generated_key_hex)

algorithm = algorithms.TripleDES(half_generated_key)
mode = modes.CBC(b"\xcb\xb1'\xd8WT-\x05")
cipher = Cipher(algorithm, mode=mode)

des_decryptor = cipher.decryptor()
x = des_decryptor.update(cipher1)

print(x)
