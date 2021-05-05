from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
import os


def sha256(x: bytes()):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(x)

    sha256_hash = digest.finalize()

    byte_stream_224 = str()
    byte_stream_32 = str()

    for byte in sha256_hash:
        temp = f'{byte:0>8b}'
        byte_stream_32 += temp[0]
        byte_stream_224 += temp[1:]

    return byte_stream_224, byte_stream_32


def key_generator(byte_stream_224: str(), byte_stream_32: str()):
    final_byte_stream = byte_stream_224 + byte_stream_32

    generated_key_hex = "{0:0>4X}".format(int(final_byte_stream, 2))
    generated_key = bytes.fromhex(generated_key_hex)

    return generated_key, generated_key_hex


# RSA Decryption Process
def RSA_decryption(cipher2 : bytes()): 
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
    return plaintext


# DES Decryption Process
def DES_decryption(plaintext : bytes(), cipher1 : bytes()): 
    generated_key_hex = plaintext.hex() #yaha use hai
    half_generated_key_hex = generated_key_hex[:32]
    half_generated_key = bytes.fromhex(half_generated_key_hex)

    algorithm = algorithms.TripleDES(half_generated_key)
    mode = modes.CBC(b"\xcb\xb1'\xd8WT-\x05")
    cipher = Cipher(algorithm, mode=mode)

    des_decryptor = cipher.decryptor()
    x = des_decryptor.update(cipher1) 

    return x

def main():
    
    read_file = open('./encrypted_file.txt', 'r')
    cipher = read_file.readlines()
    cipher1 = cipher[0].rstrip('\n')
    cipher2 = cipher[1]

    cipher1 = bytes.fromhex(cipher1)
    cipher2 = bytes.fromhex(cipher2)

    print(cipher1)
    print(cipher2)

    plaintext = RSA_decryption(cipher2) 

    x = DES_decryption(plaintext, cipher1) 

    byte_stream_224, byte_stream_32 = sha256(x)

    generated_key, generated_key_hex = key_generator(
        byte_stream_224, byte_stream_32)

    write_file = open('output.txt', 'w')
    write_file.writelines([x.decode()])


if __name__ == '__main__':
    main()
digest = hashes.Hash(hashes.SHA256())
        
    

    

    
