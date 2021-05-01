from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
import os


def sha256(input_text: bytes()):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(input_text)

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


def RSA_encryption(generated_key: bytes()):
    with open('./private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None)

    public_key = private_key.public_key()

    cipher_text_2 = public_key.encrypt(generated_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    return cipher_text_2


def DES_encryption(generated_key_hex: str(), input_text: bytes()):
    half_generated_key_hex = generated_key_hex[:32]
    half_generated_key = bytes.fromhex(half_generated_key_hex)

    algorithm = algorithms.TripleDES(half_generated_key)
    mode = modes.CBC(b"\xcb\xb1'\xd8WT-\x05")
    cipher = Cipher(algorithm, mode=mode)
    des_encryptor = cipher.encryptor()

    cipher_text_1 = des_encryptor.update(input_text)

    return cipher_text_1


def main():
    input_file = open('input.txt', 'r')
    input_text = input_file.read()
    input_text = input_text.encode('UTF-8')

    byte_stream_224, byte_stream_32 = sha256(input_text)

    generated_key, generated_key_hex = key_generator(
        byte_stream_224, byte_stream_32)

    cipher_text_2 = RSA_encryption(generated_key)
    cipher_text_1 = DES_encryption(generated_key_hex, input_text)

    cipher_text_1 = cipher_text_1.hex()
    cipher_text_2 = cipher_text_2.hex()

    write_file = open('encrypted_file.txt', 'w')
    write_file.writelines([cipher_text_1, '\n', cipher_text_2])


if __name__ == '__main__':
    main()
digest = hashes.Hash(hashes.SHA256())
