from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from time import sleep
import base64
import argparse

def aes_256_encrypt(key, plaintext):
    try:
        iv = os.urandom(16)

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        plaintext_padded = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

        encoded_text = base64.b64encode(iv + ciphertext)

        return encoded_text
    
    except Exception as e:
        print("\nError Encrypting! " + str(e))

def aes_256_decrypt(key, ciphertext_encoded):
    try:
        ciphertext = base64.b64decode(ciphertext_encoded)

        iv = ciphertext[:16]

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted
    
    except Exception as e:
        print("\nError Decrypting! " + str(e))

def generate_key(password, iterations=1000):

    salt = b'~4\xb43\xf6.\xc16P\xc7C\x84\n\xc0\x9e\x96'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    key = kdf.derive(password.encode('utf-8'))

    return key

def login():
    global key
    password = input("Password: ")
    key = generate_key(password)

if __name__=="__main__":

    parser = argparse.ArgumentParser(description='Simple Python AES-256 Encryption & Decryption')

    encrypt_or_decrypt = parser.add_mutually_exclusive_group(required=True)

    encrypt_or_decrypt.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the string.')
    encrypt_or_decrypt.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the string.')
    parser.add_argument('-s', '--string', type=str, required=True, help='Input a string to be encrypted or decrypted.')

    args = parser.parse_args()

    encrypt_flag = args.encrypt
    decrypt_flag = args.decrypt
    input_string = args.string

    global key
    password = input("Password: ")
    key = generate_key(password)

    try:
        if args.encrypt:
            plaintext = bytes(input_string, 'utf-8')
            encoded_text = aes_256_encrypt(key, plaintext)
            print("\nEncrypted String: " + encoded_text.decode() + "\n")
        if args.decrypt:
            encoded_text = aes_256_decrypt(key, input_string)
            print("\nDecrypted String: " + encoded_text.decode() + "\n")
    except:
        pass
