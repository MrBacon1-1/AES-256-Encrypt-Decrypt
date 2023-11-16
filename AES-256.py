from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from time import sleep
import base64

def aes_256_encrypt(key, plaintext):
    iv = os.urandom(16)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    plaintext_padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

    encoded_text = base64.b64encode(iv + ciphertext)

    return encoded_text

def aes_256_decrypt(key, ciphertext_encoded):
    ciphertext = base64.b64decode(ciphertext_encoded)

    iv = ciphertext[:16]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted

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

def main():
    while True:

        print("1. Encrypt \n2. Decrypt")

        opt = input("Option: ")
        if opt == "1":
            string = input("\nText To Encrypt: ")
            plaintext = bytes(string, 'utf-8')
            print("\nEncrypted String: " + aes_256_encrypt(key, plaintext).decode() + "\n")
        if opt == "2":
            encrypted_string = input("\nEncrypted String: ")
            encoded_string = encrypted_string.encode()
            print("\nDecrypted String: " + aes_256_decrypt(key, encoded_string).decode() + "\n")

        main()

def login():
    global key
    password = input("Password: ")
    key = generate_key(password)
    os.system(f"title Python AES-256 Example : Key ~ {key}")
    os.system("cls")
    main()

if __name__=="__main__":
    login()