from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import argparse
import getpass

def aes_256_encrypt(key: bytes, plaintext: bytes) -> bytes:
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

def aes_256_decrypt(key: bytes, ciphertext_encoded: bytes) -> bytes:
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

def generate_key(password: str, iterations=1946) -> bytes:

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

if __name__=="__main__":

    parser = argparse.ArgumentParser(description='Simple Python AES-256 Encryption & Decryption')

    encrypt_or_decrypt = parser.add_mutually_exclusive_group(required=True)
    string_or_file = parser.add_mutually_exclusive_group(required=True)

    encrypt_or_decrypt.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the string.')
    encrypt_or_decrypt.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the string.')
    string_or_file.add_argument('-s', '--string', type=str, help='Input a string to be encrypted or decrypted.')
    string_or_file.add_argument('-f', '--file', type=str, help='Input a file path to be encrypted or decrypted.')

    args = parser.parse_args()

    input_string = args.string
    file_path = args.file

    global key
    password = getpass.getpass("Password: ")
    key = generate_key(password)

    try:
        if args.string != None:
            if args.encrypt:
                plaintext = bytes(input_string, 'utf-8')
                encoded_text = aes_256_encrypt(key, plaintext)
                print("\nEncrypted String: " + encoded_text.decode())
            if args.decrypt:
                encoded_text = aes_256_decrypt(key, input_string)
                print("\nDecrypted String: " + encoded_text.decode())
        
        if args.file != None:
            if os.path.isfile(file_path):
                with open(file_path, "r") as f:
                    lines = f.readlines()
                    f.close()

                with open(file_path, "w") as f:
                    f.write("")
                    f.close()

                with open(file_path, "a") as f:
                    for line in lines:
                        if args.encrypt:
                            encrypted_line = aes_256_encrypt(key, bytes(line, 'utf-8'))
                            f.write(str(encrypted_line.decode()) + "\n")

                        if args.decrypt:
                            decrypted_line = aes_256_decrypt(key, line)
                            f.write(str(decrypted_line.decode()))

                if args.encrypt:
                    print("\nFile Encrypted: " + file_path)
                if args.decrypt:
                    print("\nFile Decrypted: " + file_path)

            else:
                print("Error! File not found.")
 
    except Exception as e:
        print("Error! " + str(e))
