import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# AES CBC

def encrypt_aes_cbc(key, plaintext):
    iv = os.urandom(16) # Gen IV
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) # Init AES and mode
    
    encryptor = cipher.encryptor() # Making the encryptor class
    
    padder = padding.PKCS7(128).padder() # Making the class that handles padding of the data
    
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize() # Data with padding for block size
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize() # Calculating the ciphertext
    
    return iv, ciphertext # The IV is needed for decryption

def decrypt_aes_cbc(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) # AES and mode
    
    decryptor = cipher.decryptor() # Decrypter class
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize() # Decrypting the ciphertext
    
    unpadder = padding.PKCS7(128).unpadder() # Unpadder class
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize() # Unpadding the decryptet data
   
    return plaintext.decode('utf-8') # Making from bytes to string for python


# AES CTR

def encrypt_aes_ctr(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    nonce = os.urandom(16) #nonce for randomizing data, to get different output
    
    # Initalizing the encrypter classes and modes
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    
    # No padding needed, so just diredct encryption
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    
    return nonce, ciphertext # The nonce is needed for decryption


def decrypt_aes_ctr(key, nonce, ciphertext):
    # Initalizing the decrypter classes and modes
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    
    # Decrypting the data directly
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8') # Decoding for python


# Both encryption and decryption

def encrypt_with_both(key, plaintext):
    print("\n**Encryption Comparison**")
    
    start_cbc = time.perf_counter()
    iv_cbc, cbc_cipher = encrypt_aes_cbc(key, plaintext)
    time_cbc = time.perf_counter() - start_cbc
    cbc_size = len(cbc_cipher)
    
    start_ctr = time.perf_counter()
    nonce_ctr, ctr_cipher = encrypt_aes_ctr(key, plaintext)
    time_ctr = time.perf_counter() - start_ctr
    ctr_size = len(ctr_cipher)
    
    
    print(f"Plaintext bytes length: {len(plaintext.encode('utf-8'))}")
    print(f"-\tAES-CBC Ciphertext length : {cbc_size} bytes")
    print(f"\tTime taken: {time_cbc:.6f} seconds")
    print(f"-\tAES-CTR Ciphertext length : {ctr_size} bytes")
    print(f"\tTime taken: {time_ctr:.6f} seconds")
    print("-" * 40 + "\n")
    
    return iv_cbc, cbc_cipher, nonce_ctr, ctr_cipher


def decrypt_with_both(key: bytes, iv_cbc: bytes, cbc_cipher: bytes, nonce_ctr: bytes, ctr_cipher: bytes):
    print("\n**Decryption Comparison**")
    
    start_cbc = time.perf_counter()
    plaintext_cbc = decrypt_aes_cbc(key, iv_cbc, cbc_cipher)
    time_cbc = time.perf_counter() - start_cbc
    
    start_ctr = time.perf_counter()
    plaintext_ctr = decrypt_aes_ctr(key, nonce_ctr, ctr_cipher)
    time_ctr = time.perf_counter() - start_ctr
    
    print(f"-\tAES-CBC Decryption Time: {time_cbc:.6f} seconds")
    print(f"\tPlaintext output: {plaintext_cbc}")
    print(f"-\tAES-CTR Decryption Time: {time_ctr:.6f} seconds")
    print(f"\tPlaintext output: {plaintext_ctr}")
    print("-" * 40 + "\n")