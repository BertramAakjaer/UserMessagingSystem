import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# AES CBC

def encrypt_aes_cbc(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

def decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode('utf-8')


# AES CTR

def encrypt_aes_ctr(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return nonce, ciphertext

def decrypt_aes_ctr(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')


# Both encryption and decryption

def encrypt_with_both(key: bytes, plaintext: str) -> tuple:
    print("\n**Encryption Comparison**")
    
    start_cbc = time.perf_counter()
    iv_cbc, cbc_cipher = encrypt_aes_cbc(key, plaintext)
    time_cbc = time.perf_counter() - start_cbc
    
    start_ctr = time.perf_counter()
    nonce_ctr, ctr_cipher = encrypt_aes_ctr(key, plaintext)
    time_ctr = time.perf_counter() - start_ctr
    
    print(f"Plaintext bytes length: {len(plaintext.encode('utf-8'))}")
    print(f"-\tAES-CBC Ciphertext length (padded): {len(cbc_cipher)} bytes")
    print(f"\tTime taken: {time_cbc:.6f} seconds")
    print(f"-\tAES-CTR Ciphertext length (unpadded): {len(ctr_cipher)} bytes")
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