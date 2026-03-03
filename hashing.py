import bcrypt
import hashlib
import time


# Bcrypt
def hash_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_bcrypt(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


# SHA256
def hash_sha256_no_salt(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_sha256(password: str, hashed: str) -> bool:
    new_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return new_hash == hashed




def hashing_with_both(password: str) -> tuple[str, str]:
    print("\n--- Hashing Comparison (Making) ---")
    
    start_sha = time.perf_counter()
    sha_hash = hash_sha256_no_salt(password)
    time_sha = time.perf_counter() - start_sha
    
    start_bc = time.perf_counter()
    bc_hash = hash_bcrypt(password)
    time_bc = time.perf_counter() - start_bc
    
    print(f"Plaintext Password length: {len(password)} characters")
    print(f"-\tSHA-256 (No Salt): {sha_hash}")
    print(f"\tLength: {len(sha_hash)} characters")
    print(f"\tTime taken: {time_sha:.6f} seconds")
    print(f"-\tbcrypt (Salted):   {bc_hash}")
    print(f"\tLength: {len(bc_hash)} characters")
    print(f"\tTime taken: {time_bc:.6f} seconds")
    print("-" * 40 + "\n")
    
    return (bc_hash, sha_hash)


def verify_with_both(password: str, bc_hash: str, sha_hash: str) -> bool:
    print("\n--- Hashing Comparison (Verifying) ---")
    
    start_sha = time.perf_counter()
    sha_valid = verify_sha256(password, sha_hash)
    time_sha = time.perf_counter() - start_sha
    
    start_bc = time.perf_counter()
    bc_valid = verify_bcrypt(password, bc_hash)
    time_bc = time.perf_counter() - start_bc

    print(f"-\tSHA-256 Verification Time: {time_sha:.6f} seconds (Passed: {sha_valid})")
    print(f"-\tbcrypt Verification Time:   {time_bc:.6f} seconds (Passed: {bc_valid})")
    print("-" * 40 + "\n")
    
    return sha_valid and bc_valid