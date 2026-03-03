import database as db
import hashing as hash
import encryption as encypt
import key_exchange as key_ex

import time

def register():
    print("\n**Register**")
    username = input("Enter username: ")
    
    users: dict[str, dict] = db.load_users()
    
    if username in users:
        print("User already exists!")
        return

    password = input("Enter password: ")
    bcrypt_hash, sha_hash = hash.hashing_with_both(password)

    # new keys for user
    rsa_priv, rsa_pub = key_ex.generate_rsa_keypair() # signing
    dh_priv, dh_pub = key_ex.generate_dh_keypair() # shared secret

    users[username] = {
        "bcrypt_hash": bcrypt_hash,
        "sha_256_hash": sha_hash,
        "rsa_private": key_ex.b64_encode(key_ex.serialize_private_key(rsa_priv)), # wouldn't normally be kept in databse but in local storage for owner
        "rsa_public": key_ex.b64_encode(key_ex.serialize_public_key(rsa_pub)),
        "dh_private": key_ex.b64_encode(key_ex.serialize_private_key(dh_priv)), # wouldn't normally be kept in databse but in local storage for owner
        "dh_public": key_ex.b64_encode(key_ex.serialize_public_key(dh_pub))
    }
    db.save_users(users)
    print("Registration successful!")



def login():
    print("\n**Login**")
    username = input("Username: ")
    users = db.load_users()

    if username not in users:
        print("User not found.")
        return None

    password = input("Password: ")
    
    # Using both hashes and verifying
    is_valid = hash.verify_with_both(password, users[username]["bcrypt_hash"], users[username]["sha_256_hash"])

    if is_valid:
        print(f"Welcome, {username}!")
        return username
    else:
        print("Invalid password !!")
        return None




def send_message(sender_username):
    users = db.load_users()
    recipient = input("Enter recipient username: ")
    if recipient not in users:
        print("Recipient not found.")
        return

    plaintext = input("Enter secret message: ")
    
    # RSA for signing
    sender_rsa_priv = key_ex.deserialize_private_key(key_ex.b64_decode(users[sender_username]["rsa_private"]))
    
    # Recievers public key (DH)
    recipient_dh_pub = key_ex.deserialize_public_key(key_ex.b64_decode(users[recipient]["dh_public"]))
    
    # Own private key (DH)
    sender_dh_priv = key_ex.deserialize_private_key(key_ex.b64_decode(users[sender_username]["dh_private"]))


    # Generating a shared secret for aes encryption
    aes_key = key_ex.derive_shared_aes_key(sender_dh_priv, recipient_dh_pub)

    # Encrypting with both CBC and CTR
    iv_cbc, cbc_cipher, nonce_ctr, ctr_cipher = encypt.encrypt_with_both(aes_key, plaintext)

    # Signing the data to prove integrity and sender
    cbc_signature = key_ex.sign_data(sender_rsa_priv, cbc_cipher)
    ctr_signature = key_ex.sign_data(sender_rsa_priv, ctr_cipher)
    
    message_packet = {
        "sender": sender_username,
        "recipient": recipient,
        "cbc_signature": key_ex.b64_encode(cbc_signature),
        "ctr_signature": key_ex.b64_encode(ctr_signature),
        "cbc_iv": key_ex.b64_encode(iv_cbc),
        "cbc_ciphertext": key_ex.b64_encode(cbc_cipher),
        "ctr_nonce": key_ex.b64_encode(nonce_ctr),
        "ctr_ciphertext": key_ex.b64_encode(ctr_cipher)
    }

    db.save_message(message_packet)
    print("Message encrypted and sent !!")





def read_messages(username):
    messages = db.load_messages()
    users = db.load_users()
    
    # Getting all messages for this user
    my_messages = [m for m in messages if m["recipient"] == username]
    if not my_messages:
        print("No new messages.")
        return

    # Getting the private DH key for finding the shared secret used for encryption
    my_dh_priv = key_ex.deserialize_private_key(key_ex.b64_decode(users[username]["dh_private"]))

    # For each message
    for idx, msg in enumerate(my_messages):
        
        sender = msg["sender"]
        print(f"\nMessage {idx+1} from {sender}:")
        
        # Get senders public keys
        sender_rsa_pub = key_ex.deserialize_public_key(key_ex.b64_decode(users[sender]["rsa_public"]))
        sender_dh_pub = key_ex.deserialize_public_key(key_ex.b64_decode(users[sender]["dh_public"]))
        
        
        cbc_signature = key_ex.b64_decode(msg["cbc_signature"])
        ctr_signature = key_ex.b64_decode(msg["ctr_signature"])
        cbc_cipher = key_ex.b64_decode(msg["cbc_ciphertext"])
        ctr_cipher = key_ex.b64_decode(msg["ctr_ciphertext"])
        
        
        print("\n**Verify Signatures**")
        start_cbc = time.perf_counter()
        cbc_valid = key_ex.verify_signature(sender_rsa_pub, cbc_signature, cbc_cipher)
        time_cbc = time.perf_counter() - start_cbc
        
        start_ctr = time.perf_counter()
        ctr_valid = key_ex.verify_signature(sender_rsa_pub, ctr_signature, ctr_cipher)
        time_ctr = time.perf_counter() - start_ctr
        
        print(f"-\tAES-CBC Signature Verification Time: {time_cbc:.6f} seconds (Passed: {cbc_valid})")
        print(f"-\tAES-CTR Signature Verification Time: {time_ctr:.6f} seconds (Passed: {ctr_valid})")
        print("-" * 41 + "\n")
        
        
        if not (cbc_valid and ctr_valid):
            print("Panic: Signature failed, data can be tampered with !!")
            continue
        print("Both signatures verified !!")

        # Using DH to get the shared secret used for AES encryption
        aes_key = key_ex.derive_shared_aes_key(my_dh_priv, sender_dh_pub)

        # Getting the nonce(CTR) and IV(CBC) used for making different outputs, for same input
        iv_cbc = key_ex.b64_decode(msg["cbc_iv"])
        nonce_ctr = key_ex.b64_decode(msg["ctr_nonce"])

        try:
            encypt.decrypt_with_both(aes_key, iv_cbc, cbc_cipher, nonce_ctr, ctr_cipher)
        except Exception as e:
            print(f"Failed to decrypt: {e}")




def main():
    current_user = None
    while True:
        if not current_user:
            print("\n1. Register\n2. Login\n3. Exit")
            choice = input("Choice: ")
            if choice == '1': register()
            elif choice == '2': current_user = login()
            elif choice == '3': break
        else:
            print(f"\nLogged in as: {current_user}")
            print("1. Send Message\n2. Read Messages\n3. Logout")
            choice = input("Choice: ")
            if choice == '1': send_message(current_user)
            elif choice == '2': read_messages(current_user)
            elif choice == '3': current_user = None

if __name__ == "__main__":
    main()