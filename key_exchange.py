from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

# Padding used to make RSA harder to break
RSA_PADDING = rsa_padding.PSS(
    mgf=rsa_padding.MGF1(hashes.SHA256()),
    salt_length=rsa_padding.PSS.MAX_LENGTH
)


# Base64 for storing to the json file
def b64_encode(data):
    return base64.b64encode(data).decode('utf-8')

def b64_decode(data_str):
    return base64.b64decode(data_str.encode('utf-8'))


#  RSA Keys
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key() # priv, pub

def sign_data(priv_key, data):
    signature = priv_key.sign(data, RSA_PADDING, hashes.SHA256())
    return signature

def verify_signature(pub_key, signature, data):
    try:
        pub_key.verify(signature, data, RSA_PADDING, hashes.SHA256())
        return True
    except:
        return False



# Diffie Hellman keys

def generate_dh_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    return private_key, private_key.public_key()

def derive_shared_aes_key(private_dh, public_dh) -> bytes:
    shared_secret = private_dh.exchange(ec.ECDH(), public_dh)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encrypted-message-handshake'
    ).derive(shared_secret)
    return derived_key



# Encode and decode keys for storing

def serialize_private_key(priv_key):
    return priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_public_key(pub_key):
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_private_key(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)

def deserialize_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)