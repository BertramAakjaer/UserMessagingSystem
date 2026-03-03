from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

# Base64 for storing to the json file
def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def b64_decode(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode('utf-8'))


#  RSA Keys
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data: bytes) -> bytes:
    signature = private_key.sign(
        data,
        rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=rsa_padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=rsa_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False



# Diffie Hellman keys

def generate_dh_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_aes_key(my_private_dh, peer_public_dh) -> bytes:
    shared_secret = my_private_dh.exchange(ec.ECDH(), peer_public_dh)
    
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