import os # used to create random nonce values
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # AES-GCM ready to use implementation
from cryptography.hazmat.primitives.asymmetric import ec # elliptic curve functions
from cryptography.hazmat.primitives.kdf.hkdf import HKDF # HKDF is used to turn the ECDH shared secret into a clean AES key
from cryptography.hazmat.primitives import hashes # hashes are used inside HKDF 
from cryptography.hazmat.primitives import serialization # serialization is used to convert public keys to/from PEM text

KEY_SIZE = 32     # 256-bit AES key
NONCE_SIZE = 12   # Recommended size for AES-GCM

def aes_encrypt(key, plaintext):  # encrypt text using AES-GCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)  # random nonce for each encryption
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext


def aes_decrypt(key, nonce, ciphertext):  # decrypt and verify AES-GCM ciphertext
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def ec_generate_keypair():  # generate EC private/public key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def ec_derive_aes_key(private_key, peer_public_key):  # derive AES key from ECDH + HKDF
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)  # combine private + peer public
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"secure-messenger-ecdh" # This is just a label so HKDF knows this key is for our secure messenger
    ).derive(shared_secret)


def public_to_pem(public_key):  # convert a public key to PEM text
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  # standard PEM format
    )
    return pem.decode("utf-8")


def pem_to_public(pem_str):  # load a public key back from PEM text
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))  # convert PEM text back to key object
