
# ecdh.py — ECDH key agreement + AES-GCM wrappers + PEM helpers

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

KEY_SIZE = 32     # 256-bit AES
NONCE_SIZE = 12   # Recommended size for AES-GCM

def aes_encrypt(key: bytes, plaintext: str):
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ct

def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

def ec_generate_keypair():
    """Generate an EC keypair on SECP256R1 (P-256)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub

def ec_derive_aes_key(priv, peer_pub) -> bytes:
    """Perform ECDH and derive an AES key via HKDF-SHA256."""
    shared = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None, info=b"secure-messenger-ecdh"
    ).derive(shared)

def pub_to_pem(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")

def pem_to_pub(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))
