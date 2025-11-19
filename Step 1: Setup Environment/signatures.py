
# signatures.py — ECDSA sign/verify helpers

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def sign(priv, data: bytes) -> bytes:
    """Sign data with ECDSA (SHA-256)."""
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))

def verify(pub, sig: bytes, data: bytes) -> bool:
    """Verify ECDSA signature; return True on success, False otherwise."""
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
