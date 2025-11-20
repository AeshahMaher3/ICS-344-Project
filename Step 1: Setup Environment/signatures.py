from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Create a digital signature for the data using a private key
def sign(private, data):
    return private.sign(data, ec.ECDSA(hashes.SHA256())) # Sign the data with ECDSA and SHA-256

def verify(public, signature, data):
    # Try to verify the signature with the specified public key
    try:
        public.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    
    # If verification fails, return false
    except Exception:
        return False
    
