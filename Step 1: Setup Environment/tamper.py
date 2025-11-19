
# tamper.py — Simple tampering utility

def tamper_ciphertext(ct: bytes) -> bytes:
    """Flip first bit of ciphertext for demo purposes."""
    if not ct:
        return ct
    return bytes([ct[0] ^ 0x01]) + ct[1:]
