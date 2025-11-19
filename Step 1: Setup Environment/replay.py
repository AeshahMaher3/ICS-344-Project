# replay.py — Replay detection using seen nonces per receiver

from collections import defaultdict

_seen_nonces = defaultdict(set)  # receiver -> {nonce_bytes}

def is_replay(receiver: str, nonce: bytes) -> bool:
    if nonce in _seen_nonces[receiver]:
        return True
    _seen_nonces[receiver].add(nonce)
    return False
