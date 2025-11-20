from collections import defaultdict

nonce_history = defaultdict(set)  # Stores nonce for each reciever

def check_replay(receiver, nonce):  # A function to check for replay attacks
    # Check if the nonce has been seen before
    if nonce in nonce_history[receiver]:
        return True, "Replay attack detected."
    
    # If not seen the  store the nonce
    nonce_history[receiver].add(nonce)
    return False, "No replay detected."
