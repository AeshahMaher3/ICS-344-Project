def tamper_ciphertext(ciphertext): # this function is used to test tampering

    if not ciphertext: # if there is no ciphertext, nothing to modify
        return ciphertext, "No tampering applied"
    

    modified_byte = ciphertext[0] ^ 0x01  # flip one bit in the first byte using XOR
    modified_ciphertext = bytes([modified_byte]) + ciphertext[1:]  # then add the rest of the bytes back
 
    return modified_ciphertext, "Tampering applied"
 
