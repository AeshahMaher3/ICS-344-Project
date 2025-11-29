def tamper_ciphertext(ciphertext: bytes): # this function is used to test tampering

    if not ciphertext: # check if ciphertext is empty
        return ciphertext, "No tampering applied"
    

    modified_byte = ciphertext[0] ^ 0x01  # take the first byte, flip its first bit using XOR, then add the rest of the bytes back
    modified_ciphertext = bytes([modified_byte]) + ciphertext[1:]  
 
    return modified_ciphertext, "Tampering applied"
 
