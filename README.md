# ICS-344:Information Security-Project
Cryptography in Action – Secure Messaging App (with GUI)
A secure messaging web application built using **Python** and **Flask**.  
The system applies cryptographic primitives to demonstrate secure communication and common cyber-attack simulations.

## Authors
- Jude Alharbi - 202223700
- Aeshah Almahmoud - 202167070

### **1. Key Generation (ECDH – ECC)**
Users can generate an elliptic-curve private/public key pair.  
Public keys are stored and later used for secure key exchange.

### **2. Secure Messaging**
- A shared AES key is derived using **ECDH**
- Messages are encrypted using **AES-GCM**
- Message metadata is signed using **ECDSA**
- Messages are stored with nonce, ciphertext, timestamp and signature

### **3. Message Verification & Decryption**
When opening a message:
- Signature is verified (ECDSA)
- Replay attack detection occurs (nonce tracking)
- AES key is derived
- Message is decrypted and displayed in the chat UI

### **4. Attack Simulations**
#### 🔸 **Tampering Attack**
Ciphertext is intentionally modified.  
The system detects changes because:
- Signature validation fails  
- AES-GCM decryption fails  

#### 🔸 **Replay Attack**
Reopening the same message triggers:
- “Replay detected”

This demonstrates protection against message reuse.

#### 🔸 **Phishing Simulation**
A fake login page demonstrates how users can be tricked.  
Submitting credentials displays:
- “YOU HAVE BEEN PHISHED!”

#### *5. Denial of Service (DoS) Protection**
A request rate limiter blocks excessive requests from the same IP.

## **Graphical User Interface**
The UI is implemented fully inside `ui.py` using HTML/CSS.  
It includes:
- A messenger-style chat window  
- Message bubbles  
- Metadata panel (nonce, cipher, ID)  
- Key generation panel  
- Receive & tamper controls  

