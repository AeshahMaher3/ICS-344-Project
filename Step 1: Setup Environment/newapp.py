import os, time, base64
from flask import Flask, render_template_string, request, redirect, url_for, flash

# Import frontend class
from ui import UI

# Security modules
from dos import check_dos
from tamper import tamper_ciphertext
from replay import check_replay
from signatures import sign, verify
from ecdh import (
    aes_encrypt, aes_decrypt,
    ec_generate_keypair, ec_derive_aes_key,
    pub_to_pem,
)

# Flask setup
app = Flask(__name__)
app.secret_key = os.urandom(16)

# In-memory user + message storage
users = {}
messages = []

# DoS protection
@app.before_request
def _dos_guard():
    resp = check_dos(request)
    if resp:
        return resp

# Render homepage
@app.route("/")
def home():
    return render_template_string(UI.PAGE, messages=messages)

# Generate ECC keys for user
@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    username = request.form.get("username", "").strip()

    if not username:
        flash("Username required.")
        return redirect(url_for("home"))

    priv, pub = ec_generate_keypair()
    users[username] = {"priv": priv, "pub": pub, "pem": pub_to_pem(pub)}

    flash(f"Keys generated for {username}.")
    return redirect(url_for("home"))

# Send encrypted + signed message
@app.route("/send", methods=["POST"])
def send_message():
    sender = request.form.get("sender","").strip()
    receiver = request.form.get("receiver","").strip()
    plaintext = request.form.get("plaintext","")

    if sender not in users or receiver not in users:
        flash("Both sender and receiver must have keys.")
        return redirect(url_for("home"))

    aes_key = ec_derive_aes_key(users[sender]["priv"], users[receiver]["pub"])
    nonce, ciphertext = aes_encrypt(aes_key, plaintext)

    timestamp = int(time.time())
    data = f"{sender}|{receiver}|{timestamp}".encode() + nonce + ciphertext
    signature = sign(users[sender]["priv"], data)

    msg_id = len(messages)
    messages.append({
        "id": msg_id,
        "sender": sender,
        "receiver": receiver,
        "timestamp": timestamp,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
    })

    flash(f"Message #{msg_id} sent.")
    return redirect(url_for("home"))

# Receive/decrypt/verify
@app.route("/receive", methods=["POST"])
def receive_message():
    receiver = request.form.get("receiver_view","").strip()
    mid = request.form.get("message_id","").strip()

    if receiver not in users:
        flash("Receiver has no keys.")
        return redirect(url_for("home"))

    if not mid.isdigit() or int(mid) >= len(messages):
        flash("Invalid message ID.")
        return redirect(url_for("home"))

    msg = messages[int(mid)]
    sender = msg["sender"]

    nonce = base64.b64decode(msg["nonce"])
    ciphertext = base64.b64decode(msg["ciphertext"])
    signature = base64.b64decode(msg["signature"])

    replay, _ = check_replay(receiver, nonce)

    aes_key = ec_derive_aes_key(users[receiver]["priv"], users[sender]["pub"])

    data = f"{sender}|{receiver}|{msg['timestamp']}".encode() + nonce + ciphertext
    ok = verify(users[sender]["pub"], signature, data)

    status = []

    pt = ""

    if ok:
        try:
            pt = aes_decrypt(aes_key, nonce, ciphertext)
            msg["plaintext"] = pt   # Save decrypted text
            status.append("Decryption OK")
        except:
            status.append("Decryption FAILED")
    else:
        status.append("Signature FAILED")

    if replay:
        status.append("Replay detected")

    flash(" | ".join(status))
    return redirect(url_for("home"))

# Tampering attack
@app.route("/tamper", methods=["POST"])
def tamper_attack():
    receiver = request.form.get("receiver_view_tamper","").strip()
    mid = request.form.get("tamper_id","").strip()

    if receiver not in users:
        flash("Receiver has no keys.")
        return redirect(url_for("home"))

    if not mid.isdigit() or int(mid) >= len(messages):
        flash("Invalid message ID.")
        return redirect(url_for("home"))

    msg = messages[int(mid)]
    sender = msg["sender"]

    nonce = base64.b64decode(msg["nonce"])
    ciphertext = base64.b64decode(msg["ciphertext"])
    signature = base64.b64decode(msg["signature"])

    tampered = tamper_ciphertext(ciphertext)

    aes_key = ec_derive_aes_key(users[receiver]["priv"], users[sender]["pub"])

    data = f"{sender}|{receiver}|{msg['timestamp']}".encode() + nonce + tampered
    ok = verify(users[sender]["pub"], signature, data)

    status = []
    if not ok:
        status.append("Signature FAILED")

    try:
        aes_decrypt(aes_key, nonce, tampered)
        status.append("Decryption unexpectedly OK")
    except:
        status.append("Decryption FAILED")

    flash(" | ".join(status))
    return redirect(url_for("home"))

# Fake phishing page
@app.route("/phishing")
def phishing_page():
    return """
    <h1>Fake Login Page</h1>
    <p style='color:red;'>Phishing Demo</p>
    """

if __name__ == "__main__":
    app.run(debug=True)
