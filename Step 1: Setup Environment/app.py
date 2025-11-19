# app.py  —  SINGLE FILE, READY TO RUN

import os, time, base64
from flask import Flask, render_template_string, request, redirect, url_for, flash, jsonify

# -------------------------
# Minimal DoS rate limiting
# -------------------------
import time
from collections import defaultdict
WINDOW = 10
MAX_REQUESTS = 20
_requests = defaultdict(list)

# -------------------------
# CRYPTO: AES-GCM / ECDH / ECDSA (in one file)
# -------------------------
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

KEY_SIZE = 32
NONCE_SIZE = 12

def aes_encrypt(key: bytes, plaintext: str):
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ct

def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

def ec_generate_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub

def ec_derive_aes_key(priv, peer_pub) -> bytes:
    shared = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"secure-messenger-ecdh"
    ).derive(shared)

def pub_to_pem(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")

def pem_to_pub(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))

def sign(priv, data: bytes) -> bytes:
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))

def verify(pub, sig: bytes, data: bytes) -> bool:
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# -------------------------
# ATTACK helpers in one file
# -------------------------
# Replay: remember seen nonces per receiver
_seen_nonces = defaultdict(set)
def is_replay(receiver: str, nonce: bytes) -> bool:
    if nonce in _seen_nonces[receiver]:
        return True
    _seen_nonces[receiver].add(nonce)
    return False

# Tamper: flip first bit
def tamper_ciphertext(ct: bytes) -> bytes:
    if not ct:
        return ct
    return bytes([ct[0] ^ 0x01]) + ct[1:]

# -------------------------
# Flask app + in-memory storage
# -------------------------
app = Flask(__name__)
app.secret_key = os.urandom(16)

# users: { name: {priv, pub, pem} }
users = {}
# messages: list of dict
messages = []

# -------------------------
# DoS guard
# -------------------------
@app.before_request
def dos_guard():
    ip = request.remote_addr or "unknown"
    now = time.time()
    bucket = _requests[ip]
    while bucket and now - bucket[0] > WINDOW:
        bucket.pop(0)
    if len(bucket) >= MAX_REQUESTS:
        return "Too many requests (DoS protection). Try later.", 429
    bucket.append(now)

# -------------------------
# UI (simple inline template)
# -------------------------
PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Secure Messaging (Single File)</title>
  <style>
    body{font-family:Arial;background:#f5f7fb;margin:0}
    h1{background:#283593;color:#fff;margin:0;padding:16px}
    .wrap{max-width:1000px;margin:20px auto;background:#fff;padding:16px;border-radius:8px}
    section{border-bottom:1px solid #ddd;margin-bottom:16px;padding-bottom:12px}
    .flash{padding:8px;margin:6px 0;border-radius:4px;background:#e3f2fd;color:#1565c0}
    table{width:100%;border-collapse:collapse;font-size:12px}
    th,td{border:1px solid #ccc;padding:4px;text-align:left}
    td.small{max-width:300px;word-wrap:break-word}
    button{background:#3949ab;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer}
    button:hover{background:#303f9f}
    textarea{width:100%}
    .row{display:flex;gap:8px;flex-wrap:wrap}
    input[type=text],input[type=number]{padding:6px}
  </style>
</head>
<body>
<h1>Secure Messaging – AES-GCM • ECDH • ECDSA (Single File)</h1>
<div class="wrap">

  {% with msgs = get_flashed_messages() %}
    {% if msgs %}
      {% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}
    {% endif %}
  {% endwith %}

  <section>
    <h3>1) Generate Keys</h3>
    <form method="post" action="{{ url_for('generate_keys') }}">
      <div class="row">
        <input type="text" name="username" placeholder="Alice" required>
        <button type="submit">Generate ECC keys</button>
      </div>
    </form>
    <p>Users: {% for u in users %}<b>{{u}}</b>&nbsp;{% else %}<i>none</i>{% endfor %}</p>
  </section>

  <section>
    <h3>2) Send Encrypted + Signed</h3>
    <form method="post" action="{{ url_for('send_message') }}">
      <div class="row">
        <input type="text" name="sender" placeholder="Alice" required>
        <input type="text" name="receiver" placeholder="Bob" required>
      </div>
      <p><textarea name="plaintext" rows="4" placeholder="Message..." required></textarea></p>
      <button type="submit">Encrypt, Sign & Send</button>
    </form>
  </section>

  <section>
    <h3>3) Messages</h3>
    {% if messages %}
      <table>
        <tr><th>ID</th><th>From</th><th>To</th><th>Timestamp</th><th>Nonce</th><th>Ciphertext</th></tr>
        {% for m in messages %}
          <tr>
            <td>{{m.id}}</td><td>{{m.sender}}</td><td>{{m.receiver}}</td>
            <td>{{m.timestamp}}</td>
            <td class="small">{{m.nonce}}</td>
            <td class="small">{{m.ciphertext}}</td>
          </tr>
        {% endfor %}
      </table>
    {% else %}
      <i>No messages yet</i>
    {% endif %}
  </section>

  <section>
    <h3>4) Receive & Verify</h3>
    <form method="post" action="{{ url_for('receive_message') }}">
      <div class="row">
        <input type="text" name="receiver_view" placeholder="Bob" required>
        <input type="number" name="message_id" placeholder="0" min="0" required>
        <button type="submit">Verify & Decrypt</button>
      </div>
    </form>
    <p>Includes: Replay detection, signature check, and AES-GCM integrity.</p>
  </section>

  <section>
    <h3>5) Tampering Attack</h3>
    <form method="post" action="{{ url_for('tamper_attack') }}">
      <div class="row">
        <input type="text" name="receiver_view_tamper" placeholder="Bob" required>
        <input type="number" name="tamper_id" placeholder="0" min="0" required>
        <button type="submit">Tamper & Try Decrypt</button>
      </div>
    </form>
  </section>

  <section>
    <h3>6) Phishing Demo</h3>
    <p><a href="{{ url_for('phishing_page') }}" target="_blank">Open Fake Login</a></p>
  </section>

</div>
</body>
</html>
"""

# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def home():
    return render_template_string(PAGE, users=list(users.keys()), messages=messages)

@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    username = request.form.get("username","").strip()
    if not username:
        flash("Username required")
        return redirect(url_for("home"))
    priv, pub = ec_generate_keypair()
    users[username] = {
        "priv": priv,
        "pub": pub,
        "pem": pub_to_pem(pub)
    }
    flash(f"Keys generated for {username}")
    return redirect(url_for("home"))

@app.route("/get_public_key")
def get_public_key():
    username = request.args.get("username","")
    info = users.get(username)
    if not info:
        return jsonify({"error":"user not found"}), 404
    return jsonify({"username": username, "public_key": info["pem"]})

@app.route("/send", methods=["POST"])
def send_message():
    sender = request.form.get("sender","").strip()
    receiver = request.form.get("receiver","").strip()
    plaintext = request.form.get("plaintext","")

    if sender not in users or receiver not in users:
        flash("Both sender and receiver must have keys.")
        return redirect(url_for("home"))
    if not plaintext:
        flash("Message empty.")
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

@app.route("/receive", methods=["POST"])
def receive_message():
    receiver = request.form.get("receiver_view","").strip()
    msg_id_str = request.form.get("message_id","").strip()
    if receiver not in users:
        flash("Receiver must have keys.")
        return redirect(url_for("home"))
    if not msg_id_str.isdigit() or int(msg_id_str) >= len(messages):
        flash("Invalid message id.")
        return redirect(url_for("home"))

    msg = messages[int(msg_id_str)]
    nonce = base64.b64decode(msg["nonce"])
    ciphertext = base64.b64decode(msg["ciphertext"])
    signature = base64.b64decode(msg["signature"])
    sender = msg["sender"]
    timestamp = msg["timestamp"]

    if sender not in users:
        flash("Sender keys missing.")
        return redirect(url_for("home"))

    # Replay check
    replay = is_replay(receiver, nonce)

    # Derive key and verify/decrypt
    aes_key = ec_derive_aes_key(users[receiver]["priv"], users[sender]["pub"])
    data = f"{sender}|{receiver}|{timestamp}".encode() + nonce + ciphertext
    ok_sig = verify(users[sender]["pub"], signature, data)

    status = []
    if ok_sig:
        status.append("Signature OK")
        try:
            pt = aes_decrypt(aes_key, nonce, ciphertext)
            status.append("Decryption OK")
        except Exception:
            pt = ""
            status.append("Decryption FAILED (tampered/wrong key)")
    else:
        pt = ""
        status.append("Signature FAILED")

    if replay:
        status.append("Replay detected")

    flash(f"Open msg #{msg['id']} → {' | '.join(status)}. Plaintext: {pt}")
    return redirect(url_for("home"))

@app.route("/tamper", methods=["POST"])
def tamper_attack():
    receiver = request.form.get("receiver_view_tamper","").strip()
    mid = request.form.get("tamper_id","").strip()
    if receiver not in users:
        flash("Receiver must have keys.")
        return redirect(url_for("home"))
    if not mid.isdigit() or int(mid) >= len(messages):
        flash("Invalid message id.")
        return redirect(url_for("home"))

    msg = messages[int(mid)]
    sender = msg["sender"]
    if sender not in users:
        flash("Sender keys missing.")
        return redirect(url_for("home"))

    nonce = base64.b64decode(msg["nonce"])
    ciphertext = base64.b64decode(msg["ciphertext"])
    signature = base64.b64decode(msg["signature"])

    t_ct = tamper_ciphertext(ciphertext)
    aes_key = ec_derive_aes_key(users[receiver]["priv"], users[sender]["pub"])
    data = f"{sender}|{receiver}|{msg['timestamp']}".encode() + nonce + t_ct
    ok_sig = verify(users[sender]["pub"], signature, data)

    status = []
    if not ok_sig:
        status.append("Signature FAILED (tampered)")
    else:
        status.append("Signature unexpectedly OK")

    try:
        _ = aes_decrypt(aes_key, nonce, t_ct)
        status.append("Decryption unexpectedly OK")
    except Exception:
        status.append("Decryption FAILED (as expected for tampering)")

    flash(f"Tamper msg #{msg['id']} → {' | '.join(status)}")
    return redirect(url_for("home"))

@app.route("/phishing")
def phishing_page():
    return """
    <h1>Secure Messenger - Login</h1>
    <p style="color:red;">WARNING: Fake page for phishing demo.</p>
    <form>
      <label>Username: <input type="text" name="u"></label><br>
      <label>Password: <input type="password" name="p"></label><br>
      <button type="submit">Login</button>
    </form>
    <p>Explain in your report why checking URL/TLS is important.</p>
    """

if __name__ == "__main__":
    # Run
    app.run(debug=True)
