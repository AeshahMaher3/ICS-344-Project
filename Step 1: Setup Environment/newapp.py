import os, time, base64
from flask import Flask, render_template_string, request, redirect, url_for, flash

# Local security modules
from dos import check_dos
from tamper import tamper_ciphertext
from replay import check_replay
from signatures import sign, verify
from ecdh import (
    aes_encrypt, aes_decrypt,
    ec_generate_keypair, ec_derive_aes_key,
    pub_to_pem,
)

# Flask Setup
app = Flask(__name__)
app.secret_key = os.urandom(16)

users = {}       # { username: {priv, pub, pem} }
messages = []    # list of message dictionaries

# DoS Protection
@app.before_request
def _dos_guard():
    resp = check_dos(request)
    if resp is not None:
        return resp

# Frontend
PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Secure Chat</title>
  <style>
    :root {
      --bg: #05060A;
      --panel: #0C0E15;
      --blue: #42A5F5;
      --blue-strong: #1E88E5;
      --blue-glow: rgba(66,165,245,0.4);
      --text: #E3F2FD;
      --dim: #90A4AE;
    }
    body {
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: radial-gradient(circle at top, #0E1628, #02030A);
      color: var(--text);
      height: 100vh;
      display: flex;
      align-items: stretch;
      justify-content: center;
    }
    .shell {
      width: 100%;
      max-width: 1100px;
      margin: 16px;
      background: rgba(5,7,14,0.92);
      border-radius: 16px;
      display: flex;
      overflow: hidden;
      border: 1px solid #102030;
      box-shadow: 0 0 25px rgba(30,136,229,0.25);
    }
    .side {
      width: 280px;
      background: #070A12;
      padding: 18px;
      border-right: 1px solid #102030;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }
    .title {
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 10px;
      color: var(--blue);
      display: flex;
      align-items: center;
      gap: 6px;
      text-shadow: 0 0 8px var(--blue-glow);
    }
    .flash {
      background: rgba(30,136,229,0.12);
      border: 1px solid var(--blue);
      color: var(--blue);
      padding: 8px;
      border-radius: 6px;
      font-size: 0.8rem;
    }
    h3 {
      font-size: 0.85rem;
      color: var(--dim);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .card {
      background: var(--panel);
      padding: 12px;
      border-radius: 10px;
      border: 1px solid #0E2035;
    }
    input[type=text],
    input[type=number],
    textarea {
      width: 100%;
      padding: 6px 10px;
      background: #0A0D16;
      border: 1px solid #103050;
      color: var(--text);
      border-radius: 8px;
      outline: none;
      font-size: 0.85rem;
    }
    input:focus, textarea:focus {
      border-color: var(--blue);
      box-shadow: 0 0 0 2px var(--blue-glow);
    }
    textarea { resize: vertical; min-height: 50px; }
    .btn {
      background: var(--blue);
      color: #000C1A;
      border: none;
      padding: 8px 14px;
      border-radius: 999px;
      font-size: 0.8rem;
      cursor: pointer;
      font-weight: 600;
      transition: 0.15s;
    }
    .btn:hover {
      background: var(--blue-strong);
      box-shadow: 0 0 10px var(--blue-glow);
    }
    .btn.secondary {
      background: transparent;
      border: 1px solid var(--blue);
      color: var(--blue);
    }
    .btn.secondary:hover {
      background: rgba(66,165,245,0.08);
    }

    .main {
      flex: 1;
      padding: 20px;
      display: flex;
      flex-direction: column;
    }
    .chat-box {
      flex: 1;
      background: #05070D;
      border-radius: 12px;
      border: 1px solid #102030;
      padding: 12px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .bubble {
      max-width: 70%;
      padding: 10px 12px;
      border-radius: 14px;
      font-size: 0.85rem;
      line-height: 1.3;
    }
    .bubble.other {
      background: #0E1621;
      color: var(--text);
      border-left: 3px solid var(--blue);
    }
    .chat-input {
      margin-top: 10px;
      display: flex;
      gap: 10px;
      align-items: flex-end;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.75rem;
      margin-top: 10px;
    }
    th, td {
      border: 1px solid #102030;
      padding: 5px;
      text-align: left;
    }
    th {
      background: #0E1621;
      color: var(--dim);
    }
    td.small {
      max-width: 260px;
      word-wrap: break-word;
    }
  </style>
</head>

<body>
<div class="shell">

  <!-- LEFT SIDE -->
  <div class="side">
    <div class="title">Secure Messaging App</div>

    {% with msgs = get_flashed_messages() %}
      {% if msgs %}
        {% for m in msgs %}
          <div class="flash">{{ m }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <div class="card">
      <h3>Generate Keys</h3>
      <form method="post" action="{{ url_for('generate_keys') }}">
        <input type="text" name="username" placeholder="Username" required>
        <button class="btn" type="submit">Generate</button>
      </form>
    </div>

    <div class="card">
      <h3>Receive</h3>
      <form method="post" action="{{ url_for('receive_message') }}">
        <input type="text" name="receiver_view" placeholder="Receiver" required>
        <input type="number" name="message_id" placeholder="ID" min="0" required>
        <button class="btn secondary" type="submit">Open</button>
      </form>
    </div>

    <div class="card">
      <h3>Tamper</h3>
      <form method="post" action="{{ url_for('tamper_attack') }}">
        <input type="text" name="receiver_view_tamper" placeholder="Receiver" required>
        <input type="number" name="tamper_id" placeholder="ID" min="0" required>
        <button class="btn secondary" type="submit">Tamper</button>
      </form>
    </div>

    <div class="card">
      <h3>Phishing</h3>
      <a href="{{ url_for('phishing_page') }}" style="color:var(--blue);text-decoration:none;">
        Open Fake Login →
      </a>
    </div>
  </div>

  <!-- RIGHT SIDE -->
  <div class="main">

    <!-- Messages -->
    <div class="chat-box">
      {% if messages %}
        {% for m in messages %}
        <div class="bubble other">
          <b>#{{m.id}}</b> {{m.sender}} → {{m.receiver}}<br>
          <small style="color:var(--dim);">nonce:</small> {{m.nonce}}<br>
          <small style="color:var(--dim);">cipher:</small> {{m.ciphertext}}
        </div>
        {% endfor %}
      {% else %}
        <div style="color:var(--dim);margin:auto;">No messages yet.</div>
      {% endif %}
    </div>

    <!-- Send -->
    <form method="post" action="{{ url_for('send_message') }}">
      <div class="chat-input">
        <input type="text" name="sender" placeholder="Sender" required style="max-width:120px;">
        <input type="text" name="receiver" placeholder="Receiver" required style="max-width:120px;">
        <textarea name="plaintext" placeholder="Type message..." required></textarea>
        <button class="btn" type="submit">Send</button>
      </div>
    </form>

    <!-- Raw Table -->
    <table>
      <tr><th>ID</th><th>From</th><th>To</th><th>Timestamp</th><th>Nonce</th><th>Ciphertext</th></tr>
      {% for m in messages %}
      <tr>
        <td>{{m.id}}</td>
        <td>{{m.sender}}</td>
        <td>{{m.receiver}}</td>
        <td>{{m.timestamp}}</td>
        <td class="small">{{m.nonce}}</td>
        <td class="small">{{m.ciphertext}}</td>
      </tr>
      {% endfor %}
    </table>

  </div>

</div>
</body>
</html>
"""

# Routes
@app.route("/")
def home():
    return render_template_string(PAGE, users=users.keys(), messages=messages)

@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    username = request.form.get("username","").strip()
    if not username:
        flash("Username required.")
        return redirect(url_for("home"))
    priv, pub = ec_generate_keypair()
    users[username] = {"priv": priv, "pub": pub, "pem": pub_to_pem(pub)}
    flash(f"Keys generated for {username}.")
    return redirect(url_for("home"))

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
    timestamp = msg["timestamp"]

    replay, _ = check_replay(receiver, nonce)

    aes_key = ec_derive_aes_key(users[receiver]["priv"], users[sender]["pub"])
    data = f"{sender}|{receiver}|{timestamp}".encode() + nonce + ciphertext
    ok = verify(users[sender]["pub"], signature, data)

    status = []
    if ok:
        try:
            pt = aes_decrypt(aes_key, nonce, ciphertext)
            status.append(f"Decrypted: {pt}")
        except:
            status.append("Decryption FAILED")
    else:
        status.append("Signature FAILED")

    if replay:
        status.append("Replay detected")

    flash(" | ".join(status))
    return redirect(url_for("home"))

@app.route("/tamper", methods=["POST"])
def tamper_attack():
    receiver = request.form.get("receiver_view_tamper","").strip()
    mid = request.form.get("tamper_id","").strip()

    if receiver not in users:
        flash("Receiver has no keys.")
        return redirect(url_for("home"))

    if not mid.isdigit() or int(mid) >= len(messages):
        flash("Invalid ID.")
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

@app.route("/phishing")
def phishing_page():
    return """
    <h1 style='font-family:Segoe UI;'>Fake Secure Chat Login</h1>
    <p style='color:red;'>This is a phishing simulation.</p>
    <form>
        Username: <input><br><br>
        Password: <input type='password'><br><br>
        <button>Login</button>
    </form>
    """

if __name__ == "__main__":
    app.run(debug=True)
