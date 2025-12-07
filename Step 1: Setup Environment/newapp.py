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
    public_to_pem,
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
    users[username] = {"priv": priv, "pub": pub, "pem": public_to_pem(pub)}

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

    tampered, _ = tamper_ciphertext(ciphertext)

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



  # Phishing 

@app.route("/phishing_form", methods=["GET", "POST"])
def phishing_form():
    # If user submitted the form (POST), show warning page
    if request.method == "POST":
        return """
        <!doctype html>
        <html>
        <head>
          <meta charset='utf-8'>
          <title>You Have Been Phished!</title>
          <style>
            body {
              margin:0;
              font-family:"Segoe UI", Arial, sans-serif;
              background: radial-gradient(circle at top, #0E1628, #02030A);
              color:#E3F2FD;
              height:100vh;
              display:flex;
              align-items:center;
              justify-content:center;
              text-align:center;
            }
            .box{
              background:rgba(5,7,14,0.92);
              border:1px solid #102030;
              border-radius:16px;
              padding:40px 60px;
              box-shadow:0 0 25px rgba(30,136,229,0.25);
              max-width: 520px;
            }
            h1{color:#E53935;text-shadow:0 0 10px rgba(229,57,53,0.4);}
            p{color:#90A4AE;font-size:1.05rem;}
          </style>
        </head>
        <body>
          <div class='box'>
            <h1>🚨 YOU HAVE BEEN PHISHED! 🚨</h1>
            <p>Never enter your banking or card information on untrusted links</p>
          </div>
        </body>
        </html>
        """

    # Otherwise (GET), show the fake bank form
    return """
    <!doctype html>
    <html>
    <head>
      <meta charset='utf-8'>
      <title>Prize Claim Form</title>
      <style>
        body {
          margin: 0;
          font-family: "Segoe UI", Arial, sans-serif;
          background: radial-gradient(circle at top, #0E1628, #02030A);
          color: #E3F2FD;
          height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .box {
          background: rgba(5,7,14,0.92);
          border: 1px solid #102030;
          border-radius: 16px;
          padding: 40px 60px;
          box-shadow: 0 0 25px rgba(30,136,229,0.25);
          text-align: center;
          max-width: 420px;
        }
        h1 { color:#42A5F5; text-shadow:0 0 10px rgba(66,165,245,0.4); margin-bottom:20px; }
        label { display:block; margin:12px 0 6px; font-size:0.9rem; color:#90A4AE; text-align:left; }
        input {
          width:100%; padding:8px 10px; border-radius:8px; border:1px solid #103050;
          background:#0A0D16; color:#E3F2FD; outline:none; font-size:0.9rem;
        }
        input:focus { border-color:#42A5F5; box-shadow:0 0 0 2px rgba(66,165,245,0.3); }
        button {
          margin-top:20px; background:#42A5F5; color:#000C1A; border:none;
          padding:10px 18px; border-radius:10px; font-weight:600; cursor:pointer;
        }
        button:hover { background:#1E88E5; box-shadow:0 0 10px rgba(66,165,245,0.4); }
      </style>
    </head>
    <body>
      <div class="box">
        <h1> Claim Your Prize</h1>
        <form method="post" action="/phishing_form">
          <label>Bank Account Number (5 digits)</label>
          <input type="text" name="bank" maxlength="5" pattern="\\d{5}" required>
          <label>Security Code (3 digits)</label>
          <input type="password" name="code" maxlength="3" pattern="\\d{3}" required>
          <button type="submit">Submit</button>
        </form>
      </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(debug=True)
