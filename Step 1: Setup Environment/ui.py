class UI:
    PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Secure Chat</title>

  <style>
    /* Colors */
    :root {
      --bg: #05060A;
      --panel: #0C0E15;
      --blue: #42A5F5;
      --blue-strong: #1E88E5;
      --blue-glow: rgba(66,165,245,0.5);
      --text: #E3F2FD;
      --dim: #90A4AE;
    }

    /* Layout and styling */
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

    /* Left side panel */
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
      text-shadow: 0 0 8px var(--blue-glow);
    }

    .flash {
      background: rgba(30,136,229,0.12);
      border: 1px solid var(--blue);
      color: var(--blue);
      padding: 8px;
      border-radius: 6px;
      font-size: 0.8rem;
      animation: fadeIn 0.4s ease-out;
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
      font-size: 0.85rem;
    }
    textarea { resize: vertical; }

    .btn {
      background: var(--blue);
      color: #000C1A;
      padding: 8px 14px;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      font-weight: 600;
      box-shadow: 0 0 10px transparent;
      transition: 0.2s ease;
    }
    .btn:hover {
      background: var(--blue-strong);
      box-shadow: 0 0 12px var(--blue-glow);
    }
    .btn.secondary {
      background: transparent;
      border: 1px solid var(--blue);
      color: var(--blue);
    }

    /* Main chat area */
    .main {
      flex: 1;
      padding: 20px;
      display: flex;
      flex-direction: column;
    }

    .chat-box {
      flex: 1;
      background: #05070D;
      padding: 12px;
      border-radius: 12px;
      border: 1px solid #102030;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 15px;
    }

    /* Message bubbles */
    .bubble {
      max-width: 70%;
      padding: 12px 14px;
      border-radius: 14px;
      background: #0E1621;
      color: var(--text);
      border-left: 3px solid var(--blue);
      font-size: 0.9rem;
      animation: slideIn 0.45s ease-out;
    }

    /* Metadata */
    .meta-info {
      margin-left: 6px;
      font-size: 0.75rem;
      color: var(--dim);
      line-height: 1.4;
      animation: fadeIn 0.6s ease-out;
    }

    /* Animations */
    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateX(-25px);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to   { opacity: 1; }
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
      <form method="post" action="{{ url_for('generate_keys') }}">
        <input type="text" name="username" placeholder="Username" required>
        <button class="btn" type="submit">Generate Keys</button>
      </form>
    </div>

    <div class="card">
      <form method="post" action="{{ url_for('receive_message') }}">
        <input type="text" name="receiver_view" placeholder="Receiver" required>
        <input type="number" name="message_id" placeholder="Message ID" min="0" required>
        <button class="btn secondary" type="submit">Open</button>
      </form>
    </div>

    <div class="card">
      <form method="post" action="{{ url_for('tamper_attack') }}">
        <input type="text" name="receiver_view_tamper" placeholder="Receiver" required>
        <input type="number" name="tamper_id" placeholder="Message ID" min="0" required>
        <button class="btn secondary" type="submit">Tamper</button>
      </form>
    </div>

    <div class="card">
      <a href="{{ url_for('phishing_form') }}" style="color:var(--blue); text-decoration:none;">
        Share and Win! 
      </a>

      <img src="https://cdn.corporatefinanceinstitute.com/assets/money-2.jpeg"
       class="phishing-img">
    </div>

<style>
  .phishing-img {
    width: 100%;
    border-radius: 10px;
    box-shadow: 0 0 12px rgba(66,165,245,0.3);
    animation: pulseGlow 2.2s ease-in-out infinite;
  }

  @keyframes pulseGlow {
    0% {
      box-shadow: 0 0 10px rgba(66,165,245,0.25);
      transform: scale(1);
    }
    50% {
      box-shadow: 0 0 16px rgba(66,165,245,0.45);
      transform: scale(1.03);
    }
    100% {
      box-shadow: 0 0 10px rgba(66,165,245,0.25);
      transform: scale(1);
    }
  }
</style>


  </div>

  <!-- RIGHT SIDE -->
  <div class="main">
    <div class="chat-box">

      {% if messages %}
        {% for m in messages %}

          <!-- Bubble -->
          <div class="bubble">
              <b>{{m.sender}}</b> → {{m.receiver}}<br>

              {% if m.plaintext %}
              <div style="margin-top:8px; font-size:1rem; color:white;">
                  {{m.plaintext}}
              </div>
              {% else %}
              <div style="margin-top:6px; font-size:0.9rem; color:var(--dim);">
                  (Encrypted - open to decrypt)
              </div>
              {% endif %}
          </div>

          <!-- Metadata -->
          <div class="meta-info">
              <b>#{{m.id}}</b><br>
              <small>nonce:</small> {{m.nonce}}<br>
              <small>cipher:</small> {{m.ciphertext}}
          </div>

        {% endfor %}
      {% else %}
        <div style="color:var(--dim);margin:auto;">No messages yet.</div>
      {% endif %}

    </div>

    <!-- SEND FORM -->
    <form method="post" action="{{ url_for('send_message') }}">
      <div style="display:flex; gap:10px; margin-top:10px;">
        <input type="text" name="sender" placeholder="Sender" required style="max-width:120px;">
        <input type="text" name="receiver" placeholder="Receiver" required style="max-width:120px;">
        <textarea name="plaintext" placeholder="Type message..." required></textarea>
        <button class="btn" type="submit">Send</button>
      </div>
    </form>

  </div>

</div>
</body>
</html>
"""
