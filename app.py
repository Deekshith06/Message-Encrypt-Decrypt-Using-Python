"""
Message Encrypt / Decrypt 
Python + Streamlit + cryptography (Fernet)
"""

import streamlit as st
import streamlit.components.v1 as components
from cryptography.fernet import Fernet, InvalidToken
import base64, hashlib, urllib.parse

st.set_page_config(page_title="Message Encrypt / Decrypt", layout="centered")
st.markdown("<style>.block-container{max-width:680px;padding-top:2rem}</style>", unsafe_allow_html=True)

# ── Constants ────────────────────────────────────────────────────────────
MESSAGE_TTL = 300  # 5-minute expiry on every encrypted message

# ── Core crypto ──────────────────────────────────────────────────────────
def generate_key():
    return Fernet.generate_key().decode()

def passphrase_to_key(phrase):
    return base64.urlsafe_b64encode(hashlib.sha256(phrase.encode()).digest()).decode()

def is_valid_key(key):
    try:
        return len(base64.urlsafe_b64decode(key.encode())) == 32
    except Exception:
        return False

def encrypt_message(msg, key):
    return Fernet(key.encode()).encrypt(msg.encode()).decode()

def decrypt_message(token, key):
    return Fernet(key.encode()).decrypt(token.strip().encode(), ttl=MESSAGE_TTL).decode()

# ── Combined token: key + ciphertext merged into one Base64 blob ─────────
def make_combined_token(key, ciphertext):
    raw = base64.urlsafe_b64decode(key.encode()) + base64.urlsafe_b64decode(ciphertext.encode())
    return base64.urlsafe_b64encode(raw).decode()

def parse_combined_token(token):
    try:
        raw = base64.urlsafe_b64decode(token.strip().encode())
        if len(raw) < 33:
            return "", ""
        return (base64.urlsafe_b64encode(raw[:32]).decode(),
                base64.urlsafe_b64encode(raw[32:]).decode())
    except Exception:
        return "", ""

def is_combined_token(text):
    t = text.strip()
    if "Encrypted Message:" in t or "Secret Key:" in t:
        return False
    try:
        return len(base64.urlsafe_b64decode(t.encode())) >= 33
    except Exception:
        return False

# ── UI helpers ───────────────────────────────────────────────────────────
def copy_button(text):
    safe = text.replace("\\", "\\\\").replace("`", "\\`")
    components.html(f"""
    <button id="cb" onclick="navigator.clipboard.writeText(`{safe}`).then(()=>{{
        document.getElementById('cb').innerText='Copied!';
        setTimeout(()=>document.getElementById('cb').innerText='Copy to Clipboard',2000)}})"
    style="background:#333;color:#e0e0e0;border:1px solid #555;border-radius:4px;
           padding:6px 16px;font-size:14px;cursor:pointer">Copy to Clipboard</button>
    """, height=50, scrolling=False)

def whatsapp_button(token):
    url = f"https://api.whatsapp.com/send?text={urllib.parse.quote(token)}"
    components.html(f"""
    <a href="{url}" target="_blank"
       style="display:inline-block;padding:6px 16px;background:#25D366;color:#fff;
              border-radius:4px;font-size:14px;text-decoration:none">Share on WhatsApp</a>
    """, height=50, scrolling=False)

# ════════════════════════════════ UI ════════════════════════════════════
st.markdown("# Message Encrypt / Decrypt")
st.write("Symmetric encryption — Fernet (AES-128-CBC + HMAC-SHA256) · 5-min expiry")
st.divider()

# Step 1 — Operation
operation = st.selectbox("Operation", ["Encrypt", "Decrypt"])
st.divider()

# Step 2 — Paste from WhatsApp (Decrypt only, shown before Key so key can be auto-filled)
if operation == "Decrypt":
    st.markdown("""
    <style>
    details[data-testid="stExpander"] summary {
        background: linear-gradient(90deg, #1a472a, #25D366) !important;
        border-radius: 8px !important;
        color: #ffffff !important;
        font-weight: 600 !important;
    }
    details[data-testid="stExpander"] summary svg {
        fill: #ffffff !important;
    }
    </style>
    """, unsafe_allow_html=True)
    with st.expander("💬 Paste from WhatsApp"):
        wa_paste = st.text_area("Paste the message here:",
                                placeholder="Paste the combined token or 'Encrypted Message: ...'",
                                height=140, key="wa_paste_area")
        if st.button("Parse & Auto-fill"):
            text = wa_paste.strip()
            pkey, pct = "", ""
            if is_combined_token(text):
                pkey, pct = parse_combined_token(text)
            elif "Encrypted Message:" in text:
                pct = text.split("Encrypted Message:", 1)[1].strip()
                if "Secret Key:" in text:
                    pkey = text.split("Secret Key:", 1)[1].split("Encrypted Message:", 1)[0].strip()
            if pct:
                if pkey:
                    st.session_state["key_override"] = pkey
                st.session_state.update({"parsed_ct": pct, "auto_submit": True})
                st.session_state.pop("result", None)
                st.rerun()
            else:
                st.error("Could not parse. Paste a valid combined token or 'Encrypted Message:' text.")

# Step 3 — Key
st.subheader("Key")

if operation == "Encrypt":
    mode = st.radio("Key source:", ["Auto-generate key", "Use custom passphrase"], horizontal=True)
    if mode == "Auto-generate key":
        if "gen_key" not in st.session_state:
            st.session_state["gen_key"] = generate_key()
        if st.button("Generate New Key"):
            st.session_state["gen_key"] = generate_key()
        key_input = st.text_input("Secret Key (auto-generated)", value=st.session_state["gen_key"])
        st.caption("Share this key via a separate channel — never alongside the encrypted message.")
        active_key = key_input.strip()
    else:
        phrase = st.text_input("Passphrase", placeholder="Agree on this with the recipient", type="password")
        st.caption("Both sides must use the same passphrase. Nothing is transmitted.")
        active_key = passphrase_to_key(phrase) if phrase.strip() else ""
else:
    mode = st.radio("Key source:", ["Paste key", "Use passphrase"], horizontal=True)
    if mode == "Paste key":
        # Pre-fill key if Parse & Auto-fill extracted one
        pre_key = st.session_state.pop("key_override", "")
        key_input = st.text_input("Secret Key", value=pre_key,
                                  placeholder="Paste the key received separately")
        active_key = key_input.strip()
    else:
        st.session_state.pop("key_override", None)  # discard if switching to passphrase
        phrase = st.text_input("Passphrase", placeholder="Enter the agreed passphrase", type="password")
        active_key = passphrase_to_key(phrase) if phrase.strip() else ""

# Step 4 — Input
st.subheader("Input")

default_ct = st.session_state.pop("parsed_ct", "") if operation == "Decrypt" else ""
if "key_override" in st.session_state and operation == "Decrypt":
    active_key = st.session_state.pop("key_override")

message_input = st.text_area(
    "Message" if operation == "Encrypt" else "Ciphertext",
    value=default_ct,
    placeholder="Enter plaintext to encrypt" if operation == "Encrypt" else "Paste ciphertext to decrypt",
    height=140,
)

submit = st.button("Submit")
if st.session_state.pop("auto_submit", False):
    submit = True
st.divider()

# Step 4 — Result
st.subheader("Result")

if submit:
    if not active_key:
        st.error("No key provided.")
    elif not is_valid_key(active_key):
        st.error("Invalid key. Check the key or passphrase.")
    elif not message_input.strip():
        st.error("Input cannot be empty.")
    else:
        if operation == "Encrypt":
            try:
                st.session_state["result"] = encrypt_message(message_input, active_key)
                st.session_state["result_key"] = active_key
                st.session_state["result_label"] = "Encrypted ciphertext"
            except Exception as e:
                st.error(f"Encryption error: {e}")
        else:
            try:
                st.session_state["result"] = decrypt_message(message_input, active_key)
                st.session_state["result_label"] = "Decrypted message"
            except InvalidToken:
                st.error(f"Decryption failed — message expired (valid for {MESSAGE_TTL//60} min) or wrong key.")
                st.session_state.pop("result", None)
            except Exception as e:
                st.error(f"Decryption error: {e}")
                st.session_state.pop("result", None)

if "result" in st.session_state:
    st.write(st.session_state.get("result_label", "Output") + ":")
    st.text_area("", value=st.session_state["result"], height=120, key="result_textarea")

    if operation == "Encrypt":
        combined = make_combined_token(st.session_state["result_key"], st.session_state["result"])
        st.write("Combined token (key + message merged — safe to share as one string):")
        st.text_area("", value=combined, height=80, key="combined_display")
        col1, col2 = st.columns(2)
        with col1:
            copy_button(combined)
        with col2:
            whatsapp_button(combined)
        st.caption("The token looks random — key and message are indistinguishable without the app.")
else:
    st.write("Output will appear here after you click Submit.")

st.divider()
st.caption("Message Encrypt / Decrypt  |  2024-25")
