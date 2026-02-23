"""Message Encrypt / Decrypt — Streamlit + Fernet (AES-128-CBC + HMAC-SHA256)"""

import streamlit as st
import streamlit.components.v1 as components
from cryptography.fernet import Fernet, InvalidToken
import base64, hashlib, urllib.parse

st.set_page_config(page_title="Message Encrypt / Decrypt", layout="centered")

# ── Global polish ─────────────────────────────────────────────────────────
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.block-container { max-width: 680px; padding-top: 2rem; }
textarea, input[type="text"], input[type="password"] {
    border-radius: 8px !important; font-size: 14px !important; }
div[data-testid="stTextArea"] textarea:focus,
div[data-testid="stTextInput"] input:focus { border-color: #25D366 !important; box-shadow: 0 0 0 2px rgba(37,211,102,.2) !important; }
div[data-testid="stButton"] > button {
    border-radius: 8px !important; font-weight: 600 !important; transition: opacity .2s; }
div[data-testid="stButton"] > button:hover { opacity: .85; }
</style>""", unsafe_allow_html=True)

MESSAGE_TTL = 300

# ── Crypto helpers ────────────────────────────────────────────────────────
def generate_key():
    return Fernet.generate_key().decode()

def passphrase_to_key(phrase):
    return base64.urlsafe_b64encode(hashlib.sha256(phrase.encode()).digest()).decode()

def is_valid_key(key):
    try:    return len(base64.urlsafe_b64decode(key.encode())) == 32
    except: return False

def encrypt_message(msg, key):
    return Fernet(key.encode()).encrypt(msg.encode()).decode()

def decrypt_message(token, key):
    return Fernet(key.encode()).decrypt(token.strip().encode(), ttl=MESSAGE_TTL).decode()

def make_combined_token(key, ciphertext):
    raw = base64.urlsafe_b64decode(key.encode()) + base64.urlsafe_b64decode(ciphertext.encode())
    return base64.urlsafe_b64encode(raw).decode()

def parse_combined_token(token):
    try:
        raw = base64.urlsafe_b64decode(token.strip().encode())
        if len(raw) < 33: return "", ""
        return (base64.urlsafe_b64encode(raw[:32]).decode(),
                base64.urlsafe_b64encode(raw[32:]).decode())
    except: return "", ""

def is_combined_token(text):
    t = text.strip()
    if "Encrypted Message:" in t or "Secret Key:" in t: return False
    try:    return len(base64.urlsafe_b64decode(t.encode())) >= 33
    except: return False

# ── UI helpers ────────────────────────────────────────────────────────────
def copy_button(text):
    safe = text.replace("\\", "\\\\").replace("`", "\\`")
    components.html(f"""<button id="cb" onclick="navigator.clipboard.writeText(`{safe}`).then(()=>{{
        document.getElementById('cb').innerText='Copied!';
        setTimeout(()=>document.getElementById('cb').innerText='Copy to Clipboard',2000)}})"
    style="background:#2d2d2d;color:#e0e0e0;border:1px solid #444;border-radius:8px;
           padding:7px 18px;font-size:14px;font-weight:600;cursor:pointer;font-family:Inter,sans-serif">
    Copy to Clipboard</button>""", height=50, scrolling=False)

def whatsapp_button(token):
    url = f"https://api.whatsapp.com/send?text={urllib.parse.quote(token)}"
    components.html(f"""<a href="{url}" target="_blank"
       style="display:inline-block;padding:7px 18px;background:#25D366;color:#fff;
              border-radius:8px;font-size:14px;font-weight:600;text-decoration:none;font-family:Inter,sans-serif">
       Share on WhatsApp</a>""", height=50, scrolling=False)

# ══════════════════════════════ UI ═══════════════════════════════════════
st.markdown("## Message Encrypt / Decrypt")
st.caption("Symmetric encryption — Fernet (AES-128-CBC + HMAC-SHA256) · 5-min expiry")
st.divider()

operation = st.selectbox("Operation", ["Encrypt", "Decrypt"])
st.divider()

# ── Decrypt ───────────────────────────────────────────────────────────────
if operation == "Decrypt":

    # WhatsApp section — green card header, always visible
    st.markdown("""
    <div style="background:linear-gradient(90deg,#1a472a,#25D366);border-radius:10px;
                padding:11px 18px;margin-bottom:12px">
        <span style="color:#fff;font-weight:700;font-size:15px">Copy from WhatsApp</span><br>
        <span style="color:#d4f5e0;font-size:12px">Paste the message you received, then click Parse & Auto-fill.</span>
    </div>""", unsafe_allow_html=True)

    wa_paste = st.text_area("WhatsApp message:",
                            placeholder="Paste combined token or 'Encrypted Message: ...'",
                            height=120, key="wa_paste_area", label_visibility="collapsed")
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
            if pkey: st.session_state["key_override"] = pkey
            st.session_state.update({"parsed_ct": pct, "auto_submit": True})
            st.session_state.pop("result", None)
            st.rerun()
        else:
            st.error("Could not parse. Paste a valid combined token or 'Encrypted Message:' text.")

    st.divider()

    # Manual Entry — collapsed
    with st.expander("Manual Entry"):
        mode = st.radio("Key source:", ["Paste key", "Use passphrase"], horizontal=True)
        if mode == "Paste key":
            active_key = st.text_input("Secret Key", value=st.session_state.pop("key_override", ""),
                                       placeholder="Paste the key received separately").strip()
        else:
            st.session_state.pop("key_override", None)
            phrase = st.text_input("Passphrase", placeholder="Enter the agreed passphrase", type="password")
            active_key = passphrase_to_key(phrase) if phrase.strip() else ""

        default_ct = st.session_state.pop("parsed_ct", "")
        message_input = st.text_area("Ciphertext", value=default_ct,
                                     placeholder="Paste ciphertext to decrypt", height=120)
        submit = st.button("Decrypt", key="dec_submit")
        if st.session_state.pop("auto_submit", False): submit = True

# ── Encrypt ───────────────────────────────────────────────────────────────
else:
    st.subheader("Key")
    mode = st.radio("Key source:", ["Auto-generate key", "Use custom passphrase"], horizontal=True)
    if mode == "Auto-generate key":
        if "gen_key" not in st.session_state:
            st.session_state["gen_key"] = generate_key()
        if st.button("Generate New Key"):
            st.session_state["gen_key"] = generate_key()
        active_key = st.text_input("Secret Key (auto-generated)", value=st.session_state["gen_key"]).strip()
        st.caption("Share via a separate channel — never alongside the encrypted message.")
    else:
        phrase = st.text_input("Passphrase", placeholder="Agree on this with the recipient", type="password")
        st.caption("Both sides must use the same passphrase. Nothing is transmitted.")
        active_key = passphrase_to_key(phrase) if phrase.strip() else ""

    st.subheader("Message")
    message_input = st.text_area("Plaintext", placeholder="Enter your message to encrypt",
                                 height=140, label_visibility="collapsed")
    submit = st.button("Encrypt")
    st.divider()

# ── Result ────────────────────────────────────────────────────────────────
st.subheader("Result")

if submit:
    if not active_key:
        st.error("No key provided.")
    elif not is_valid_key(active_key):
        st.error("Invalid key. Check the key or passphrase.")
    elif not message_input.strip():
        st.error("Input cannot be empty.")
    elif operation == "Encrypt":
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
            st.error(f"Decryption failed — expired (valid {MESSAGE_TTL//60} min) or wrong key.")
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
        with col1: copy_button(combined)
        with col2: whatsapp_button(combined)
        st.caption("The token looks random — key and message are indistinguishable without the app.")
else:
    st.caption("Output will appear here after you submit.")

st.divider()
st.caption("Message Encrypt / Decrypt  |  2024-25")
