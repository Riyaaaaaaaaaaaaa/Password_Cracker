import streamlit as st
import os
import time
import string
from datetime import datetime
from cracker import crack_dictionary, crack_bcrypt, brute_force, hash_string

# Configuration
st.set_page_config(page_title="🔐 Hashed Password Cracker", layout="centered")

# Global Log Store
if 'logs' not in st.session_state:
    st.session_state.logs = []

# Inject CSS to make the checkbox tick green
st.markdown("""
    <style>
    /* Make checkbox tick green */
    input[type="checkbox"] {
        accent-color: green;
    }
    </style>
""", unsafe_allow_html=True)


# Terms and Conditions Modal
def show_terms_modal():
    st.markdown("## 👋 Welcome to Hashed Password Cracker Toolkit")
    st.write("""
    This toolkit allows you to:
    - Crack password hashes using Dictionary or Brute-force attacks.
    - Estimate brute-force cracking times.
    - Check password strength.
    - Generate hash values and more.
    """)

    st.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=100)

    st.markdown("### ⚖️ Terms and Conditions")
    with st.expander("Click to view Terms and Conditions", expanded=True):
        st.info("""
        - This tool is for **educational and ethical** use only.  
        - Do **not** use it to crack unauthorized systems.  
        - You agree to use this tool **responsibly**.  
        """)
        
        agree = st.checkbox("I Agree to the Terms and Conditions")
    
    if agree:
        st.session_state.agreed_terms = True
        #st.markdown("### ✅ You have agreed to the Terms and Conditions")
        time.sleep(1)
        st.rerun()
    else:
        st.stop()

if 'agreed_terms' not in st.session_state or not st.session_state.agreed_terms:
    show_terms_modal()

# Helper for Logging
def log_event(hash_value, algo, password, method, success=True):
    entry = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'hash': hash_value,
        'algorithm': algo,
        'password': password if success else "NOT FOUND",
        'method': method
    }
    st.session_state.logs.append(entry)

# --- Tabs ---
tabs = st.tabs(["🔓 Crack Hash", "🔢 Hash Generator", "⏱️ Time Estimator", "📈 Strength Checker", "🧠 Session Logs"])

# --- Crack Hash Tab ---
with tabs[0]:
    st.header("🔓 Crack a Hashed Password")
    target_hash = st.text_input("Enter the hash to crack")
    hash_algo = st.selectbox("Hash Algorithm", ["md5", "sha1", "sha256", "sha512", "bcrypt"])
    method = st.radio("Attack Method", ["Dictionary", "Brute-force (demo)"])

    dictionary_file = None
    if method == "Dictionary":
        uploaded_file = st.file_uploader("Upload Dictionary", type="txt")
        if uploaded_file:
            dictionary_file = f"temp_dict_{uploaded_file.name}"
            with open(dictionary_file, "wb") as f:
                f.write(uploaded_file.read())

            if st.checkbox("🧠 Enable Smart Dictionary Augmentation"):
                with open(dictionary_file, 'r+', encoding='utf-8') as f:
                    words = [line.strip() for line in f.readlines()]
                    augment = set()
                    for word in words:
                        augment.update({
                            word.lower(), word.upper(), word.capitalize(),
                            word + "123", word + "@123"
                        })
                    all_words = set(words) | augment
                    f.seek(0)
                    f.truncate()
                    for word in all_words:
                        f.write(word + "\n")

    if st.button("🚀 Crack Now"):
        if not target_hash:
            st.error("Enter a hash to crack")
        elif method == "Dictionary" and not dictionary_file:
            st.error("Upload a dictionary file")
        else:
            result = None
            if method == "Dictionary":
                if hash_algo == "bcrypt":
                    result = crack_bcrypt(target_hash, dictionary_file)
                else:
                    result = crack_dictionary(target_hash, dictionary_file, hash_algo)
                log_event(target_hash, hash_algo, result, "Dictionary", success=bool(result))
            else:
                if hash_algo == "bcrypt":
                    st.error("Brute-force not supported for bcrypt")
                else:
                    result = brute_force(target_hash, max_length=4, algo=hash_algo)
                    log_event(target_hash, hash_algo, result, "Brute-force", success=bool(result))

            if result:
                st.success(f"✅ Password found: `{result}`")
            else:
                st.error("❌ Password not found")

    if dictionary_file and os.path.exists(dictionary_file):
        os.remove(dictionary_file)

# --- Hash Generator ---
with tabs[1]:
    st.header("🔢 Hash Generator")
    plain = st.text_input("Enter plain text")
    algo = st.selectbox("Algorithm", ["md5", "sha1", "sha256", "sha512"])
    if st.button("Generate Hash"):
        hashed = hash_string(plain, algo)
        st.code(hashed)

# --- Brute-force Estimator ---
with tabs[2]:
    st.header("⏱️ Brute-force Time Estimator")
    max_len = st.slider("Max password length", 1, 6, 4)
    charset_size = len(string.ascii_lowercase + string.digits)
    total_attempts = sum([charset_size ** i for i in range(1, max_len + 1)])
    avg_hash_time = 0.00005  # Example value for estimation
    estimated_time = total_attempts * avg_hash_time
    st.markdown(f"Total attempts: `{total_attempts}`")
    st.markdown(f"Estimated time: `{estimated_time:.2f} seconds`")

# --- Strength Checker ---
with tabs[3]:
    st.header("📈 Password Strength Checker")
    password = st.text_input("Enter password to check")
    if password:
        score = 0
        if len(password) >= 8: score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in string.punctuation for c in password): score += 1
        strength = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        st.success(f"Password Strength: {strength[score - 1] if score else 'Very Weak'}")

# --- Session Logs ---
with tabs[4]:
    st.header("🧠 Session Logs")
    if st.session_state.logs:
        for log in st.session_state.logs:
            st.markdown(f"**Timestamp**: {log['timestamp']}  ")
            st.markdown(f"**Hash**: `{log['hash']}`  ")
            st.markdown(f"**Algorithm**: `{log['algorithm']}`  ")
            st.markdown(f"**Cracked Password**: `{log['password']}`  ")
            st.markdown(f"**Method**: {log['method']}  ")
            st.markdown("---")

        if st.button("📥 Download Logs"):
            log_text = "\n".join([
                f"Timestamp: {log['timestamp']}\nHash: {log['hash']}\nAlgorithm: {log['algorithm']}\nCracked Password: {log['password']}\nMethod: {log['method']}\n"
                for log in st.session_state.logs
            ])
            with open("session_report.txt", "w") as f:
                f.write(log_text)
            with open("session_report.txt", "rb") as f:
                st.download_button("Download Report", f, file_name="session_report.txt")
    else:
        st.info("No session logs available.")
