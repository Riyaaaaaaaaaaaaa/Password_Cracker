# 🔐 Password Cracker Toolkit

A versatile Python toolkit to crack hashed passwords using **dictionary** or **brute-force** attacks. Includes a **CLI** and a **Streamlit Web App** with a modern UI and extra features.

## 🚀 Features

- ✅ Crack hashes using:
  - Dictionary attack
  - Brute-force attack (demo-level)
- 🔒 Supports hash algorithms:
  - `MD5`, `SHA1`, `SHA256`, `SHA512`, `bcrypt`
- 🧠 Smart dictionary enhancement:
  - Adds common variations from `common_passwords.txt`
- 🌐 Streamlit Web UI:
  - Password strength checker
  - Hash generator
  - Brute-force time estimator
  - Logs & export reports
- ✅ Ethical use modal before launch

## 📁 Project Structure

| File/Folder            | Description                             |
|------------------------|-----------------------------------------|
| `cracker.py`           | CLI-based password cracker              |
| `cracker_app.py`       | Streamlit Web UI app                    |
| `common_passwords.txt` | Sample password dictionary              |
| `generate_hash.py`     | Utility to generate hashes manually     |
| `requirements.txt`     | Python dependencies                     |

## 🧪 CLI Usage (`cracker.py`)

### Dictionary Attack

```bash
python cracker.py <hash> --dict common_passwords.txt --algo md5
python cracker.py <hash> --dict common_passwords.txt --algo sha256
python cracker.py <bcrypt_hash> --dict common_passwords.txt --algo bcrypt
````

### Brute-Force Attack

```bash
python cracker.py <hash> --brute --maxlen 4 --algo sha1
```

## 🌐 Web App Usage (`cracker_app.py`)

```bash
streamlit run cracker_app.py
```

### Web App Features:

* 🔍 Password strength checker
* 🔢 Hash generator
* 🕒 Brute-force time estimator
* 📜 View logs & export reports
* ✅ Consent popup for ethical use

## 🧪 Generate Hashes (`generate_hash.py`)

Generate hashes for testing:

```bash
python generate_hash.py --password hello --algo md5
python generate_hash.py --password hello --algo bcrypt
```

## 📦 Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

## ⚠️ Disclaimer

This tool is developed strictly for **educational** and **ethical testing** purposes only. Do not use it for any illegal or malicious activity. The developer is not responsible for misuse.
