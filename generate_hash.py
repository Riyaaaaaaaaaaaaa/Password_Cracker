# generate_hash.py
import hashlib
import bcrypt

def generate_hash(password, algo='md5'):
    password = password.encode()
    if algo == 'md5':
        return hashlib.md5(password).hexdigest()
    elif algo == 'sha1':
        return hashlib.sha1(password).hexdigest()
    elif algo == 'sha256':
        return hashlib.sha256(password).hexdigest()
    elif algo == 'sha512':
        return hashlib.sha512(password).hexdigest()
    elif algo == 'bcrypt':
        return bcrypt.hashpw(password, bcrypt.gensalt()).decode()
    else:
        raise ValueError("Unsupported algorithm")

if __name__ == "__main__":
    pw = input("Enter password: ")
    algo = input("Enter algorithm (md5/sha1/sha256/sha512/bcrypt): ")
    print("Hashed:", generate_hash(pw, algo))
