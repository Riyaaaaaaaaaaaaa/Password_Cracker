import hashlib
import itertools
import string
import bcrypt
import argparse

def hash_string(text, algo='md5'):
    h = getattr(hashlib, algo)()
    h.update(text.encode())
    return h.hexdigest()

def crack_dictionary(target_hash, dictionary_file, algo='md5'):
    with open(dictionary_file, 'r', encoding='utf-8') as file:
        for line in file:
            word = line.strip()
            hashed = hash_string(word, algo)
            if hashed == target_hash:
                print(f"[+] Password found: {word}")
                return word
    print("[-] Password not found in dictionary.")
    return None

def crack_bcrypt(target_hash, dictionary_file):
    target_hash = target_hash.encode()
    with open(dictionary_file, 'r', encoding='utf-8') as file:
        for line in file:
            word = line.strip().encode()
            if bcrypt.checkpw(word, target_hash):
                print(f"[+] Password found: {word.decode()}")
                return word.decode()
    print("[-] Password not found in dictionary.")
    return None

def brute_force(target_hash, max_length=4, algo='md5'):
    charset = string.ascii_lowercase + string.digits
    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            guess = ''.join(attempt)
            if hash_string(guess, algo) == target_hash:
                print(f"[+] Password found: {guess}")
                return guess
    print("[-] Password not found with brute-force.")
    return None

def main():
    parser = argparse.ArgumentParser(description="Hashed Password Cracker")
    parser.add_argument("hash", help="Hashed password to crack")
    parser.add_argument("--algo", default="md5", help="Hash algorithm (md5, sha1, sha256, bcrypt)")
    parser.add_argument("--dict", help="Path to dictionary file")
    parser.add_argument("--brute", action="store_true", help="Use brute-force method")
    parser.add_argument("--maxlen", type=int, default=4, help="Max password length for brute-force")

    args = parser.parse_args()

    if args.algo == 'bcrypt':
        if args.dict:
            crack_bcrypt(args.hash, args.dict)
        else:
            print("[-] bcrypt requires a dictionary file. Brute-force is not practical.")
    else:
        if args.dict:
            crack_dictionary(args.hash, args.dict, args.algo)
        if args.brute:
            brute_force(args.hash, args.maxlen, args.algo)

if __name__ == "__main__":
    main()
