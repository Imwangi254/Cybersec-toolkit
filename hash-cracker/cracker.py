import hashlib
import sys

def crack(target_hash, wordlist_path, algorithm="md5"):
    """Try each word in the wordlist; return the match or None."""
    target_hash = target_hash.lower().strip()
    try:
        # errors="ignore" skips undecodable bytes in messy real-world wordlists
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                guess = line.strip()
                if not guess:
                    continue
                h = hashlib.new(algorithm)
                h.update(guess.encode())
                guess_hash = h.hexdigest()
                if guess_hash == target_hash:
                    return guess
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
        return None
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 cracker.py <target_hash> <wordlist> [algorithm]")
        sys.exit(1)

    target = sys.argv[1]
    wordlist = sys.argv[2]
    algo = sys.argv[3] if len(sys.argv) > 3 else "md5"

    print("=== Hash Cracker ===")
    print(f"Target hash: {target}")
    print(f"Algorithm:   {algo}")
    print(f"Wordlist:    {wordlist}")
    print("Cracking...")
    print()

    result = crack(target, wordlist, algo)
    if result:
        print(f"[+] CRACKED! The password is: {result}")
    else:
        print("[-] Not found in the wordlist. Password may be strong or use a different algorithm.")
