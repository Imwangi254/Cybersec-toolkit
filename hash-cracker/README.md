# Hash Cracker / Dictionary Attack Tool

A Python tool that recovers a password from its hash using a dictionary
(wordlist) attack. Built to understand how password hashes are attacked -
the offensive counterpart to the File Integrity Monitor, which uses the
same hashing for defense.

For learning and authorised testing only. Use it against hashes you
generate yourself, never against credentials that are not yours.

## The core idea

A hash is one-way and cannot be reversed. So a cracker does not reverse it -
it guesses. It hashes millions of candidate passwords from a wordlist in
the normal forward direction and looks for a hash that matches the target.
A match means the guess is the password.

This reveals the real meaning of password strength: a password is strong
only if it is unguessable - i.e. not present in any wordlist. Complexity
rules (symbols, capitals) do not help if the password is a common pattern
already in the list.

## Usage

    python3 cracker.py <target_hash> <wordlist> [algorithm]

Example (md5 is the default):

    python3 cracker.py 0d107d09f5bbe40cade3de5c71e9e9b7 rockyou.txt md5

Supports any algorithm in Python's hashlib (md5, sha1, sha256, etc).

## Demonstration

- A common password like "letmein" is in wordlists such as rockyou.txt
  (14 million real leaked passwords) and cracks almost instantly.
- A random password like Xq7 (mixed symbols) is in no wordlist, so the
  tool tries all 14 million entries and still fails - a strong password
  winning.

## Why real crackers use GPUs and why slow hashes matter

This Python tool tries a few hundred thousand guesses per second. Tools
like hashcat use the GPU and try billions per second. That is why:

- Password length matters enormously (each character multiplies the work).
- Systems should store passwords with deliberately slow hashes (bcrypt,
  argon2), not fast ones like MD5 or SHA-1, to make mass guessing infeasible.

## What I learned

- Cracking does not reverse a hash - it hashes guesses forward and matches.
- Password strength is really unguessability, measured by wordlist presence.
- Handling messy real-world data (rockyou.txt has non-UTF-8 bytes) without
  crashing, using errors="ignore".
- Why fast hashes are unsuitable for password storage.
- The relationship between this offensive tool and defensive hashing (FIM).

## Note on the wordlist

rockyou.txt is not included (it is large and ships with Kali at
/usr/share/wordlists/). Decompress it with: gunzip rockyou.txt.gz
