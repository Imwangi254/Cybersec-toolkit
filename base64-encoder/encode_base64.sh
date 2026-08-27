#!/usr/bin/env bash
#
# encode_base64.sh — Base64-encode a file of plaintext passwords, line by line.
#
# What it does:
#   - Prompts for an input file (one plaintext password per line).
#   - Prompts for an output file to write the Base64-encoded lines to.
#   - Encodes each non-empty line, preserving the original order.
#   - Skips empty/blank lines in the input.
#   - Uses a portable encoder: GNU/Linux base64, macOS base64, or
#     falls back to python3 if neither behaves as expected.
#   - Prints clear error messages and exits non-zero on fatal errors.
#
# Usage:
#   ./encode_base64.sh
#   (then answer the two prompts for input and output file paths)
#
# Author: Peter Ndirangu (Imwangi254)  |  AH200 Bash automation assignment
#

set -u
set -o pipefail

# encode_line: Base64-encode a single string ($1). Tries system base64,
# falls back to python3. Echoes the encoded string on success.
encode_line() {
    local plaintext="$1"
    if command -v base64 >/dev/null 2>&1; then
        printf '%s' "$plaintext" | base64 | tr -d '\n'
    elif command -v python3 >/dev/null 2>&1; then
        printf '%s' "$plaintext" \
            | python3 -c "import sys, base64; sys.stdout.write(base64.b64encode(sys.stdin.buffer.read()).decode())"
    else
        return 1
    fi
}

# Confirm at least one encoder exists before doing anything.
if ! command -v base64 >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Error: neither 'base64' nor 'python3' is available. Cannot continue." >&2
    exit 1
fi

# Prompt for the input file.
read -r -p "Enter the input file (plaintext passwords, one per line): " input_file
if [ -z "$input_file" ]; then
    echo "[!] Error: no input file given." >&2
    exit 1
fi
if [ ! -f "$input_file" ]; then
    echo "[!] Error: input file '$input_file' does not exist or is not a regular file." >&2
    exit 1
fi
if [ ! -r "$input_file" ]; then
    echo "[!] Error: input file '$input_file' is not readable (check permissions)." >&2
    exit 1
fi

# Prompt for the output file.
read -r -p "Enter the output file to write Base64 lines to: " output_file
if [ -z "$output_file" ]; then
    echo "[!] Error: no output file given." >&2
    exit 1
fi

# Start with an empty output file. Fatal if we can't create it.
if ! : > "$output_file" 2>/dev/null; then
    echo "[!] Error: cannot write to output file '$output_file' (check path/permissions)." >&2
    exit 1
fi

echo "[*] Encoding '$input_file' -> '$output_file' ..."

encoded_count=0
skipped_count=0

# Read line by line. IFS= and -r preserve the line exactly; the || [ -n ]
# handles a final line with no trailing newline.
while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty or whitespace-only lines, preserving order of the rest.
    if [ -z "${line//[[:space:]]/}" ]; then
        skipped_count=$((skipped_count + 1))
        continue
    fi
    if ! encoded=$(encode_line "$line"); then
        echo "[!] Error: failed to Base64-encode a line. Aborting." >&2
        exit 1
    fi
    printf '%s\n' "$encoded" >> "$output_file"
    encoded_count=$((encoded_count + 1))
done < "$input_file"

echo "[+] Done. Encoded $encoded_count line(s), skipped $skipped_count empty line(s)."
echo "[+] Output written to '$output_file'."
exit 0
