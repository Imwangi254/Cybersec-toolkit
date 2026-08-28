#!/bin/bash
# ============================================================
# C2A: Bash Scripting Essentials — SQUAD 7
# Script: encode_base64.sh
# Base64-encodes plaintext passwords from an input file,
# line by line, into an output file.
# ============================================================

read -r -p "Enter the input file: " input_file

if [ -z "$input_file" ]; then
    echo "Error: No input file was provided."
    exit 1
fi
if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' does not exist."
    exit 1
fi
if [ ! -r "$input_file" ]; then
    echo "Error: Input file '$input_file' cannot be read."
    exit 1
fi

read -r -p "Enter the output file: " output_file

if [ -z "$output_file" ]; then
    echo "Error: Output file cannot be empty."
    exit 1
fi

if command -v base64 >/dev/null 2>&1; then
    encoder="base64"
elif command -v python3 >/dev/null 2>&1; then
    encoder="python3"
else
    echo "Error: Neither 'base64' nor 'python3' is available."
    exit 1
fi

if ! : > "$output_file"; then
    echo "Error: Cannot create or write to '$output_file'."
    exit 1
fi

echo "=========================================="
echo "Starting Base64 encoding"
echo "Input file : $input_file"
echo "Output file: $output_file"
echo "Encoder    : $encoder"
echo "=========================================="

while IFS= read -r line || [ -n "$line" ]; do
    if [ -z "$line" ]; then
        continue
    fi
    if [ "$encoder" = "base64" ]; then
        encoded=$(printf '%s' "$line" | base64 | tr -d '\n')
    else
        encoded=$(printf '%s' "$line" | python3 -c \
'import sys, base64; print(base64.b64encode(sys.stdin.read().encode()).decode())')
    fi
    if [ $? -ne 0 ] || [ -z "$encoded" ]; then
        echo "Error: Failed to encode an input line."
        exit 1
    fi
    if ! printf '%s\n' "$encoded" >> "$output_file"; then
        echo "Error: Failed to write to '$output_file'."
        exit 1
    fi
done < "$input_file"

echo "=========================================="
echo "Base64 encoding completed successfully."
echo "Results saved to: $output_file"
echo "=========================================="
