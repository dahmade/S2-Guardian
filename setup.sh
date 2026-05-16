#!/bin/bash

echo "[*] Creating Virtual Environment..."
python3 -m venv venv

echo "[*] Activating Virtual Environment..."
source venv/bin/activate

echo "[*] Installing Dependencies..."
pip install google-genai

echo "[+] Setup Complete!"
echo "[!] Remember to run: export GOOGLE_API_KEY='your_key_here'"
echo "[!] Then activate with: source venv/bin/activate"
