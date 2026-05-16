import os
import argparse
import shutil
from google import genai
from google.genai import types

# --- Configuration & Logic Setup ---
client = genai.Client(api_key=os.environ.get("GOOGLE_API_KEY"))
MODEL_NAME = "gemini-2.5-flash-lite"

def get_instruction(mode, file_ext):
    """
    Defines the Agent's persona based on the operation mode and language.
    Applies the 80/20 rule to focus on critical logic and security flaws.
    """
    is_python = file_ext.lower() == '.py'
    lang = "Python" if is_python else "C"
    
    if mode == "audit":
        base_prompt = f"You are a Senior {lang} Security & Algorithm Engineer."
        if is_python:
            return base_prompt + """
            1. Analyze Logic Flaws & Secure Coding (OWASP standards).
            2. Analyze Time & Space Complexity (Big O).
            3. Check for hardcoded secrets or insecure library usage.
            Use 80/20 rule. Focus on the 20% of code causing 80% of risks."""
        else:
            return base_prompt + """
            1. Analyze Security Vulnerabilities (Memory leaks, Buffer overflows, Pointers).
            2. Analyze Time & Space Complexity (Big O).
            Explain the logic using Lamport Protocol (Logic before Syntax)."""
            
    elif mode == "fix":
        return f"Expert {lang} Developer. Provide ONLY the corrected and optimized {lang} code. Fix security vulnerabilities and improve efficiency. No prose."
    
    elif mode == "test":
        return f"QA Engineer. Create a {lang} unit test file. Focus on EDGE CASES (NULL, empty inputs, boundaries). Provide ONLY code."
    
    elif mode == "exploit":
        return """White-Hat Hacker. 
        1. Create a Python script to trigger the vulnerability in the provided C code.
        2. Draw an ASCII Memory Map (Stack/Heap visualization).
        3. Explain the exploitation logic (e.g., return address overwrite)."""

def process_file(file_path, mode):
    """Handles single file processing: Reads, Requests AI Analysis, and Returns Result."""
    try:
        ext = os.path.splitext(file_path)[1]
        with open(file_path, 'r') as f:
            code = f.read()
        
        print(f"[*] Mode: {mode.upper()} | Processing: {file_path}")
        
        response = client.models.generate_content(
            model=MODEL_NAME,
            config=types.GenerateContentConfig(system_instruction=get_instruction(mode, ext)),
            contents=code
        )
        
        clean_text = response.text.replace("```c", "").replace("```python", "").replace("```", "").strip()
        return clean_text
    except Exception as e:
        return f"[!] Error processing {file_path}: {e}"

def scan_directory(directory_path):
    """Performs a recursive audit on all .c and .py files within a directory."""
    report = "# Global Security & Complexity Audit Report\n\n"
    target_exts = ('.c', '.py')
    files = [f for f in os.listdir(directory_path) if f.lower().endswith(target_exts)]
    
    if not files:
        print("[!] No supported source files (.c, .py) found in directory.")
        return

    print(f"[+] Found {len(files)} files. Initiating Global Scan...")
    for f in files:
        path = os.path.join(directory_path, f)
        report += f"## Analysis of {f}\n\n" + process_file(path, "audit") + "\n\n---\n"
    
    with open("global_report.md", "w") as out:
        out.write(report)
    print("\n[SUCCESS] Global report generated: 'global_report.md'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S2-Guardian: AI-Powered Security Auditor for C & Python")
    parser.add_argument("path", help="Path to a file or directory")
    parser.add_argument("--fix", action="store_true", help="Automatically fix and optimize the code")
    parser.add_argument("--test", action="store_true", help="Generate unit tests for edge-case coverage")
    parser.add_argument("--exploit", action="store_true", help="Hacker POV: Generate exploit PoC and memory map (C only)")
    
    args = parser.parse_args()

    if os.path.isdir(args.path):
        scan_directory(args.path)
    elif os.path.isfile(args.path):
        if args.fix:
            backup_dir = ".s2_backup"
            try:
                os.makedirs(backup_dir, exist_ok=True)
                backup_path = os.path.join(backup_dir, f"{os.path.basename(args.path)}.bak")
                shutil.copy2(args.path, backup_path)
                print(f"[*] Safety Net: Original file backed up to '{backup_path}'")
            except Exception as backup_error:
                print(f"[!] Warning: Could not create backup: {backup_error}. Proceeding with execution.")

            result = process_file(args.path, "fix")
            with open(args.path, 'w') as f: 
                f.write(result)
            print(f"[+] Success: {args.path} has been patched and optimized.")
            
        elif args.test:
            result = process_file(args.path, "test")
            test_file = f"tests_gen_{os.path.basename(args.path)}"
            with open(test_file, "w") as f: 
                f.write(result)
            print(f"[+] Success: Unit tests generated in '{test_file}'.")
            
        elif args.exploit:
            result = process_file(args.path, "exploit")
            print("\n--- [ HACKER POV: EXPLOIT & MEMORY VISUALIZATION ] ---\n")
            print(result)
            with open("exploit_poc.py", "w") as f: 
                f.write(result)
                
        else:
            print("\n--- [ SECURITY & COMPLEXITY AUDIT ] ---\n")
            print(process_file(args.path, "audit"))
    else:
        print("[!] Invalid Path. Please provide a valid file or directory.")
