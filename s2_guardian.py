import os
import argparse
import sys
import requests
import re
import subprocess # Added for cppcheck
from google import genai
from google.genai import types

# =====================================================================
# CONFIGURATION & CONSTANTS
# =====================================================================
client = genai.Client(api_key=os.environ.get("GOOGLE_API_KEY"))
MODEL_NAME = "gemini-2.5-flash-lite"
LOCAL_MODEL_NAME = "qwen2.5-coder:1.5b"
OLLAMA_URL = "http://localhost:11434/api/generate"

# =====================================================================
# CORE LOGIC & PERSONA DEFINITION
# =====================================================================
def get_instruction(mode, file_ext):
    """Defines the AI's persona based on operation mode."""
    is_python = file_ext.lower() == '.py'
    lang = "Python" if is_python else "C"
    
    strict_constraints = """
    STRICT CONSTRAINTS:
    1. No Forced Analogies. Focus on Logic, Edge-Cases, and Memory Maps.
    2. 80/20 Rule: Focus strictly on the 20% of code causing 80% of risks.
    3. Brutal Honesty. Zero filler text."""
    
    if mode == "audit":
        base = f"You are a Senior {lang} Security & Algorithm Engineer."
        if is_python:
            return base + "\n1. Analyze Logic Flaws.\n2. Analyze Big O.\n3. Detect secrets." + strict_constraints
        else:
            return base + "\n1. Analyze Memory leaks, Buffer overflows.\n2. Analyze Big O." + strict_constraints
            
    elif mode == "fix":
        return f"Expert {lang} Developer. Return ONLY optimized code. Fix vulnerabilities. No prose."
    elif mode == "test":
        return f"QA Engineer. Create {lang} unit tests. Focus on EDGE CASES (NULL, boundaries). Return ONLY code."
    elif mode == "exploit":
        return "White-Hat Hacker.\n1. Write exploit script.\n2. Draw ASCII Stack Map.\n3. Explain return address overwrite."

# =====================================================================
# CONTEXT & MEMORY MANAGEMENT
# =====================================================================
def gather_headers_context(directory_path):
    """Scans for .h files to provide Cross-File Context (C only)."""
    context_str = "\n=== GLOBAL PROJECT CONTEXT (C-HEADERS) ===\n"
    try:
        if not directory_path or not os.path.isdir(directory_path):
            return ""
            
        header_files = [f for f in os.listdir(directory_path) if f.lower().endswith('.h')]
        if not header_files:
            return "" 
            
        for h_file in header_files:
            path = os.path.join(directory_path, h_file)
            context_str += f"\n--- Header: {h_file} ---\n"
            with open(path, 'r', encoding='utf-8') as f:
                for line in f.splitlines():
                    if line.startswith('#') or '(' in line: 
                        context_str += f"{line}\n"
        return context_str + "==========================================\n"
    except Exception as e:
        return f"\n[!] Context Gathering Error: {e}\n"


def split_into_chunks(code, max_lines=150):
    """
    Smart Chunking: Splits code on function boundaries.
    """
    lines = code.splitlines()
    if len(lines) <= max_lines:
        return [code]

    chunks = []
    current_chunk = []
    
    # هاد السطر كيقلب على: كلمة def، كلمة class، أو بداية فانكشن فـ C
    boundary_pattern = re.compile(r'^(def\s+|class\s+|[a-zA-Z_][a-zA-Z0-0_*\s]+\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(.*?\)\s*\{?)')

    for line in lines:
        # إيلا فتنا 150 سطر + ولقينا دالة جديدة عاد كنقطعو
        if len(current_chunk) >= max_lines and boundary_pattern.match(line):
            chunks.append("\n".join(current_chunk))
            current_chunk = [] # كنخويو الـ Chunk باش نبداو واحد جديد

        current_chunk.append(line)

    # كنزيدو داكشي اللي بقا فـ اللخر
    if current_chunk:
        chunks.append("\n".join(current_chunk))

    return chunks

# =====================================================================
# FALLBACK DEFENSES
# =====================================================================
def query_ollama(prompt, system):
    """Single Responsibility: Handles local Ollama requests."""
    payload = {"model": LOCAL_MODEL_NAME, "prompt": prompt, "system": system, "stream": False}
    res = requests.post(OLLAMA_URL, json=payload, timeout=180)
    if res.status_code == 200:
        return res.json().get("response", "").replace("```c", "").replace("```python", "").replace("```", "").strip()
    raise Exception(f"Local AI Offline (Status: {res.status_code})")

def run_sast_fallback(file_path, file_ext):
    """
    [PLAN C] Hardware-level scan when AI is dead.
    Supports both C (cppcheck) and Python (bandit).
    """
    report = "### 🛡️ [PLAN C] Deterministic SAST Fallback\n⚠️ *AI Unreachable. Executing hardware-level scan.*\n\n"
    ext = file_ext.lower()

    # الحالة الأولى: الكود بايثون
    if ext == '.py':
        try:
            # كنعطيو أمر لـ نظام التشغيل باش يخدم bandit
            result = subprocess.run(
                ["bandit", "-r", file_path, "-f", "txt"],
                capture_output=True, text=True
            )
            output = result.stdout.strip() or result.stderr.strip()
            if output:
                return report + f"**Bandit Python Security Scan:**\n```text\n{output}\n```"
            return report + "✅ Bandit found no security flaws.\n"
        except FileNotFoundError:
            return report + "[!] CRITICAL: 'bandit' is not installed. Run 'pip install bandit'."

    # الحالة الثانية: الكود سي
    elif ext == '.c':
        try:
            # كنعطيو أمر لـ نظام التشغيل باش يخدم cppcheck
            result = subprocess.run(
                ["cppcheck", "--enable=all", "--inconclusive", file_path],
                capture_output=True, text=True
            )
            if result.stderr.strip():
                return report + f"**Cppcheck Violations:**\n```text\n{result.stderr.strip()}\n```"
            return report + "✅ Cppcheck found no memory violations.\n"
        except FileNotFoundError:
            return report + "[!] CRITICAL: 'cppcheck' is not installed."

    return report + "[!] Unsupported file extension."

# =====================================================================
# EXECUTION ENGINE
# =====================================================================
def process_file(file_path, mode, project_context=""):
    """Master handler implementing the Fault-Tolerant Pipeline."""
    try:
        ext = os.path.splitext(file_path)[1]
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        system_prompt = get_instruction(mode, ext) + project_context
        print(f"[*] Mode: {mode.upper()} | Processing: {file_path}")
        
        chunks = split_into_chunks(code, max_lines=150)
        total = len(chunks)
        final_responses = []
        
        for index, chunk in enumerate(chunks):
            if total > 1: print(f"    -> Chunk {index + 1}/{total}...")
            
            try:
                # --- PHASE 1: Cloud AI (Gemini) ---
                response = client.models.generate_content(
                    model=MODEL_NAME,
                    config=types.GenerateContentConfig(system_instruction=system_prompt),
                    contents=chunk
                )
                final_responses.append(response.text.strip())
                
            except Exception as cloud_error:
                print(f"[!] Cloud Error. Local Fallback (Chunk {index + 1})...")
                try:
                    # --- PHASE 2: Local AI (Ollama) ---
                    final_responses.append(query_ollama(chunk, system_prompt))
                    
                except Exception as local_error:
                    # --- PHASE 3: Hard SAST (Cppcheck Fallback) ---
                    if mode in ["fix", "test"]:
                        print(f"[!] CRITICAL: AI completely offline. Cannot execute {mode.upper()} without AI.")
                        comment_start = "#" if ext.lower() == ".py" else "//"
                        return f"{comment_start} [!] CRITICAL ERROR: AI Offline. Could not generate automated {mode}."
                    else:
                        print("[!] AI completely failed. Executing SAST Fallback...")
                        return run_sast_fallback(file_path, ext)
                        
        # --- RETURN LOGIC BASED ON MODE ---
        if mode in ["fix", "test"]:
            return "\n".join(final_responses).replace("```c", "").replace("```python", "").replace("```", "")
        else:
            return f"\n\n{'='*40}\n\n".join(final_responses).replace("```c", "").replace("```python", "").replace("```", "")
        
    except Exception as e:
        return f"[!] Core Error processing file: {e}"

def scan_directory(directory_path):
    """Recursive directory audit."""
    report = "# 🌐 Global Security Audit Report\n\n"
    files = [f for f in os.listdir(directory_path) if f.lower().endswith(('.c', '.py'))]
    
    if not files:
        print("[!] No supported files found.")
        return

    print(f"[+] Found {len(files)} files. Gathering Context...")
    global_context = gather_headers_context(directory_path)
    
    for f in files:
        path = os.path.join(directory_path, f)
        report += f"## File: {f}\n\n" + process_file(path, "audit", global_context) + "\n\n---\n"
    
    with open("global_report.md", "w", encoding="utf-8") as out:
        out.write(report)
    print("\n[SUCCESS] Global report saved: 'global_report.md'")

# =====================================================================
# CLI ENTRY POINT (Refactored Pipeline)
# =====================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S2-Guardian: Fault-Tolerant Auditor")
    parser.add_argument("path", help="Target file or directory")
    parser.add_argument("--fix", action="store_true", help="Auto-patch code")
    parser.add_argument("--test", action="store_true", help="Generate unit tests")
    parser.add_argument("--exploit", action="store_true", help="Generate exploit PoC (C only)")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        scan_directory(args.path)
        
    elif os.path.isfile(args.path):
        parent_dir = os.path.dirname(args.path) or "."
        project_ctx = gather_headers_context(parent_dir)
        
        # Extract base name for consistent output naming (without date)
        base_name, ext = os.path.splitext(os.path.basename(args.path))

        # -------------------------------------------------------------
        # STATE 1: CORE AUDIT (Always Executes First)
        # -------------------------------------------------------------
        os.makedirs("audit_reports", exist_ok=True)
        audit_result = process_file(args.path, "audit", project_ctx)
        
        if not audit_result.strip():
            print("[!] CRITICAL ERROR: AI returned an empty audit report.")
            sys.exit(1)
            
        audit_path = f"audit_reports/audit_{base_name}.md" # must be .md for formatting
        with open(audit_path, "w", encoding="utf-8") as f:
            f.write(f"# 🛡️ Security Audit: {base_name}{ext}\n\n{audit_result}")
        print(f"[+] AUDIT SUCCESS: {audit_path}") 

        # -------------------------------------------------------------
        # STATE 2: AUTO-PATCH MODE (Conditional)
        # -------------------------------------------------------------
        if args.fix:
            os.makedirs("fixed_files", exist_ok=True) # new directory for fixed files
            fix_result = process_file(args.path, "fix", project_ctx)
            
            fix_path = f"fixed_files/{base_name}_fixed{ext}"
            with open(fix_path, "w", encoding="utf-8") as f:
                f.write(fix_result)
            print(f"[+] PATCH SUCCESS: {fix_path}")

        # -------------------------------------------------------------
        # STATE 3: EXPLOIT GEN MODE (Conditional)
        # -------------------------------------------------------------
        if args.exploit:
            os.makedirs("exploit_reports", exist_ok=True) # new directory for exploit reports
            exploit_result = process_file(args.path, "exploit", project_ctx)
            
            exploit_path = f"exploit_reports/exploit_{base_name}.md" # must be .md
            with open(exploit_path, "w", encoding="utf-8") as f:
                f.write(exploit_result)
            print(f"[+] EXPLOIT REPORT: {exploit_path}")

        # -------------------------------------------------------------
        # STATE 4: TEST GEN MODE (Optional)
        # -------------------------------------------------------------
        if args.test:
            os.makedirs("test_files", exist_ok=True)
            test_result = process_file(args.path, "test", project_ctx)
            
            test_path = f"test_files/test_{base_name}{ext}"
            with open(test_path, "w", encoding="utf-8") as f:
                f.write(test_result)
            print(f"[+] TESTS GENERATED: {test_path}")

    else:
        print("[!] Invalid path. Target does not exist.")