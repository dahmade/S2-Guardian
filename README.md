# 🛡️ S2-Guardian: AI-Powered Security Auditor

An intelligent, lightweight Command Line Interface (CLI) tool designed to audit, fix, and analyze **C** and **Python** source code. Powered by Google's `gemini-2.5-flash-lite`, S2-Guardian acts as your personal Senior Security Engineer, applying rigorous logic to spot vulnerabilities before they become threats.

Built on the **Lamport Protocol** (Logic Before Syntax) and the **80/20 Rule** (focusing on the 20% of code that causes 80% of security risks).

---

## ⚠️ ETHICAL DISCLAIMER & USAGE WARNING

**The `--exploit` mode in this tool is strictly designed for EDUCATIONAL and DEFENSIVE purposes only.** Understanding how an attack is executed (e.g., memory corruption, buffer overflows) is a critical step in learning how to defend against it. This mode exists solely to visualize vulnerabilities and study their mechanics. 

**DO NOT** use this tool on systems, codebases, or applications you do not own or have explicit permission to test. Unethical, malicious, or illegal use of these concepts is strictly prohibited. You are fully responsible for your actions.

---

## ✨ Core Features & Capabilities

S2-Guardian operates in 4 distinct modes:

1. **🔍 Audit Mode (Default):** Scans your `.c` or `.py` files to detect logic flaws, memory leaks, OWASP vulnerabilities, and calculates Time/Space complexity (Big O).
2. **🛠️ Fix & Optimize (`--fix`):** Automatically patches detected vulnerabilities and refactors the code for efficiency. 
   * *Safety Net:* Automatically creates a backup (`.bak`) in a hidden `.s2_backup/` directory before modifying any files.
3. **🧪 QA Testing (`--test`):** Generates dedicated unit tests focused entirely on edge-cases (Null pointers, empty strings, boundaries) to stress-test your logic.
4. **💀 Hacker POV (`--exploit`):** Generates a Python Proof-of-Concept (PoC) and an ASCII Memory Map (Stack/Heap) to visualize how a vulnerability in C code could theoretically be exploited.

---

## 🚧 Current Limitations (Know Your Tool)

To use S2-Guardian effectively, you must understand its boundaries:
* **Context Limit (File Size):** The tool is designed for individual scripts and moderate-sized files. Sending massive codebases (thousands of lines) in a single run may exceed the API's token limit and cause an error.
* **API Dependency:** This current version requires an active internet connection and a valid Google Gemini API Key to function.
* **AI Hallucinations:** While highly accurate, the AI might occasionally suggest suboptimal fixes. Always review the patched code (which is why the automated `.bak` system is in place).

---

## 🛠️ Prerequisites & Setup

You only need the essentials to run this tool:
* **Python 3.10+**
* **GCC / Clang** (If you are compiling C files)

### Quick Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/dahmade/s2-guardian.git](https://github.com/dahmade/s2-guardian.git)
   cd s2-guardian

2. **Run the automated setup script, set your API key, and activate the environment:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   export GOOGLE_API_KEY="your_actual_gemini_api_key_here"
   source venv/bin/activate

---

## 🎯 Usage Examples
    ```bash
    # 1. Standard Security Audit:
        python3 s2_guardian.py vulnerable_code.c

    # 2. Auto-Fix (With automatic backup):
        python3 s2_guardian.py server_script.py --fix

    # 3. Generate Edge-Case Tests:
        python3 s2_guardian.py algorithm.c --test

    # 4. Exploit Analysis & Memory Map (C Only):
        python3 s2_guardian.py vulnerable_code.c --exploit

---

## 🔮 Future Roadmap

While S2-Guardian is highly functional and will significantly improve your code security, it is currently in its    initial phase. Massive architectural upgrades are currently in development. Without revealing too much, the upco    ming versions will introduce advanced capabilities designed to break current operational limits, ensuring deeper    independence, robust scalability, and an entirely new layer of logic analysis. Stay tuned.
