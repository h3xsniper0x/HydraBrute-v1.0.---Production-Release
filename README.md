# ⚡ HydraBrute v1.0
### High-Throughput Asynchronous Network Authentication Testing Engine
**Pure Python Security Assessment Framework (Zero External Dependencies)**
 
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/Architecture-AsyncIO%20%7C%20Non--blocking-brightgreen.svg)](#architecture)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-success.svg)](#zero-dependencies)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)](#cross-platform)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
 
---
 
## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT:** HydraBrute is designed strictly for **educational, academic, and authorized defensive auditing** purposes. Testing systems without prior explicit written authorization from the owner is illegal. The author assumes no liability for any misuse or damages caused by this tool.
 
---
 
## 📌 Problem Statement
Traditional network authentication auditing tools (e.g., standard multi-threaded brute-forcers) encounter significant architectural constraints:
1. **Thread Exhaustion & Overhead:** Spawning hundreds of OS threads causes severe memory bloat and continuous CPU context-switching.
2. **Disk I/O Bottlenecks:** Line-by-line reading of massive wordlists limits throughput and lacks dynamic payload adaptability.
3. **State Loss on Disruption:** Terminating a scan midway (`Ctrl+C` or network drops) discards state, forcing auditors to restart from zero.
 
---
 
## 💡 System Architecture
HydraBrute replaces the multi-threaded model with a single-threaded asynchronous event loop driven by Python's native `asyncio` and `socket` engines.
 
```text
[CLI Parser: argparse]
          |
          +-------------------------------+
          |                               |
[In-Memory Rule Mutator]       [Checkpoint Manager (.hbstate)]
(Leet / Case / Suffix)                    |
          |                               |
          +---------------+---------------+
                          |
             [AsyncIO Orchestrator Engine]
           (Controlled by asyncio.Semaphore)
                          |
         +----------------+----------------+
         |                |                |
[HTTP-Basic Stream]  [FTP Stream]    [SMTP Stream]
  (Raw TCP Sockets)   (RFC 959)        (RFC 4954)
```
 
---
 
## 🚀 Core Features
 
* **⚡ High-Throughput Async Engine:** Built entirely on non-blocking raw TCP streams capable of handling thousands of requests concurrently.
* **🧠 In-Memory Rule Mutation (`--mutate`):** Real-time generation of common password variations (Leet speak, capitalization, dynamic suffixes) in memory without disk writes.
* **🔄 State Checkpointing & Resumption (`--resume`):** Gracefully catches `Ctrl+C` interruptions, serializing the execution index to `.hbstate` for zero-loss recovery.
* **🛡️ Zero 3rd-Party Dependencies:** 100% Pure Python standard library implementation (`asyncio`, `socket`, `argparse`, `json`, `base64`).
* **📊 Dual Reporting:** Live terminal status dashboard alongside structured JSON report exports (`--export`).
 
---
 
## 📊 Benchmark Verification
 
Benchmarked against a localized target environment:
 
| Metrics | Local Isolated Benchmark |
| --- | --- |
| **Total Processed Requests** | **10,302 candidate pairs** |
| **Elapsed Execution Time** | **5.19 seconds** |
| **Throughput Speed** | **~1,986.77 req/s** |
| **Memory Footprint** | `< 35 MB RAM` |
 
---
 
## 🔧 Usage & Command Syntax
 
### 1. View Supported Protocols & Options
 
```bash
python hydra_brute.py --help
```
 
### 2. HTTP-Basic Authentication Audit
 
```bash
python hydra_brute.py http-basic -t 127.0.0.1 -p 8080 --path / -U users.txt -P passwords.txt -c 32 -F --export live_audit.json
```
 
### 3. Resuming an Interrupted Session
 
```bash
python hydra_brute.py http-basic -t 127.0.0.1 -p 8080 -U users.txt -P passwords.txt --resume
```
 
### 4. FTP Authentication Audit
 
```bash
python hydra_brute.py ftp -t 192.168.1.100 -p 21 -u admin -P passwords.txt -c 16 -F
```
 
---
 
## 📋 Academic Compliance Checklist (PLC-PR)
 
* [x] **Pure Python Standard Library:** Zero third-party dependencies (`pip`).
* [x] **Cross-Platform Operation:** Validated on Windows 10/11 & Linux.
* [x] **Subcommands Architecture:** Dedicated sub-parsers for supported protocols.
* [x] **Robust Error Handling:** Zero unhandled tracebacks on timeouts or network refusal.
* [x] **Bonus Objective:** Complete architectural deconstruction and async re-engineering of THC-Hydra.
 
---
 
## 📄 JSON Report Output Example (`live_audit.json`)
 
```json
{
    "engine": "HydraBrute",
    "version": "2.0.0",
    "target": "127.0.0.1",
    "port": 8080,
    "protocol": "http-basic",
    "timestamp": "2026-09-10 01:56:05",
    "results": [
        {
            "user": "admin",
            "pass": "admin2026!"
        }
    ]
}
```
 
---
 
## 📜 License
 
Distributed under the **MIT License**. See `LICENSE` for full details.\n
