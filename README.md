# VulnOwl

**VulnOwl** is a small experimental PE (Portable Executable) static disassembler for Windows, written in C++ and powered by [Zydis](https://github.com/zyantific/zydis).

## About the Project

This project is not intended to be a large or production-ready tool. It is a personal learning project and a way for me to get back into programming after taking a longer break.

My goal is to refresh my C++ knowledge, improve my understanding of low-level programming, and explore topics that have interested me for a long time.

I want to use projects like VulnOwl to gradually deepen my knowledge in:

- **Windows Internals** – Understanding Windows architecture, processes, memory management, and the PE format.
- **Binary Exploitation** – Learning how software vulnerabilities work and how binary-level security research is performed.
- **Malware Analysis** – Understanding malicious software, reverse engineering, and analyzing suspicious binaries.
- **Malware Development** – Exploring malware-related techniques in controlled lab environments for educational and defensive security research.

## Current Features

- Opens Windows PE files using the Windows API.
- Maps files into memory for analysis.
- Parses PE headers and sections.
- Identifies executable sections.
- Uses Zydis to decode x86/x64 machine instructions.
- Formats disassembled instructions in Intel syntax.

## Technologies

- C++
- Windows API
- [Zydis](https://github.com/zyantific/zydis)
- PE (Portable Executable) format
- MinGW / GCC

## Project Status

VulnOwl is currently an early-stage experiment.

The code is still evolving, and there may be bugs, missing features, or incomplete implementations. I am building it step by step while learning more about Windows internals, reverse engineering, and binary analysis.

Contributions, suggestions, and constructive feedback are welcome.

## Disclaimer

This project is intended for educational purposes and legitimate security research. Any malware-related experimentation should be performed only in isolated, controlled environments and never against systems without authorization.

---

*Small project, big learning goals.*
