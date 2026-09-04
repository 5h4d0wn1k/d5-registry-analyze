# D5 — Registry Analyzer

Windows registry hive parser and timeline generator for digital forensics.

## Overview

This project parses Windows registry hive files (e.g., `NTUSER.DAT`, `SYSTEM`, `SOFTWARE`) and extracts:
- Key enumeration and hierarchy
- Value name/type/data decoding
- Last-write timestamps for timeline analysis
- Hive header metadata and version

## Features

- **Hive parsing**: regf header, cells, nk/vk blocks
- **Key enumeration**: nested key tree with values
- **Value decoding**: REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ
- **Timeline**: sorts key last-write events chronologically
- **Subkey lists**: lf/lh/ri index handling

## Usage

```bash
python3 registry.py NTUSER.DAT
python3 registry.py C:/Windows/System32/config/SOFTWARE
```

## Example Output

```
=== D5 - Registry Analyzer ===
File: NTUSER.DAT
Hive size: 131072 bytes
Version: 1.5
Last written: 2024-01-15 09:30:12
Root key: 
...
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
