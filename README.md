# MC2S SNMP AUDIT

A Python tool focused on **defensive auditing and network diagnostics** to check **SNMPv1/v2c** configurations, test a single community string or a community wordlist, gather system information (scalars and tables), detect the vendor, and generate a structured JSON report with hardening recommendations.

---

## Project Structure

```text
snmp_pentest/
├── .venv/                  # Python virtual environment (ignored by git)[cite: 2]
├── reports/                # Generated JSON audit reports[cite: 2]
├── wordlists/
│   └── communities.txt     # Candidate SNMP community strings[cite: 2]
├── .gitignore              # Files and folders excluded from version control
├── README.md               # Project documentation[cite: 2]
├── requirements.txt        # Python dependencies
└── snmp_audit.py           # Main script[cite: 2]
```

---

## Installation

1. Create and activate the virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

---

## Usage

### Audit with a single community (default: `public`, SNMPv2c)

```powershell
python .\snmp_audit.py 192.168.100.4 --verbose
```

### Audit with a community wordlist

```powershell
python .\snmp_audit.py 192.168.100.4 -w .\wordlists\communities.txt -o .\reports\audit.json --verbose
```

### Audit using SNMPv1 with custom timeout and retries

```powershell
python .\snmp_audit.py 192.168.100.4 --version v1 -c public --timeout 3.0 --retries 2 -o .\reports\audit_v1.json
```

---

## Options

| Option | Description | Default |
| :--- | :--- | :--- |
| `target` | Target IP address or hostname | *(required)* |
| `-p`, `--port` | SNMP UDP port | `161` |
| `--version` | SNMP version (`v1`, `v2c`) | `v2c` |
| `-c`, `--community` | Single SNMP community string | `public` |
| `-w`, `--wordlist` | Path to a community wordlist (`wordlists/communities.txt` if omitted) | *(disabled)* |
| `--delay` | Delay in seconds between community tests | `0.05` |
| `--timeout` | Request timeout in seconds | `1.5` |
| `--retries` | Number of retries | `1` |
| `-o`, `--output` | Output JSON report file path | `reports/snmp_audit_report.json` |
| `--verbose` | Enable verbose (`DEBUG`) logging | disabled |

---

## Disclaimer

This tool is intended for system administration, diagnostics, and defensive auditing within an authorized environment (internal network, lab, or explicitly approved scope). You are solely responsible for how you use it.
