# sl0ppy-UEFIScan
# sl0ppy UEFI Scanner

![GitHub release](https://img.shields.io/github/v/release/yourusername/sl0ppy-UefiScan)
![GitHub license](https://img.shields.io/github/license/yourusername/sl0ppy-UefiScan)
![GitHub stars](https://img.shields.io/github/stars/yourusername/sl0ppy-UefiScan)
![GitHub issues](https://img.shields.io/github/issues/yourusername/sl0ppy-UefiScan)

**Advanced UEFI Firmware Scanner with Auto-Updating Threat Intelligence**
```
* sl0ppy UEFI Scanner is a comprehensive tool for detecting UEFI firmware vulnerabilities, malware, and security misconfigurations. It performs deep analysis of UEFI components including firmware integrity checks, NVRAM validation, threat detection, and hardware security assessments.

```

## 🔍 Features

✅ **Comprehensive UEFI Analysis**
- Firmware integrity verification (BIOS, ME, EC regions)
- NVRAM variable validation (12+ critical variables)
- UEFI threat detection (20+ malware signatures)
- Hardware security checks (TPM, Intel TXT, Secure Boot)

✅ **Auto-Updating Threat Intelligence**
- Pulls latest YARA rules from multiple sources:
  - GitHub Yara-Rules repository
  - MISP threat intelligence feeds
  - Local custom rules
- Built-in fallback rules for offline operation

✅ **Advanced Detection Capabilities**
- Multi-stage confirmation system (YARA + NVRAM + module analysis)
- Confidence scoring (Low/Medium/High)
- CVE correlation and vulnerability detection
- Anti-evasion techniques (direct memory access, SPI flash checks)

✅ **Enterprise-Grade Reporting**
- JSON reports for SIEM integration
- Human-readable summary reports
- Prioritized recommendations by severity
- Timestamped logs with full detection details

✅ **Professional Output Formatting**
- Color-coded results for quick assessment
- Clear visual hierarchy with section headers
- Status indicators (✓ OK, ⚠ WARNING, ✗ CRITICAL)

---

## 📦 Installation

### Prerequisites
```
- **Linux system** (tested on Ubuntu 20.04/22.04, Debian 10/11)
- **Go 1.16+** (for building from source)
- **Root privileges** (for full functionality)
```
### Dependencies
# Install required packages:

```
sudo apt update
sudo apt install -y git golang yara tpm2-tools mokutil flashrom jq
Build from Source
git clone https://github.com/yourusername/sl0ppy-UefiScan.git
cd sl0ppy-UefiScan
go mod tidy
go build -o sl0ppy-uefiscan
Install (Optional)
sudo install -m 755 sl0ppy-uefiscan /usr/local/bin/
```
## 🚀 Usage
# Basic Scan
```
sudo ./sl0ppy-uefiscan
```
Example Output
==================================================
=            sl0ppy UEFI Scanner v3.3           =
=          [ FULL COVERAGE UEFI ANALYSIS ]        =
==================================================

## ⚠️  Run with sudo for full functionality!
```
⚠︸  Example: sudo ./sl0ppy-uefiscan

┌───────────────────────────────────────────────
│ Updating YARA Rules
└────────────────────────────────────────────---
  [INFO] Updated YARA rules from: GitHub\:APT_LoJax.yar, MISP, Built-in
  [INFO] Loaded 23 YARA rules

┌───────────────────────────────────────────────
│ System Information
└────────────────────────────────────────────---
  [INFO] Running on bare metal
  [INFO] CPU Information: [details]
  [INFO] OS Information: [details]

┌───────────────────────────────────────────────
│ Firmware Integrity Check
└────────────────────────────────────────────---
  [✓ OK] BIOS Region: a1b2c3d4... (TPM-bound)
  [✓ OK] SPI flash write protection is enabled
Report Location
All reports are saved to:
/var/log/sl0ppy_uefi_scan/

JSON report: report_[timestamp].json
Human-readable summary: summary_[timestamp].txt

Automated Scanning (Cron)
For daily scans at 3 AM:
echo "0 3 * * * root /path/to/sl0ppy-uefiscan >> /var/log/uefi_daily_scan.log 2>&1" | sudo tee /etc/cron.d/uefi_scan
```

## 📊 Detection Capabilities
# UEFI Threats Detected
```
BootkitsLoJax, MoonBounce, ESPecterCRITICALRootkitsLightEater, UEFI Rootkit GenericCRITICALSpywareFinFisher, UEFI SpyHIGHRATsUEFI RAT, GodMode SpywareCRITICALExploitsSMM Callout, TianoCore Buffer OverflowCRITICAL
Vulnerabilities Checked
CVE-2023-20569SMM Callout VulnerabilityCRITICALCVE-2022-31705TianoCore Buffer OverflowCRITICALCVE-2022-34303Intel ME Privilege EscalationHIGHCVE-2021-28210AMI BIOS SMM VulnerabilityCRITICALCVE-2022-28739UEFI Variable Authentication BypassCRITICAL
```

## 🛠 Configuration
# Custom YARA Rules
```
Add your custom YARA rules to:
/etc/sl0ppy/yara_rules.custom
The tool will automatically load these rules on each scan.
Trusted Hashes
Edit the trustedHashes map in the source code to add your known-good firmware hashes:
var trustedHashes = map[string]string{
    "BIOS Region": "your_bios_hash_here",
    "ME Region":   "your_me_hash_here",
    "EC Region":   "your_ec_hash_here",
}
```
## 📄 Reports
# JSON Report
```
Machine-readable report for integration with SIEM systems:
{
  "timestamp": "2023-11-16T14:30:00Z",
  "hostname": "my-server",
  "version": "3.3",
  "firmware": [
    {
      "region": "BIOS Region",
      "hash": "a1b2c3d4...",
      "expected": "expected_hash",
      "status": "OK",
      "tpm_bound": true
    }
  ],
  "malware": [
    {
      "name": "LoJax",
      "detected": false,
      "severity": "CRITICAL",
      "source": "GitHub\:APT_LoJax.yar",
      "category": "Bootkit",
      "confidence": "Low",
      "indicators": 0,
      "cve": "CVE-2018-4005"
    }
  ],
  "recommendations": [
    "Enable Intel TXT in BIOS for additional protection against firmware attacks",
    "Enable and configure TPM 2.0 in BIOS for secure boot and measured boot"
  ]
}
Human-Readable Summary
Formatted text report with color-coded results:
=== sl0ppy UEFI Scan Summary (v3.3) ===
Hostname: my-server
Timestamp: 2023-11-16T14:30:00Z
Rules Updated From: GitHub\:APT_LoJax.yar, MISP, Built-in

=== [ Firmware Integrity ] ===
BIOS Region    : ✓ OK
ME Region      : ✓ OK
EC Region      : ✓ OK

=== [ UEFI Threats ] ===
No threats detected

=== [ Security Recommendations ] ===
[01] Enable Intel TXT in BIOS for additional protection against firmware attacks
[02] Enable and configure TPM 2.0 in BIOS for secure boot and measured boot

✓ No critical issues found.
```
## 🔧 Integration
# SIEM Integration
```
Send JSON reports to your SIEM (Elasticsearch, Splunk, etc.):
curl -X POST "http://your-siem:9200/uefi-scans/_doc" \
     -H "Content-Type: application/json" \
     -d "@/var/log/sl0ppy_uefi_scan/report_*.json"
CHIPSEC Integration
Combine with CHIPSEC for deeper hardware analysis:
sudo python chipsec_main.py > chipsec_results.txt
./parse_chipsec.py chipsec_results.txt >> uefi_report.json
```
## 🤝 Contributing
Contributions are welcome! Please follow these guidelines:
```
Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request

Adding New Detection Rules

Add YARA rules to the appropriate source (GitHub, local file, etc.)
Update the uefiVulnerabilities list if adding new CVE checks
Add test cases for new detection logic

Code Style

Follow Go standard formatting (gofmt)
Use clear, descriptive variable names
Add comments for complex logic
Keep functions focused on single responsibilities

```
## 📋 License
This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## 🚨 Disclaimer
This tool is designed for authorized security assessments only. Only use this tool on systems you own or have explicit permission to test. Unauthorized scanning may violate laws and regulations.
The authors are not responsible for any misuse or damage caused by this program.

## 📬 Contact
For questions, suggestions, or security reports:
```
GitHub Issues: https://github.com/x0xr00t/sl0ppy-UefiScan/issues
```


#🙏 Acknowledgments

Yara-Rules for threat intelligence
MISP Project for shared indicators
fatih/color for terminal coloring
