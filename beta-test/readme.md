## 🔹 What’s New in v1.4?
```
✅ Expanded YARA Rules – Added signatures for MosaicRegressor, FinFisher, TrickBoot, and more.
✅ Firmware Capsule Validation – Detects malicious UEFI capsules (e.g., BlackLotus).
✅ SPI Flash Protection Bypass Detection – Checks if BIOS write protection is disabled.
✅ TPM 2.0 Deep Inspection – Validates TPM NV indices, PCR banks, and attestation.
✅ Secure Boot Key Validation – Checks for revoked or malicious keys in db, dbx, KEK, and PK.
✅ SMM (System Management Mode) Exploit Detection – Scans for SMM callout vulnerabilities (e.g., CVE-2023-20569).
✅ DXE (Driver Execution Environment) Integrity Checks – Detects malicious DXE drivers.
✅ NVRAM Forensics – Deep inspection of NVRAM variables for persistence mechanisms.
✅ Hardware Root of Trust (RoT) Validation – Checks Intel Boot Guard, AMD Platform Secure Boot (PSB), and ARM TrustZone.
✅ UEFI Shell & Malicious EFI Applications – Scans for hidden UEFI shell binaries (e.g., Shell.efi in /EFI/).
✅ PCI Option ROM Validation – Detects suspicious PCI Option ROMs.
✅ Anti-Rollback Protection Check – Detects if firmware rollback attacks are possible.
✅ Measured Boot & IMA Validation – Checks if kernel-level integrity checks are enabled.
✅ Virtualization Escape Detection – Detects VM escape attempts (e.g., QEMU, VMware, KVM).
✅ Side-Channel Attack Mitigations – Checks for Spectre, Meltdown, and TPM side-channel protections.
✅ Detailed Reporting – Generates JSON and summary reports with actionable recommendations.
```
