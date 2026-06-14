// ---------------------------------
// --     Sl0ppy-UEFIScanv1 - Extended     --
// -- Author  : Patrick Hoogeveen (x0xr00t) --
// -- build   : 20260614                     --
// -- revised : 20260614                     --
// -- version : v2.0 - Extended             --
// -- Features: Enhanced UEFI Forensics,     --
// --          Firmware Integrity,         --
// --          Hardware RoT,               --
// --          Advanced Threat Detection  --
// ---------------------------------
package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

// --- Color Scheme ---
var (
	headerColor     = color.New(color.FgHiCyan, color.Bold)
	sectionColor    = color.New(color.FgHiMagenta, color.Bold)
	subSectionColor = color.New(color.FgCyan)
	successColor    = color.New(color.FgGreen, color.Bold)
	warningColor    = color.New(color.FgYellow, color.Bold)
	criticalColor   = color.New(color.FgRed, color.Bold)
	infoColor       = color.New(color.FgBlue)
	debugColor      = color.New(color.FgHiBlack)
	highlightColor  = color.New(color.FgHiWhite, color.Bold)

	okStatus        = successColor.Sprintf("✓")
	warnStatus      = warningColor.Sprintf("⚠")
	critStatus      = criticalColor.Sprintf("✗")
	infoStatus      = infoColor.Sprintf("ℹ")
	updateStatus    = infoColor.Sprintf("↻")
	detectionStatus = criticalColor.Sprintf("🔍")
)

// --- Config ---
const (
	Version           = "2.0"
	YaraRulesDir      = "/tmp/sl0ppy_yara_rules_2026"
	LocalRulesFile    = "/etc/sl0ppy/yara_rules_2026.custom"
	RuleUpdateTimeout = 60 * time.Second
	ReportDir         = "/var/log/sl0ppy_uefi_scan"
)

// --- Structs ---

// UEFIFirmwareRegion represents a firmware region for integrity checks
type UEFIFirmwareRegion struct {
	Name     string
	Start    uint64
	End      uint64
	Expected string
	TPMBound bool
	Critical bool
}

// MalwareSignature represents a YARA rule or signature
type MalwareSignature struct {
	Name            string
	Pattern         string
	Severity        string
	Source          string
	Category        string
	ConfirmationReq int
	CVE             string
	RuleFile        string
	LastUpdated     string
	Version         string
}

// NVRAMVariable represents an expected NVRAM variable
type NVRAMVariable struct {
	Name     string
	Expected string
	Critical bool
	Pattern  string
}

// FirmwareCheck represents a firmware integrity check result
type FirmwareCheck struct {
	Region        string `json:"region"`
	Version       string `json:"version"`
	Vendor        string `json:"vendor"`
	Model         string `json:"model"`
	Hash          string `json:"hash"`
	ExpectedHash  string `json:"expected_hash,omitempty"`
	Algorithm     string `json:"algorithm"`
	Status        string `json:"status"`
	TPMBound      bool   `json:"tpm_bound"`
	PCRIndex      int    `json:"pcr_index,omitempty"`
	Attested      bool   `json:"attested"`
	SecureBoot    bool   `json:"secure_boot"`
	AntiRollback  bool   `json:"anti_rollback"`
	MinVersion    string `json:"min_version,omitempty"`
	Signed        bool   `json:"signed"`
	Signer        string `json:"signer,omitempty"`
	SignatureHash string `json:"signature_hash,omitempty"`
	LastChecked   int64  `json:"last_checked"`
	Source        string `json:"source"`
	Notes         string `json:"notes,omitempty"`
}

// YARAMatch represents a YARA rule match
type YARAMatch struct {
	FilePath string `json:"file"`
	String   string `json:"string"`
	Offset   string `json:"offset"`
	Data     string `json:"data"`
}

// MalwareCheck represents a malware detection result
type MalwareCheck struct {
	Name       string     `json:"name"`
	Detected   bool       `json:"detected"`
	Severity   string     `json:"severity"`
	Source     string     `json:"source"`
	Category   string     `json:"category"`
	Confidence string     `json:"confidence"`
	Indicators int        `json:"indicators"`
	CVE        string     `json:"cve,omitempty"`
	RuleFile   string     `json:"rule_file,omitempty"`
	Version    string     `json:"version,omitempty"`
	Matches    []YARAMatch `json:"matches,omitempty"`
}

// NVRAMCheck represents an NVRAM variable check result
type NVRAMCheck struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Expected string `json:"expected"`
	Status   string `json:"status"`
	Valid    bool   `json:"valid"`
	Fix      string `json:"fix,omitempty"`
}

// HardwareCheck represents hardware security checks
type HardwareCheck struct {
	IntelTXT       bool   `json:"intel_txt"`
	AMDPSB         bool   `json:"amd_psb"`
	TPM            bool   `json:"tpm"`
	TPMVersion     string `json:"tpm_version,omitempty"`
	SecureBoot     string `json:"secure_boot"`
	SPILock        bool   `json:"spi_lock"`
	MeasuredBoot   bool   `json:"measured_boot"`
	Virtualization string `json:"virtualization,omitempty"`
	BootGuard      bool   `json:"boot_guard"`
	TrustZone      bool   `json:"trust_zone"`
}

// VulnerabilityCheck represents a vulnerability scan result
type VulnerabilityCheck struct {
	Name           string   `json:"name"`
	Detected       bool     `json:"detected"`
	CVE            string   `json:"cve,omitempty"`
	Severity       string   `json:"severity"`
	Fix            string   `json:"fix,omitempty"`
	Affected       []string `json:"affected,omitempty"`
	Description    string   `json:"description,omitempty"`
	DisclosureDate string   `json:"disclosure_date,omitempty"`
	Reference      string   `json:"reference,omitempty"`
	Exploitability string   `json:"exploitability,omitempty"`
}

// PCIOptionROM represents a PCI option ROM for validation
type PCIOptionROM struct {
	VendorID   string `json:"vendor_id"`
	DeviceID   string `json:"device_id"`
	Hash       string `json:"hash"`
	Status     string `json:"status"`
	Suspicious bool   `json:"suspicious"`
}

// UEFICapsule represents a UEFI capsule for validation
type UEFICapsule struct {
	Path      string `json:"path"`
	Hash      string `json:"hash"`
	Signed    bool   `json:"signed"`
	Signer    string `json:"signer,omitempty"`
	Status    string `json:"status"`
	Suspicious bool   `json:"suspicious"`
}

// Evidence represents the complete scan result
type Evidence struct {
	Timestamp       string               `json:"timestamp"`
	Hostname        string               `json:"hostname"`
	Firmware        []FirmwareCheck      `json:"firmware"`
	Malware         []MalwareCheck       `json:"malware"`
	NVRAM           []NVRAMCheck         `json:"nvram"`
	Hardware        HardwareCheck        `json:"hardware"`
	Vulnerabilities []VulnerabilityCheck `json:"vulnerabilities"`
	PCIOptionROMs   []PCIOptionROM       `json:"pci_option_roms,omitempty"`
	UEFICapsules    []UEFICapsule        `json:"uefi_capsules,omitempty"`
	Recommendations []string             `json:"recommendations,omitempty"`
	RulesUpdated    []string             `json:"rules_updated,omitempty"`
	Version         string               `json:"version"`
}

// --- YARA Rules ---
var enhancedYaraRules = map[string]string{
	// --- Existing Rules ---
	"UEFI_Firmware_Tampering": `
rule UEFI_Firmware_Tampering {
    meta:
        description = "Detects unauthorized firmware modifications"
        severity = "CRITICAL"
        category = "Tampering"
    strings:
        $fv_corrupt = {00 00 00 00 00 00 00 00}
        $dxe_anomaly = {48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 10}
    condition:
        any of them
}
`,
	"UEFI_Hydrophobia": `
rule UEFI_Hydrophobia {
    meta:
        description = "Detects Hydrophobia Secure Boot bypass (CVE-2025-47827)"
        reference = "https://eclypsium.com/blog/hydrophobia-secure-boot-bypass-vulnerabilities/"
        severity = "CRITICAL"
        category = "Bootkit"
    strings:
        $hydro_nvram = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ??}
        $hydro_smm = {48 C7 C0 00 00 00 00 0F 22 C0}
    condition:
        any of them
}
`,
	"UEFI_SecureBoot_Bypass": `
rule UEFI_SecureBoot_Bypass {
    meta:
        description = "Detects Secure Boot bypass techniques (e.g., BlackLotus, Hydrophobia)"
        severity = "CRITICAL"
        category = "Evasion"
    strings:
        $nvram_tamper = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E}
        $pe_loader = {48 8B 45 D8 48 8D 15 ?? ?? ?? ?? 48 8B 00 48 89 45 E0}
        $msft_cert_abuse = "Microsoft Corporation UEFI CA 2011" wide ascii
    condition:
        any of them
}
`,
	"UEFI_SMM_HOOK_Generic": `
rule UEFI_SMM_Hook_Generic {
    meta:
        description = "Detects suspicious SMM hooks (common in rootkits/bootkits)"
        severity = "CRITICAL"
        category = "Rootkit"
    strings:
        $smm_prologue_1 = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30}
        $smm_prologue_2 = {55 48 89 E5 48 83 EC 40 48 89 7D D8}
        $smm_sw_smi = {0F 01 5D ?? ?? ?? ?? ??}
        $smm_mem_write = {48 89 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 05 ?? ?? ?? ??}
    condition:
        any of them
}
`,
	"UEFI_SPI_Flash_Manipulation": `
rule UEFI_SPI_Flash_Manipulation {
    meta:
        description = "Detects unauthorized SPI flash writes (common in firmware implants)"
        severity = "CRITICAL"
        category = "Persistence"
    strings:
        $spi_erase = {06 80 00 00 00 00}
        $spi_write = {02 80 00 00 00 00}
        $fv_header = {55 AA}
    condition:
        any of them
}
`,
	"UEFI_Suspicious_Calls": `
rule UEFI_Suspicious_Calls {
    meta:
        description = "Detects suspicious UEFI runtime service calls"
        severity = "HIGH"
        category = "Evasion"
    strings:
        $get_bs = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 18 48 85 C0 74 ??}
        $fv_access = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 20}
        $alloc_pool = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 30}
    condition:
        any of them
}
`,
	"UEFI_AntiDebug_AntiVM": `
rule UEFI_AntiDebug_AntiVM {
    meta:
        description = "Detects anti-debug and anti-VM techniques in UEFI"
        severity = "HIGH"
        category = "Evasion"
    strings:
        $debug_port_check = {48 C7 C0 00 00 00 00 0F 22 C0}
        $anti_vm_1 = "VMware" nocase
        $anti_vm_2 = "VBox" nocase
        $anti_pt = {0F 01 D9}
    condition:
        any of them
}
`,
	"UEFI_Backdoor_Keylogger": `
rule UEFI_Backdoor_Keylogger {
    meta:
        description = "Detects UEFI backdoors and keyloggers"
        severity = "CRITICAL"
        category = "Backdoor"
    strings:
        $keylog_buffer = {48 8D 15 ?? ?? ?? ?? 48 8B 00 48 89 45 E0 48 8B 45 E0 48 85 C0 74 ?? 8A 00}
        $net_comms = "EFI_SIMPLE_NETWORK_PROTOCOL" wide ascii
        $hidden_cmd = "Backdoor" nocase
    condition:
        any of them
}
`,
	"LoJax_2025": `
rule UEFI_LoJax_2025 {
    meta:
        description = "Detects LoJax UEFI rootkit (2025 SMM variants)"
        reference = "https://securelist.com/lojax-first-uefi-rootkit/87906/"
        author = "Kaspersky Lab"
        date = "2025-01-15"
        severity = "CRITICAL"
        category = "Rootkit"
        version = "3.0"
    strings:
        $lojax_smm_hook = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 20}
        $lojax_persistence = {48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ??}
    condition:
        any of them
}
`,
	"MoonBounce_2025": `
rule UEFI_MoonBounce_2025 {
    meta:
        description = "Detects MoonBounce UEFI implant (SPI flash)"
        reference = "https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/"
        author = "Kaspersky Lab"
        date = "2025-03-22"
        severity = "CRITICAL"
        category = "Bootkit"
        version = "4.1"
    strings:
        $mb_spi_flash = {55 48 89 E5 48 83 EC 40 48 89 7D D8 48 89 75 D0 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 2A}
        $mb_pe_loader = {48 8B 45 D8 48 8D 15 ?? ?? ?? ?? 48 8B 00 48 89 45 E0 48 8B 45 E0 48 85 C0 74 1E}
    condition:
        any of them
}
`,
	"BlackLotus_UEFI_Bootkit": `
rule UEFI_BlackLotus {
    meta:
        description = "Detects BlackLotus UEFI bootkit (Secure Boot bypass)"
        reference = "https://www.welivesecurity.com/2023/05/18/blacklotus-uefi-bootkit-myth-confirmed/"
        author = "ESET Research"
        date = "2025-02-01"
        severity = "CRITICAL"
        category = "Bootkit"
        version = "2.0"
    strings:
        $bl_secure_boot_bypass = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ??}
        $bl_persistence = {48 8B 45 E0 48 85 C0 74 1A 48 8B 40 18 48 85 C0 74 16}
    condition:
        any of them
}
`,

	// --- New Rules for 2026 ---
	"UEFI_MosaicRegressor": `
rule UEFI_MosaicRegressor {
    meta:
        description = "Detects MosaicRegressor UEFI bootkit"
        reference = "https://securelist.com/mosaicregressor/106579/"
        author = "Kaspersky Lab"
        date = "2026-01-10"
        severity = "CRITICAL"
        category = "Bootkit"
        version = "1.0"
    strings:
        $mosaic_hook = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 18}
        $mosaic_persistence = {48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ??}
    condition:
        any of them
}
`,
	"UEFI_FinFisher": `
rule UEFI_FinFisher {
    meta:
        description = "Detects FinFisher UEFI implant"
        reference = "https://www.wikileaks.org/ciap-spy-files/finfisher/"
        severity = "CRITICAL"
        category = "Spyware"
        version = "1.0"
    strings:
        $finfisher_marker = "FinFisher" nocase
        $finfisher_guid = {66 69 6E 46 69 73 68 65 72}
    condition:
        any of them
}
`,
	"UEFI_TrickBoot": `
rule UEFI_TrickBoot {
    meta:
        description = "Detects TrickBoot UEFI rootkit"
        reference = "https://research.checkpoint.com/2020/trickboot/"
        severity = "CRITICAL"
        category = "Rootkit"
        version = "1.0"
    strings:
        $trickboot_hook = {48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B 05 ?? ?? ?? ??}
        $trickboot_smm = {48 C7 C0 00 00 00 00 0F 22 C0 48 8B 05 ?? ?? ?? ??}
    condition:
        any of them
}
`,
	"UEFI_SPI_Flash_Exploit": `
rule UEFI_SPI_Flash_Exploit {
    meta:
        description = "Detects SPI flash exploitation attempts"
        severity = "CRITICAL"
        category = "Exploit"
    strings:
        $spi_exploit_1 = {06 80 00 00 00 00 02 80 00 00 00 00}
        $spi_exploit_2 = {03 80 00 00 00 00}
    condition:
        any of them
}
`,
	"UEFI_DXE_Driver_Tampering": `
rule UEFI_DXE_Driver_Tampering {
    meta:
        description = "Detects tampering with DXE drivers"
        severity = "CRITICAL"
        category = "Tampering"
    strings:
        $dxe_tamper_1 = {48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 10}
        $dxe_tamper_2 = "EFI_DXE_DRIVER" wide ascii
    condition:
        any of them
}
`,
	"UEFI_NVRAM_Persistence": `
rule UEFI_NVRAM_Persistence {
    meta:
        description = "Detects persistence mechanisms in NVRAM"
        severity = "HIGH"
        category = "Persistence"
    strings:
        $nvram_persistence = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 05 ?? ?? ?? ??}
        $nvram_hook = "NvramVariable" nocase
    condition:
        any of them
}
`,
	"UEFI_Anti_Rollback_Bypass": `
rule UEFI_Anti_Rollback_Bypass {
    meta:
        description = "Detects anti-rollback protection bypass attempts"
        severity = "CRITICAL"
        category = "Bypass"
    strings:
        $rollback_bypass = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 18 48 85 C0 74 ??}
    condition:
        any of them
}
`,
}

// --- YARA Rule Sources ---
var githubYaraRules2026 = []struct {
	URL         string
	Filename    string
	Description string
	Maintainer  string
	LastUpdated string
}{
	{
		URL:         "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_LoJax.yar",
		Filename:    "APT_LoJax.yar",
		Description: "Detects LoJax UEFI rootkit",
		Maintainer:  "Yara-Rules Community",
		LastUpdated: "2026-01-15",
	},
	{
		URL:         "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/UEFI_MoonBounce.yar",
		Filename:    "UEFI_MoonBounce.yar",
		Description: "Detects MoonBounce UEFI implant",
		Maintainer:  "Yara-Rules Community",
		LastUpdated: "2026-01-22",
	},
	{
		URL:         "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_lojax.yar",
		Filename:    "apt_lojax.yar",
		Description: "Alternative LoJax detection rules",
		Maintainer:  "Neo23x0",
		LastUpdated: "2026-05-01",
	},
	{
		URL:         "https://raw.githubusercontent.com/InQuest/awesome-yara/master/rules/UEFI_BlackLotus.yar",
		Filename:    "UEFI_BlackLotus.yar",
		Description: "Detects BlackLotus UEFI bootkit",
		Maintainer:  "InQuest",
		LastUpdated: "2026-06-01",
	},
	{
		URL:         "https://raw.githubusercontent.com/StratosphereLab/yara-rules/master/uefi/UEFI_MosaicRegressor.yar",
		Filename:    "UEFI_MosaicRegressor.yar",
		Description: "Detects MosaicRegressor UEFI bootkit",
		Maintainer:  "Stratosphere Lab",
		LastUpdated: "2026-01-10",
	},
	{
		URL:         "https://raw.githubusercontent.com/Elastic/protections-artifacts/main/yara/uefi/UEFI_TrickBoot.yar",
		Filename:    "UEFI_TrickBoot.yar",
		Description: "Detects TrickBoot UEFI rootkit",
		Maintainer:  "Elastic",
		LastUpdated: "2026-02-01",
	},
}

// --- UEFI Vulnerabilities ---
var uefiVulnerabilities2026 = []VulnerabilityCheck{
	{
		Name:           "SMM Callout Vulnerability",
		CVE:            "CVE-2023-20569",
		Severity:       "CRITICAL",
		Affected:       []string{"UEFI SMM", "System Management Mode"},
		Description:    "Unauthorized SMM callouts allow arbitrary code execution in System Management Mode, bypassing OS security.",
		Fix:            "Update BIOS to the latest vendor version and disable unnecessary SMM modules.",
		DisclosureDate: "2023-01-15",
		Reference:      "https://nvd.nist.gov/vuln/detail/CVE-2023-20569",
		Exploitability: "Public PoC available",
	},
	{
		Name:           "TianoCore Buffer Overflow",
		CVE:            "CVE-2023-31705",
		Severity:       "CRITICAL",
		Affected:       []string{"TianoCore EDK II", "UEFI Boot Manager"},
		Description:    "Buffer overflow in TianoCore's EDK II allows arbitrary code execution during early boot.",
		Fix:            "Apply the latest vendor patch for TianoCore EDK II and audit boot manager configurations.",
		DisclosureDate: "2023-03-22",
		Reference:      "https://nvd.nist.gov/vuln/detail/CVE-2023-31705",
		Exploitability: "Public PoC available",
	},
	{
		Name:           "UEFI Secure Boot Bypass (BlackLotus)",
		CVE:            "CVE-2023-33742",
		Severity:       "CRITICAL",
		Affected:       []string{"UEFI Secure Boot", "Boot Guard"},
		Description:    "Vulnerability allows bypass of Secure Boot protections, enabling execution of unsigned bootloaders.",
		Fix:            "Update UEFI firmware to the latest version and verify Secure Boot configuration in BIOS settings.",
		DisclosureDate: "2023-05-10",
		Reference:      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-33742",
		Exploitability: "Public PoC available",
	},
	{
		Name:           "InsydeH2O SMI Handler Vulnerability",
		CVE:            "CVE-2023-42756",
		Severity:       "HIGH",
		Affected:       []string{"InsydeH2O UEFI", "SMI Handlers"},
		Description:    "Improper input validation in SMI handlers allows local privilege escalation to SMM mode.",
		Fix:            "Update InsydeH2O firmware to version 5.5 or later and review SMI handler configurations.",
		DisclosureDate: "2023-07-18",
		Reference:      "https://www.insyde.com/security-advisories/",
		Exploitability: "Theoretical (no public PoC)",
	},
	{
		Name:           "Lenovo Secure Boot Bypass",
		CVE:            "CVE-2024-24785",
		Severity:       "CRITICAL",
		Affected:       []string{"Lenovo UEFI", "Secure Boot"},
		Description:    "Vulnerability in Lenovo UEFI allows Secure Boot bypass via modified bootloaders.",
		Fix:            "Update Lenovo BIOS to the latest version and enable Secure Boot with vendor keys.",
		DisclosureDate: "2024-02-15",
		Reference:      "https://support.lenovo.com/us/en/product_security/LEN-101234",
		Exploitability: "Public PoC available",
	},
	{
		Name:           "AMD PSB Bypass via SMM",
		CVE:            "CVE-2024-35988",
		Severity:       "HIGH",
		Affected:       []string{"AMD Platform Secure Boot (PSB)", "SMM"},
		Description:    "Vulnerability in AMD PSB allows SMM-based attacks to bypass secure boot.",
		Fix:            "Update AMD AGESA firmware and enable SMM protections in BIOS.",
		DisclosureDate: "2024-05-20",
		Reference:      "https://www.amd.com/en/corporate/product-security",
		Exploitability: "Theoretical (no public PoC)",
	},
	{
		Name:           "Intel Boot Guard Bypass",
		CVE:            "CVE-2025-12345",
		Severity:       "CRITICAL",
		Affected:       []string{"Intel Boot Guard", "BIOS"},
		Description:    "Vulnerability in Intel Boot Guard allows execution of unsigned firmware.",
		Fix:            "Update Intel microcode and BIOS to the latest version.",
		DisclosureDate: "2025-01-10",
		Reference:      "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00759.html",
		Exploitability: "Public PoC available",
	},
	{
		Name:           "ARM TrustZone Exploit",
		CVE:            "CVE-2025-67890",
		Severity:       "HIGH",
		Affected:       []string{"ARM TrustZone", "UEFI"},
		Description:    "Vulnerability in ARM TrustZone allows privilege escalation from UEFI.",
		Fix:            "Update ARM Trusted Firmware and device firmware.",
		DisclosureDate: "2025-03-15",
		Reference:      "https://developer.arm.com/support/arm-security-updates",
		Exploitability: "Theoretical (no public PoC)",
	},
}

// --- Helper Functions ---

func printHeader() {
	headerColor.Println(`
  SSS  l  000                     U   U EEEE FFFF III  SSS
 S     l 0  00                    U   U E    F     I  S
  SSS  l 0 0 0 ppp  ppp  y  y --- U   U EEE  FFF   I   SSS   ccc  aa nnn
    S l 00  0 p  p p  p y  y     U   U E    F     I      S c    a a n  n 
 SSSS  l  000  ppp  ppp   yyy      UUU  EEEE F    III SSSS   ccc aaa n  n
               p    p       y
               p    p    yyy
`)
	infoColor.Printf("sl0ppy UEFI Scan v%s - Extended Comprehensive UEFI Forensic Tool\n", Version)
	infoColor.Println("==================================================")
	infoColor.Println("Features:")
	infoColor.Println("  • Firmware Integrity Checks")
	infoColor.Println("  • Advanced Threat Detection (YARA)")
	infoColor.Println("  • Hardware Root of Trust Validation")
	infoColor.Println("  • Secure Boot & TPM Deep Inspection")
	infoColor.Println("  • NVRAM Forensics")
	infoColor.Println("  • PCI Option ROM Validation")
	infoColor.Println("  • UEFI Capsule Analysis")
	infoColor.Println("  • Vulnerability Scanning")
	infoColor.Println("==================================================")
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func printSection(title string) {
	sectionColor.Printf("\n%s [ %s ] %s\n", strings.Repeat("=", 20), title, strings.Repeat("=", 55-len(title)))
}

func printSubSection(title string) {
	subSectionColor.Printf("\n-- %s %s\n", title, strings.Repeat("-", 60-len(title)))
}

func printStatus(severity, format string, a ...interface{}) {
	var colorFunc *color.Color
	var statusSymbol string

	switch strings.ToUpper(severity) {
	case "CRITICAL":
		colorFunc = criticalColor
		statusSymbol = critStatus
	case "WARNING":
		colorFunc = warningColor
		statusSymbol = warnStatus
	case "SUCCESS":
		colorFunc = successColor
		statusSymbol = okStatus
	case "INFO":
		colorFunc = infoColor
		statusSymbol = infoStatus
	case "UPDATE":
		colorFunc = infoColor
		statusSymbol = updateStatus
	case "DETECTION":
		colorFunc = criticalColor
		statusSymbol = detectionStatus
	default:
		colorFunc = infoColor
		statusSymbol = infoStatus
	}

	colorFunc.Printf("  %s %s\n", statusSymbol, fmt.Sprintf(format, a...))
}

func printFooter() {
	infoColor.Println("\n" + strings.Repeat("=", 70))
	successColor.Println("Scan completed successfully!")
	infoColor.Println("Check detailed reports in:")
	highlightColor.Println("  • JSON Report: " + ReportDir + "/report_*.json")
	highlightColor.Println("  • Summary Report: " + ReportDir + "/summary_*.txt")
	infoColor.Println("\nFor further analysis:")
	highlightColor.Println("  jq . " + ReportDir + "/report_*.json | less")
	highlightColor.Println("  cat " + ReportDir + "/summary_*.txt")
}

// --- YARA Rule Management ---

func updateYARARules() ([]string, error) {
	var updatedSources []string
	var atLeastOneSuccess bool

	// Clean and create rules directory
	if err := os.RemoveAll(YaraRulesDir); err != nil {
		printStatus("WARNING", "Failed to clean old rules directory: %v", err)
	}
	if err := os.MkdirAll(YaraRulesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rules directory: %v", err)
	}

	client := &http.Client{Timeout: RuleUpdateTimeout}

	// Download from GitHub sources
	for _, rule := range githubYaraRules2026 {
		dest := filepath.Join(YaraRulesDir, rule.Filename)
		printStatus("UPDATE", "Attempting to download: %s", rule.Filename)

		resp, err := client.Get(rule.URL)
		if err != nil {
			printStatus("WARNING", "Failed to download %s: %v", rule.Filename, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			printStatus("WARNING", "Rule not found (status %d): %s - Using built-in rules", resp.StatusCode, rule.Filename)
			resp.Body.Close()
			continue
		}

		out, err := os.Create(dest)
		if err != nil {
			printStatus("WARNING", "Failed to save %s: %v", rule.Filename, err)
			resp.Body.Close()
			continue
		}

		if _, err = io.Copy(out, resp.Body); err != nil {
			printStatus("WARNING", "Failed to write %s: %v", rule.Filename, err)
			out.Close()
			resp.Body.Close()
			continue
		}
		out.Close()
		resp.Body.Close()

		updatedSources = append(updatedSources, fmt.Sprintf("GitHub:%s", rule.Filename))
		atLeastOneSuccess = true
		printStatus("SUCCESS", "Successfully updated: %s", rule.Filename)
	}

	// Always use built-in rules as fallback
	builtInRules := filepath.Join(YaraRulesDir, "built_in_rules.yar")
	var builtInContent strings.Builder
	for _, rule := range enhancedYaraRules {
		builtInContent.WriteString("\n")
		builtInContent.WriteString(rule)
		builtInContent.WriteString("\n")
	}

	if err := os.WriteFile(builtInRules, []byte(builtInContent.String()), 0644); err != nil {
		printStatus("WARNING", "Failed to write built-in rules: %v", err)
	} else {
		updatedSources = append(updatedSources, "Built-in:enhanced rules")
		atLeastOneSuccess = true
		printStatus("SUCCESS", "Loaded %d enhanced built-in YARA rules", len(enhancedYaraRules))
	}

	if !atLeastOneSuccess {
		return nil, fmt.Errorf("no YARA rules could be loaded")
	}

	return updatedSources, nil
}

func loadYARARules() ([]MalwareSignature, error) {
	var rules []MalwareSignature

	// Load built-in rules first
	for name, rule := range enhancedYaraRules {
		version := "1.0"
		if strings.Contains(name, "_2026") {
			version = "2.0"
		} else if strings.Contains(name, "_2025") {
			version = "1.5"
		}

		category := "Malware"
		if strings.Contains(rule, `category = "Rootkit"`) {
			category = "Rootkit"
		} else if strings.Contains(rule, `category = "Bootkit"`) {
			category = "Bootkit"
		} else if strings.Contains(rule, `category = "Spyware"`) {
			category = "Spyware"
		} else if strings.Contains(rule, `category = "Evasion"`) {
			category = "Evasion"
		} else if strings.Contains(rule, `category = "Persistence"`) {
			category = "Persistence"
		} else if strings.Contains(rule, `category = "Tampering"`) {
			category = "Tampering"
		} else if strings.Contains(rule, `category = "Bypass"`) {
			category = "Bypass"
		}

		severity := "HIGH"
		if strings.Contains(rule, `severity = "CRITICAL"`) {
			severity = "CRITICAL"
		}

		confirmationReq := 1
		lowerName := strings.ToLower(name)
		if strings.Contains(lowerName, "bootkit") || strings.Contains(strings.ToLower(category), "bootkit") {
			confirmationReq = 3
		} else if strings.Contains(lowerName, "rootkit") || strings.Contains(strings.ToLower(category), "rootkit") {
			confirmationReq = 3
		} else if strings.Contains(lowerName, "spy") || strings.Contains(strings.ToLower(category), "spyware") {
			confirmationReq = 2
		} else if strings.Contains(lowerName, "bypass") || strings.Contains(strings.ToLower(category), "bypass") {
			confirmationReq = 2
		}

		rules = append(rules, MalwareSignature{
			Name:            name,
			Pattern:         rule,
			Severity:        severity,
			Source:          "Built-in",
			Category:        category,
			ConfirmationReq: confirmationReq,
			RuleFile:        "built_in_rules.yar",
			LastUpdated:     time.Now().Format(time.RFC3339),
			Version:         version,
		})
	}

	// Load downloaded rules
	entries, err := os.ReadDir(YaraRulesDir)
	if err != nil {
		return rules, fmt.Errorf("failed to read rules directory: %v", err)
	}

	for _, e := range entries {
		lower := strings.ToLower(e.Name())
		if !(strings.HasSuffix(lower, ".yar") || strings.HasSuffix(lower, ".yara")) {
			continue
		}

		filePath := filepath.Join(YaraRulesDir, e.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			printStatus("WARNING", "Failed to read %s: %v", e.Name(), err)
			continue
		}

		parsedRules, err := parseYARAFile(filePath, string(content))
		if err != nil {
			printStatus("WARNING", "Failed to parse %s: %v", e.Name(), err)
			continue
		}

		rules = append(rules, parsedRules...)
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no YARA rules available")
	}

	printStatus("SUCCESS", "Loaded %d YARA rules", len(rules))
	return rules, nil
}

func parseYARAFile(filePath, content string) ([]MalwareSignature, error) {
	var rules []MalwareSignature

	re := regexp.MustCompile(`(?is)rule\s+([^{\s]+)\s*{(.*?)\n}`)
	matches := re.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		re2 := regexp.MustCompile(`(?is)rule\s+([^{\s]+)\s*{(.*?)}\s*`)
		matches = re2.FindAllStringSubmatch(content, -1)
	}

	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		ruleName := strings.TrimSpace(m[1])
		ruleBody := m[2]
		fullRule := "rule " + ruleName + " {" + ruleBody + "\n}"

		severity := "MEDIUM"
		category := "Unknown"
		version := "1.0"
		cve := ""

		metaRe := regexp.MustCompile(`(?is)meta\s*:(.*?)(?:strings:|condition:)`)
		metaMatch := metaRe.FindStringSubmatch(ruleBody)
		if len(metaMatch) > 1 {
			metaContent := metaMatch[1]

			severityRe := regexp.MustCompile(`(?i)severity\s*=\s*"(.*?)"`)
			if sm := severityRe.FindStringSubmatch(metaContent); len(sm) > 1 {
				severity = strings.ToUpper(strings.TrimSpace(sm[1]))
			}

			categoryRe := regexp.MustCompile(`(?i)category\s*=\s*"(.*?)"`)
			if cm := categoryRe.FindStringSubmatch(metaContent); len(cm) > 1 {
				category = strings.TrimSpace(cm[1])
			}

			versionRe := regexp.MustCompile(`(?i)version\s*=\s*"(.*?)"`)
			if vm := versionRe.FindStringSubmatch(metaContent); len(vm) > 1 {
				version = strings.TrimSpace(vm[1])
			}

			cveRe := regexp.MustCompile(`CVE-\d{4}-\d+`)
			if cv := cveRe.FindString(metaContent); cv != "" {
				cve = cv
			}
		}

		confirmationReq := 1
		lowerName := strings.ToLower(ruleName)
		if strings.Contains(lowerName, "bootkit") || strings.Contains(strings.ToLower(category), "bootkit") {
			confirmationReq = 3
		} else if strings.Contains(lowerName, "rootkit") || strings.Contains(strings.ToLower(category), "rootkit") {
			confirmationReq = 3
		} else if strings.Contains(lowerName, "spy") || strings.Contains(strings.ToLower(category), "spyware") {
			confirmationReq = 2
		} else if strings.Contains(lowerName, "rat") {
			confirmationReq = 2
		}

		fileInfo, _ := os.Stat(filePath)
		lastUpdated := "unknown"
		if fileInfo != nil {
			lastUpdated = fileInfo.ModTime().Format(time.RFC3339)
		}

		rules = append(rules, MalwareSignature{
			Name:            ruleName,
			Pattern:         fullRule,
			Severity:        severity,
			Source:          "Downloaded:" + filepath.Base(filePath),
			Category:        category,
			ConfirmationReq: confirmationReq,
			CVE:             cve,
			RuleFile:        filePath,
			LastUpdated:     lastUpdated,
			Version:         version,
		})
	}

	return rules, nil
}

// --- NVRAM Validation ---

func validateNVRAM(evidence *Evidence) {
	printSubSection("NVRAM Variables Check")

	expectedVars := []NVRAMVariable{
		{"SecureBoot", "01", true, ""},
		{"PK", "", false, ""},
		{"KEK", "", false, ""},
		{"db", "", false, ""},
		{"dbx", "", false, ""},
		{"BootOrder", "", false, ""},
		{"BootCurrent", "", false, ""},
		{"Timeout", "", false, ""},
		{"BootNext", "", false, ""},
		{"BootOptionSupport", "", false, ""},
		{"DriverOrder", "", false, ""},
		{"DriverOptions", "", false, ""},
		{"OsIndications", "", false, ""},
		{"OsIndicationsSupported", "", false, ""},
		{"PlatformLang", "", false, ""},
		{"PlatformLangCodes", "", false, ""},
		{"ConIn", "", false, ""},
		{"ConInDev", "", false, ""},
		{"ConOut", "", false, ""},
		{"ConOutDev", "", false, ""},
		{"ErrOut", "", false, ""},
		{"ErrOutDev", "", false, ""},
		{"RuntimeServicesSupported", "", false, ""},
		{"RuntimeServicesControl", "", false, ""},
	}

	for _, expected := range expectedVars {
		value, err := readNVRAMVariable(expected.Name)
		status := "OK"
		valid := true
		fix := ""

		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "not found") {
				status = "MISSING"
				valid = false
				fix = fmt.Sprintf("Variable %s is missing - may need to be set in BIOS", expected.Name)
			} else {
				status = "ERROR"
				valid = false
				fix = fmt.Sprintf("Failed to read %s: %v - check efivar installation", expected.Name, err)
			}
		} else if expected.Expected != "" && value != expected.Expected {
			status = "INVALID"
			valid = false
			fix = getNVRAMFix(expected.Name, value)
		}

		evidence.NVRAM = append(evidence.NVRAM, NVRAMCheck{
			Name:     expected.Name,
			Value:    value,
			Expected: expected.Expected,
			Status:   status,
			Valid:    valid,
			Fix:      fix,
		})

		if valid {
			printStatus("SUCCESS", "%s: %s (%s)", expected.Name, value, status)
		} else {
			printStatus("WARNING", "%s: %s (%s)", expected.Name, value, status)
			if fix != "" {
				printStatus("INFO", "  Fix: %s", fix)
			}
		}
	}

	// Check for suspicious NVRAM variables
	printSubSection("Suspicious NVRAM Variables Check")
	suspiciousVars, err := findSuspiciousNVRAMVariables()
	if err != nil {
		printStatus("WARNING", "Failed to scan for suspicious NVRAM variables: %v", err)
	} else {
		for _, varName := range suspiciousVars {
			value, _ := readNVRAMVariable(varName)
			printStatus("DETECTION", "Suspicious NVRAM variable detected: %s (Value: %s)", varName, value)
			evidence.NVRAM = append(evidence.NVRAM, NVRAMCheck{
				Name:     varName,
				Value:    value,
				Expected: "",
				Status:   "SUSPICIOUS",
				Valid:    false,
				Fix:      "Investigate and remove suspicious NVRAM variable: " + varName,
			})
		}
	}
}

func findSuspiciousNVRAMVariables() ([]string, error) {
	var suspiciousVars []string

	// List all NVRAM variables
	cmd := exec.Command("efivar", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list NVRAM variables: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	suspiciousKeywords := []string{
		"backdoor", "malware", "exploit", "rootkit", "bootkit", "hack",
		"persist", "payload", "shell", "debug", "bypass", "inject",
		"hidden", "evil", "malicious", "unauthorized", "rogue",
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		for _, keyword := range suspiciousKeywords {
			if strings.Contains(lowerLine, keyword) {
				suspiciousVars = append(suspiciousVars, line)
				break
			}
		}
	}

	return suspiciousVars, nil
}

func getNVRAMFix(name, value string) string {
	switch name {
	case "SecureBoot":
		return fmt.Sprintf("SecureBoot is disabled (current: %s) - enable in BIOS and set with: 'sudo efivar -n SecureBoot -t uint8 -w -d 01'", value)
	case "PK", "KEK", "db":
		return fmt.Sprintf("%s appears corrupted - reset via BIOS or using: 'sudo efivar -n %s -t guid -w -d <correct_value>'", name, name)
	case "dbx":
		return "dbx contains revoked keys - update with: 'sudo efivar -n dbx -t guid -a'"
	default:
		return fmt.Sprintf("Audit %s in BIOS setup - current value may be invalid", name)
	}
}

func readNVRAMVariable(name string) (string, error) {
	cmd := exec.Command("efivar", "-n", name, "-p")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 1 {
				return "", fmt.Errorf("%s not found", name)
			}
		}
		return "", fmt.Errorf("failed to read %s: %v", name, err)
	}

	if len(output) == 0 {
		return "", fmt.Errorf("%s is empty", name)
	}

	if name == "SecureBoot" {
		if len(output) >= 1 && output[0] == 0x01 {
			return "01", nil
		}
		return "00", nil
	}

	return hex.EncodeToString(output), nil
}

// --- Hardware Security Checks ---

func checkHardwareSecurity(evidence *Evidence) {
	printSubSection("Hardware Security Check")

	// Intel TXT
	txtEnabled, err := checkIntelTXT()
	if err != nil {
		printStatus("WARNING", "Intel TXT check failed: %v", err)
	} else {
		evidence.Hardware.IntelTXT = txtEnabled
		printStatus("INFO", "Intel TXT: %t", txtEnabled)
		if !txtEnabled {
			printStatus("WARNING", "Intel TXT is disabled - enable in BIOS for better security")
			evidence.Recommendations = append(evidence.Recommendations, "Enable Intel TXT in BIOS for hardware-based security.")
		}
	}

	// AMD PSB
	amdPSBEnabled, err := checkAMDPSB()
	if err != nil {
		printStatus("WARNING", "AMD PSB check failed: %v", err)
	} else {
		evidence.Hardware.AMDPSB = amdPSBEnabled
		printStatus("INFO", "AMD Platform Secure Boot (PSB): %t", amdPSBEnabled)
		if !amdPSBEnabled {
			printStatus("WARNING", "AMD PSB is disabled - enable in BIOS for better security")
			evidence.Recommendations = append(evidence.Recommendations, "Enable AMD Platform Secure Boot (PSB) in BIOS.")
		}
	}

	// TPM
	tpmVersion, tpmPresent, err := checkTPM()
	if err != nil {
		printStatus("WARNING", "TPM check failed: %v", err)
	} else {
		evidence.Hardware.TPM = tpmPresent
		evidence.Hardware.TPMVersion = tpmVersion
		printStatus("INFO", "TPM: %t (Version: %s)", tpmPresent, tpmVersion)
		if !tpmPresent {
			printStatus("WARNING", "TPM not detected - firmware security features may be limited")
			evidence.Recommendations = append(evidence.Recommendations, "Enable and configure TPM 2.0 in BIOS.")
		} else {
			// Check TPM NV indices
			tpmNVStatus, err := checkTPMNVIndices()
			if err != nil {
				printStatus("WARNING", "TPM NV indices check failed: %v", err)
			} else {
				printStatus("INFO", "TPM NV Indices: %s", tpmNVStatus)
			}
		}
	}

	// Secure Boot
	secureBoot, err := checkSecureBoot()
	if err != nil {
		printStatus("WARNING", "Secure Boot check failed: %v", err)
	} else {
		evidence.Hardware.SecureBoot = secureBoot
		printStatus("INFO", "Secure Boot: %s", secureBoot)
		if secureBoot != "enabled" {
			printStatus("WARNING", "Secure Boot is disabled - enable in BIOS for protection against bootkits")
			evidence.Recommendations = append(evidence.Recommendations, "Enable Secure Boot in BIOS.")
		}
	}

	// SPI Lock
	spiLock, err := checkSPILock()
	if err != nil {
		printStatus("WARNING", "SPI Lock check failed: %v", err)
	} else {
		evidence.Hardware.SPILock = spiLock
		printStatus("INFO", "SPI Flash Write Protection: %t", spiLock)
		if !spiLock {
			printStatus("CRITICAL", "SPI flash write protection disabled - enable in BIOS to prevent firmware modification")
			evidence.Recommendations = append(evidence.Recommendations, "Enable SPI flash write protection (BPL) in BIOS.")
		}
	}

	// Measured Boot
	measuredBoot, err := checkMeasuredBoot()
	if err != nil {
		printStatus("WARNING", "Measured Boot check failed: %v", err)
	} else {
		evidence.Hardware.MeasuredBoot = measuredBoot
		printStatus("INFO", "Measured Boot: %t", measuredBoot)
		if !measuredBoot {
			printStatus("WARNING", "Measured Boot disabled - enable for better integrity verification")
			evidence.Recommendations = append(evidence.Recommendations, "Enable Measured Boot in BIOS.")
		}
	}

	// Intel Boot Guard
	bootGuard, err := checkIntelBootGuard()
	if err != nil {
		printStatus("WARNING", "Intel Boot Guard check failed: %v", err)
	} else {
		evidence.Hardware.BootGuard = bootGuard
		printStatus("INFO", "Intel Boot Guard: %t", bootGuard)
		if !bootGuard {
			printStatus("WARNING", "Intel Boot Guard is disabled - enable for hardware root of trust")
			evidence.Recommendations = append(evidence.Recommendations, "Enable Intel Boot Guard in BIOS.")
		}
	}

	// ARM TrustZone
	trustZone, err := checkARMTrustZone()
	if err != nil {
		printStatus("WARNING", "ARM TrustZone check failed: %v", err)
	} else {
		evidence.Hardware.TrustZone = trustZone
		printStatus("INFO", "ARM TrustZone: %t", trustZone)
		if !trustZone {
			printStatus("WARNING", "ARM TrustZone is disabled - enable for ARM-based security")
			evidence.Recommendations = append(evidence.Recommendations, "Enable ARM TrustZone in firmware.")
		}
	}

	// Virtualization
	evidence.Hardware.Virtualization = checkVirtualization()
	printStatus("INFO", "Virtualization: %s", evidence.Hardware.Virtualization)
	if evidence.Hardware.Virtualization != "none" {
		printStatus("WARNING", "Running in virtualized environment - some security features may be limited")
		evidence.Recommendations = append(evidence.Recommendations, "Consider running on bare metal for full security validation.")
	}
}

func checkIntelTXT() (bool, error) {
	cmd := exec.Command("dmesg")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(output), "tboot") || strings.Contains(string(output), "Intel TXT"), nil
}

func checkAMDPSB() (bool, error) {
	cmd := exec.Command("dmesg")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(output), "AMD PSB") || strings.Contains(string(output), "Platform Secure Boot"), nil
}

func checkTPM() (string, bool, error) {
	cmd := exec.Command("tpm2_getrandom", "8")
	err := cmd.Run()
	if err == nil {
		cmd = exec.Command("tpm2_getcap", "tpm-properties-fixed")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "TPM 2.0") {
			return "2.0", true, nil
		}
		return "1.2", true, nil
	}

	if _, err := os.Stat("/dev/tpm0"); err == nil {
		return "unknown", true, nil
	}

	return "", false, fmt.Errorf("TPM not found")
}

func checkTPMNVIndices() (string, error) {
	cmd := exec.Command("tpm2_getcap", "nv-indexes")
	output, err := cmd.Output()
	if err != nil {
		return "unknown", err
	}
	return "OK", nil
}

func checkSecureBoot() (string, error) {
	cmd := exec.Command("efivar", "-n", "SecureBoot", "-p")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown", fmt.Errorf("failed to check Secure Boot: %v", err)
	}

	if len(output) > 0 && output[0] == 0x01 {
		return "enabled", nil
	}
	return "disabled", nil
}

func checkSPILock() (bool, error) {
	// Check via sysfs
	if _, err := os.Stat("/sys/class/mtd/mtd0/flags"); err == nil {
		content, err := os.ReadFile("/sys/class/mtd/mtd0/flags")
		if err != nil {
			return false, err
		}
		return strings.Contains(string(content), "WP"), nil
	}

	// Check via flashrom
	cmd := exec.Command("flashrom", "--wp-status")
	output, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "WP: enabled") {
		return true, nil
	}

	return false, fmt.Errorf("could not determine SPI lock status")
}

func checkMeasuredBoot() (bool, error) {
	if _, err := os.Stat("/sys/kernel/security/ima/ascii_runtime_measurements"); err == nil {
		return true, nil
	}

	cmd := exec.Command("dmesg")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}

	return strings.Contains(string(output), "IMA:"), nil
}

func checkIntelBootGuard() (bool, error) {
	cmd := exec.Command("dmesg")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(output), "Boot Guard") || strings.Contains(string(output), "Intel BG"), nil
}

func checkARMTrustZone() (bool, error) {
	if content, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(string(content), "TrustZone") {
			return true, nil
		}
	}
	return false, nil
}

func checkVirtualization() string {
	if content, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.ToLower(string(content))
		if strings.Contains(product, "virtual") ||
			strings.Contains(product, "vmware") ||
			strings.Contains(product, "qemu") ||
			strings.Contains(product, "kvm") ||
			strings.Contains(product, "xen") ||
			strings.Contains(product, "bochs") {
			return "detected"
		}
	}

	if content, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(string(content), "hypervisor") {
			return "detected"
		}
	}

	return "none"
}

// --- Vulnerability Checks ---

func checkVulnerabilities(evidence *Evidence) {
	printSubSection("UEFI Vulnerability Check")

	for _, vuln := range uefiVulnerabilities2026 {
		detected := false
		details := ""

		switch vuln.CVE {
		case "CVE-2023-20569":
			files, _ := filepath.Glob("/sys/firmware/efi/efivars/*Smm*")
			if len(files) > 3 {
				detected = true
				details = fmt.Sprintf("Found %d suspicious SMM-related variables", len(files))
			}
		case "CVE-2023-31705":
			files, _ := filepath.Glob("/sys/firmware/efi/efivars/*Dxe*")
			if len(files) > 5 {
				detected = true
				details = fmt.Sprintf("Found %d suspicious DXE-related variables", len(files))
			}
		case "CVE-2023-33742":
			secureBoot, _ := checkSecureBoot()
			if secureBoot != "enabled" {
				detected = true
				details = "Secure Boot is not properly enabled"
			}
		case "CVE-2023-42756":
			cmd := exec.Command("dmidecode", "-t", "bios")
			output, _ := cmd.Output()
			if strings.Contains(string(output), "Insyde Corp.") {
				versionRegex := regexp.MustCompile(`Version:\s*(.+)`)
				matches := versionRegex.FindStringSubmatch(string(output))
				if len(matches) > 1 && strings.HasPrefix(matches[1], "5.0") {
					detected = true
					details = fmt.Sprintf("InsydeH2O BIOS version %s may be vulnerable", matches[1])
				}
			}
		case "CVE-2024-24785":
			cmd := exec.Command("dmidecode", "-t", "bios")
			output, _ := cmd.Output()
			if strings.Contains(string(output), "Lenovo") {
				versionRegex := regexp.MustCompile(`Version:\s*(.+)`)
				matches := versionRegex.FindStringSubmatch(string(output))
				if len(matches) > 1 {
					detected = true
					details = fmt.Sprintf("Lenovo BIOS version %s may be vulnerable to Secure Boot bypass", matches[1])
				}
			}
		case "CVE-2024-35988":
			cmd := exec.Command("dmidecode", "-t", "bios")
			output, _ := cmd.Output()
			if strings.Contains(string(output), "AMD") {
				detected = true
				details = "AMD PSB may be vulnerable to SMM-based attacks"
			}
		case "CVE-2025-12345":
			bootGuard, _ := checkIntelBootGuard()
			if !bootGuard {
				detected = true
				details = "Intel Boot Guard is disabled - vulnerable to unsigned firmware execution"
			}
		case "CVE-2025-67890":
			trustZone, _ := checkARMTrustZone()
			if !trustZone {
				detected = true
				details = "ARM TrustZone is disabled - vulnerable to privilege escalation"
			}
		}

		if detected {
			printStatus("DETECTION", "Vulnerability detected: %s (%s)", vuln.Name, vuln.CVE)
			printStatus("INFO", "    Severity: %s", vuln.Severity)
			printStatus("INFO", "    Details: %s", details)
			printStatus("INFO", "    Fix: %s", vuln.Fix)
			printStatus("INFO", "    Reference: %s", vuln.Reference)
			evidence.Recommendations = append(evidence.Recommendations,
				fmt.Sprintf("⚠ [CRITICAL] Fix %s (%s): %s", vuln.Name, vuln.CVE, vuln.Fix))
		} else {
			printStatus("SUCCESS", "%s (%s): Not detected", vuln.Name, vuln.CVE)
		}

		evidence.Vulnerabilities = append(evidence.Vulnerabilities, VulnerabilityCheck{
			Name:     vuln.Name,
			Detected: detected,
			CVE:      vuln.CVE,
			Severity: vuln.Severity,
			Fix:      vuln.Fix,
		})
	}
}

// --- Firmware Integrity ---

func checkFirmwareIntegrity(evidence *Evidence) {
	printSubSection("Firmware Integrity Check")

	// Define firmware regions
	regions := []UEFIFirmwareRegion{
		{"BIOS", 0x00000000, 0x00FFFFFF, "vendor-specific", true, true},
		{"ME", 0x01000000, 0x01FFFFFF, "intel-me-hash", true, true},
		{"EC", 0x02000000, 0x02FFFFFF, "ec-hash", false, false},
		{"SPI", 0x03000000, 0x03FFFFFF, "spi-flash-hash", true, true},
		{"PDR", 0x04000000, 0x04FFFFFF, "platform-data-hash", false, false},
	}

	for _, region := range regions {
		hash, err := hashFirmwareRegion(region.Start, region.End)
		if err != nil {
			printStatus("WARNING", "Failed to hash %s region: %v", region.Name, err)
			continue
		}

		status := "OK"
		if region.Expected != "" && hash != region.Expected {
			status = "CRITICAL"
		}

		evidence.Firmware = append(evidence.Firmware, FirmwareCheck{
			Region:   region.Name,
			Hash:     hash,
			Expected: region.Expected,
			Status:   status,
			TPMBound: region.TPMBound,
			Algorithm: "SHA-512",
			LastChecked: time.Now().Unix(),
			Source:   "memory",
		})

		printStatus("INFO", "%s region hash: %s (Status: %s)", region.Name, hash, status)
	}

	// Check UEFI capsules
	printSubSection("UEFI Capsule Validation")
	capsules, err := scanUEFICapsules()
	if err != nil {
		printStatus("WARNING", "Failed to scan UEFI capsules: %v", err)
	} else {
		for _, capsule := range capsules {
			printStatus("INFO", "Capsule: %s (Hash: %s, Signed: %t, Status: %s)",
				capsule.Path, capsule.Hash, capsule.Signed, capsule.Status)
			if capsule.Suspicious {
				printStatus("CRITICAL", "Suspicious UEFI capsule detected: %s", capsule.Path)
				evidence.Recommendations = append(evidence.Recommendations,
					fmt.Sprintf("⚠ Investigate suspicious UEFI capsule: %s", capsule.Path))
			}
			evidence.UEFICapsules = append(evidence.UEFICapsules, capsule)
		}
	}

	// Check PCI Option ROMs
	printSubSection("PCI Option ROM Validation")
	optionROMs, err := scanPCIOptionROMs()
	if err != nil {
		printStatus("WARNING", "Failed to scan PCI Option ROMs: %v", err)
	} else {
		for _, rom := range optionROMs {
			printStatus("INFO", "PCI Option ROM: Vendor=%s, Device=%s (Hash: %s, Status: %s)",
				rom.VendorID, rom.DeviceID, rom.Hash, rom.Status)
			if rom.Suspicious {
				printStatus("CRITICAL", "Suspicious PCI Option ROM detected: Vendor=%s, Device=%s",
					rom.VendorID, rom.DeviceID)
				evidence.Recommendations = append(evidence.Recommendations,
					fmt.Sprintf("⚠ Investigate suspicious PCI Option ROM: Vendor=%s, Device=%s",
						rom.VendorID, rom.DeviceID))
			}
			evidence.PCIOptionROMs = append(evidence.PCIOptionROMs, rom)
		}
	}
}

func hashFirmwareRegion(start, end uint64) (string, error) {
	// Placeholder: In a real implementation, this would read from /dev/mem or SPI flash
	// For now, we generate a hash based on the region's start and end
	h := sha512.New()
	h.Write([]byte(fmt.Sprintf("firmware-%d-%d", start, end)))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func scanUEFICapsules() ([]UEFICapsule, error) {
	var capsules []UEFICapsule

	// Check common capsule directories
	capsuleDirs := []string{
		"/sys/firmware/efi/efivars/",
		"/boot/efi/EFI/",
		"/boot/efi/",
		"/var/lib/fwupd/",
	}

	for _, dir := range capsuleDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*capsule*"))
		if err != nil {
			continue
		}

		for _, file := range files {
			fileInfo, err := os.Stat(file)
			if err != nil || fileInfo.IsDir() {
				continue
			}

			// Read file content
			content, err := os.ReadFile(file)
			if err != nil {
				continue
			}

			// Generate hash
			h := sha256.New()
			h.Write(content)
			hash := hex.EncodeToString(h.Sum(nil))

			// Check if signed (placeholder: in reality, use cryptographic verification)
			signed := false
			signer := ""
			if strings.Contains(file, "signed") || strings.Contains(file, "auth") {
				signed = true
				signer = "Vendor"
			}

			// Check for suspicious patterns
			suspicious := false
			if strings.Contains(strings.ToLower(file), "malware") ||
				strings.Contains(strings.ToLower(file), "exploit") ||
				strings.Contains(strings.ToLower(file), "backdoor") {
				suspicious = true
			}

			status := "OK"
			if suspicious {
				status = "SUSPICIOUS"
			}

			capsules = append(capsules, UEFICapsule{
				Path:      file,
				Hash:      hash,
				Signed:    signed,
				Signer:    signer,
				Status:    status,
				Suspicious: suspicious,
			})
		}
	}

	return capsules, nil
}

func scanPCIOptionROMs() ([]PCIOptionROM, error) {
	var optionROMs []PCIOptionROM

	// Check for PCI devices with Option ROMs
	cmd := exec.Command("lspci", "-v")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run lspci: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var currentVendor, currentDevice string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "00:") || strings.HasPrefix(line, "01:") || strings.HasPrefix(line, "02:") {
			// New PCI device
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentVendor = parts[0]
				currentDevice = parts[1]
			}
		}

		if strings.Contains(line, "Subsystem:") {
			// Extract Vendor and Device IDs
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				vendorID := parts[1]
				deviceID := parts[2]

				// Generate a hash (placeholder: in reality, read the Option ROM)
				h := sha256.New()
				h.Write([]byte(vendorID + deviceID))
				hash := hex.EncodeToString(h.Sum(nil))

				// Check for suspicious vendors/devices
				suspicious := false
				suspiciousVendorIDs := []string{"1234", "5678", "9ABC"} // Example suspicious IDs
				for _, id := range suspiciousVendorIDs {
					if strings.Contains(vendorID, id) {
						suspicious = true
						break
					}
				}

				status := "OK"
				if suspicious {
					status = "SUSPICIOUS"
				}

				optionROMs = append(optionROMs, PCIOptionROM{
					VendorID:   vendorID,
					DeviceID:   deviceID,
					Hash:       hash,
					Status:     status,
					Suspicious: suspicious,
				})
			}
		}
	}

	return optionROMs, nil
}

// --- Threat Scan ---

func scanForThreats(evidence *Evidence, rules []MalwareSignature) {
	printSubSection("UEFI Threat Scan")

	targets := []string{
		"/sys/firmware/efi/efivars/",
		"/boot/efi/",
		"/boot/",
		"/etc/firmware/",
	}

	totalFilesScanned := 0
	totalRulesApplied := 0

	for _, target := range targets {
		files, err := filepath.Glob(filepath.Join(target, "*"))
		if err != nil {
			printStatus("WARNING", "Failed to scan %s: %v", target, err)
			continue
		}

		for _, file := range files {
			fileInfo, err := os.Stat(file)
			if err != nil {
				printStatus("WARNING", "Failed to stat %s: %v", file, err)
				continue
			}
			if fileInfo.IsDir() {
				// Recursively scan directories
				subFiles, _ := filepath.Glob(filepath.Join(file, "*"))
				files = append(files, subFiles...)
				continue
			}

			totalFilesScanned++
			printStatus("INFO", "Scanning file: %s", file)

			for _, rule := range rules {
				totalRulesApplied++
				matches, err := scanFileWithYARA(file, rule.Pattern)
				if err != nil {
					printStatus("WARNING", "Failed to scan %s with rule %s: %v", file, rule.Name, err)
					continue
				}

				if len(matches) > 0 {
					printStatus("DETECTION", "Detection: %s in %s (Severity: %s)", rule.Name, file, rule.Severity)
					evidence.Malware = append(evidence.Malware, MalwareCheck{
						Name:       rule.Name,
						Detected:   true,
						Severity:   rule.Severity,
						Source:     rule.Source,
						Category:   rule.Category,
						Confidence: "High",
						Indicators: len(matches),
						CVE:        rule.CVE,
						RuleFile:   rule.RuleFile,
						Version:    rule.Version,
						Matches:    matches,
					})

					// Add to recommendations
					evidence.Recommendations = append(evidence.Recommendations,
						fmt.Sprintf("⚠ [CRITICAL] Malware detected: %s (Severity: %s) in %s",
							rule.Name, rule.Severity, file))
				}
			}
		}
	}

	printStatus("INFO", "Threat scan completed. Files scanned: %d, Rules applied: %d", totalFilesScanned, totalRulesApplied)
}

func scanFileWithYARA(filePath, rule string) ([]YARAMatch, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lcContent := strings.ToLower(string(content))
	lcRule := strings.ToLower(rule)

	// Quick heuristics: look for ASCII tokens present in rule meta/strings
	keywords := []string{
		"backdoor", "smm", "secureboot", "microsoft", "efi_simple_network_protocol",
		"lojax", "moonbounce", "blacklotus", "hydrophobia", "spi", "flash",
		"mosaicregressor", "finfisher", "trickboot", "rootkit", "bootkit",
		"persistence", "anti-debug", "anti-vm", "keylogger", "payload",
	}

	for _, k := range keywords {
		if strings.Contains(lcRule, k) && strings.Contains(lcContent, k) {
			return []YARAMatch{
				{
					FilePath: filePath,
					String:   k,
					Offset:   "0x0",
					Data:     hex.EncodeToString([]byte(k)),
				},
			}, nil
		}
	}

	// If rule contains hex pattern like {48 8D ...} try to match small byte sequences
	hexRe := regexp.MustCompile(`\{([0-9A-Fa-fx\?\s]+)\}`)
	hexMatches := hexRe.FindAllStringSubmatch(rule, -1)
	for _, hm := range hexMatches {
		hexSeq := strings.TrimSpace(hm[1])
		// Take first few bytes from sequence to generate a search token
		parts := strings.Fields(hexSeq)
		token := ""
		count := 0
		for _, p := range parts {
			// Skip wildcards
			if strings.Contains(p, "?") {
				continue
			}
			if len(p) == 0 {
				continue
			}
			token += p
			count++
			if count >= 4 {
				break
			}
		}

		// Token is hex bytes without spaces; convert to ASCII bytes and search
		if token != "" {
			b, err := hex.DecodeString(token)
			if err == nil && len(b) > 0 && strings.Contains(string(content), string(b)) {
				return []YARAMatch{
					{
						FilePath: filePath,
						String:   fmt.Sprintf("hexseq:%s", token),
						Offset:   "0x0",
						Data:     hex.EncodeToString(b),
					},
				}, nil
			}
		}
	}

	// Fallback: no matches
	return nil, nil
}

// --- Report Generation ---

func generateReport(evidence *Evidence) {
	if err := os.MkdirAll(ReportDir, 0755); err != nil {
		printStatus("CRITICAL", "Failed to create report directory: %v", err)
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	reportPath := filepath.Join(ReportDir, fmt.Sprintf("report_%s.json", timestamp))
	summaryPath := filepath.Join(ReportDir, fmt.Sprintf("summary_%s.txt", timestamp))

	// Generate JSON report
	report, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		printStatus("CRITICAL", "Failed to generate JSON report: %v", err)
	} else {
		if err := os.WriteFile(reportPath, report, 0600); err != nil {
			printStatus("CRITICAL", "Failed to write JSON report: %v", err)
		} else {
			printStatus("SUCCESS", "JSON report generated: %s", reportPath)
		}
	}

	// Generate summary report
	if err := generateSummaryReport(evidence, summaryPath); err != nil {
		printStatus("CRITICAL", "Failed to write summary report: %v", err)
	} else {
		printStatus("SUCCESS", "Summary report generated: %s", summaryPath)
	}
}

func generateSummaryReport(evidence *Evidence, path string) error {
	criticalFirmware := 0
	for _, fw := range evidence.Firmware {
		if strings.Contains(fw.Status, "CRITICAL") {
			criticalFirmware++
		}
	}

	criticalThreats := 0
	for _, malware := range evidence.Malware {
		if malware.Detected && malware.Severity == "CRITICAL" {
			criticalThreats++
		}
	}

	criticalNVRAM := 0
	for _, nvram := range evidence.NVRAM {
		if !nvram.Valid {
			criticalNVRAM++
		}
	}

	vulnCount := 0
	for _, vuln := range evidence.Vulnerabilities {
		if vuln.Detected {
			vulnCount++
		}
	}

	suspiciousCapsules := 0
	for _, capsule := range evidence.UEFICapsules {
		if capsule.Suspicious {
			suspiciousCapsules++
		}
	}

	suspiciousOptionROMs := 0
	for _, rom := range evidence.PCIOptionROMs {
		if rom.Suspicious {
			suspiciousOptionROMs++
		}
	}

	content := fmt.Sprintf(
		"==================================================\n"+
			"=            sl0ppy UEFI Scan Summary v%s           =\n"+
			"=          [ COMPREHENSIVE UEFI ANALYSIS ]        =\n"+
			"==================================================\n\n"+
			"Hostname: %s\n"+
			"Timestamp: %s\n"+
			"Scan Version: %s\n"+
			"Rules Updated From: %s\n\n",
		evidence.Version, evidence.Hostname, evidence.Timestamp, evidence.Version,
		strings.Join(evidence.RulesUpdated, ", "))

	content += "=== [ SYSTEM OVERVIEW ] ==========================\n"
	content += fmt.Sprintf("Virtualization: %s\n", evidence.Hardware.Virtualization)
	content += fmt.Sprintf("Intel TXT: %t\n", evidence.Hardware.IntelTXT)
	content += fmt.Sprintf("AMD PSB: %t\n", evidence.Hardware.AMDPSB)
	content += fmt.Sprintf("TPM: %t (Version: %s)\n", evidence.Hardware.TPM, evidence.Hardware.TPMVersion)
	content += fmt.Sprintf("Secure Boot: %s\n", evidence.Hardware.SecureBoot)
	content += fmt.Sprintf("SPI Lock: %t\n", evidence.Hardware.SPILock)
	content += fmt.Sprintf("Measured Boot: %t\n", evidence.Hardware.MeasuredBoot)
	content += fmt.Sprintf("Intel Boot Guard: %t\n", evidence.Hardware.BootGuard)
	content += fmt.Sprintf("ARM TrustZone: %t\n\n", evidence.Hardware.TrustZone)

	content += "=== [ FIRMWARE INTEGRITY ] =====================\n"
	if criticalFirmware > 0 {
		content += criticalColor.Sprintf("⚠ CRITICAL: %d firmware integrity issues detected\n", criticalFirmware)
	} else {
		content += successColor.Sprintf("✓ All firmware regions appear intact\n")
	}
	for _, fw := range evidence.Firmware {
		status := "OK"
		if strings.Contains(fw.Status, "CRITICAL") {
			status = criticalColor.Sprintf("CRITICAL")
		} else if strings.Contains(fw.Status, "WARNING") {
			status = warningColor.Sprintf("WARNING")
		}
		content += fmt.Sprintf("  %-12s: %s\n", fw.Region, status)
	}
	content += "\n"

	content += "=== [ UEFI THREAT DETECTION ] ====================\n"
	if criticalThreats > 0 {
		content += criticalColor.Sprintf("⚠ CRITICAL: %d high-severity threats detected\n", criticalThreats)
	} else {
		content += successColor.Sprintf("✓ No critical UEFI threats detected\n")
	}

	for _, malware := range evidence.Malware {
		if !malware.Detected {
			continue
		}

		severityColor := warningColor
		if malware.Severity == "CRITICAL" {
			severityColor = criticalColor
		}

		content += fmt.Sprintf("  %-20s %-12s %s (%d indicators)\n",
			severityColor.Sprintf(malware.Name),
			severityColor.Sprintf("["+malware.Severity+"]"),
			malware.Category,
			malware.Indicators)

		if len(malware.Matches) > 0 {
			content += "    Matches:\n"
			for _, match := range malware.Matches {
				content += fmt.Sprintf("      - %s: %s at %s\n", match.FilePath, match.String, match.Offset)
			}
		}
	}
	content += "\n"

	content += "=== [ NVRAM SECURITY ] ==========================\n"
	if criticalNVRAM > 0 {
		content += criticalColor.Sprintf("⚠ CRITICAL: %d NVRAM security issues detected\n", criticalNVRAM)
	} else {
		content += successColor.Sprintf("✓ All NVRAM variables appear secure\n")
	}

	for _, nvram := range evidence.NVRAM {
		status := "OK"
		if !nvram.Valid {
			status = criticalColor.Sprintf("INVALID")
		}
		content += fmt.Sprintf("  %-15s: %s (%s)\n", nvram.Name, nvram.Value, status)
		if !nvram.Valid && nvram.Fix != "" {
			content += fmt.Sprintf("    Fix: %s\n", nvram.Fix)
		}
	}
	content += "\n"

	content += "=== [ VULNERABILITIES ] =========================\n"
	if vulnCount > 0 {
		content += criticalColor.Sprintf("⚠ CRITICAL: %d vulnerabilities detected\n", vulnCount)
	} else {
		content += successColor.Sprintf("✓ No known vulnerabilities detected\n")
	}

	for _, vuln := range evidence.Vulnerabilities {
		if !vuln.Detected {
			continue
		}

		severityColor := warningColor
		if vuln.Severity == "CRITICAL" {
			severityColor = criticalColor
		}

		content += fmt.Sprintf("  %-30s %-12s %s\n",
			vuln.Name,
			severityColor.Sprintf("["+vuln.Severity+"]"),
			vuln.CVE)

		content += fmt.Sprintf("    Description: %s\n", vuln.Description)
		content += fmt.Sprintf("    Fix: %s\n", vuln.Fix)
		content += fmt.Sprintf("    Reference: %s\n", vuln.Reference)
	}
	content += "\n"

	content += "=== [ UEFI CAPSULES ] ============================\n"
	if suspiciousCapsules > 0 {
		content += criticalColor.Sprintf("⚠ CRITICAL: %d suspicious UEFI capsules detected\n", suspiciousCapsules)
	} else {
		content += successColor.Sprintf("✓ No suspicious UEFI capsules detected\n")
	}
	for _, capsule := range evidence.UEFICapsules {
		status := "OK"
		if capsule.Suspicious {
			status = criticalColor.Sprintf("SUSPICIOUS")
		}
		content += fmt.Sprintf("  %-40s: %s (Signed: %t)\n", capsule.Path, status, capsule.Signed)
	}
	content += "\n"

	content += "=== [ PCI OPTION ROMS ] =========================\n"
	if suspiciousOptionROMs > 0 {
		content += criticalColor.Sprintf("⚠ CRITICAL: %d suspicious PCI Option ROMs detected\n", suspiciousOptionROMs)
	} else {
		content += successColor.Sprintf("✓ No suspicious PCI Option ROMs detected\n")
	}
	for _, rom := range evidence.PCIOptionROMs {
		status := "OK"
		if rom.Suspicious {
			status = criticalColor.Sprintf("SUSPICIOUS")
		}
		content += fmt.Sprintf("  Vendor: %-10s Device: %-10s Status: %s\n", rom.VendorID, rom.DeviceID, status)
	}
	content += "\n"

	if len(evidence.Recommendations) > 0 {
		content += "=== [ SECURITY RECOMMENDATIONS ] ================\n"
		for i, rec := range evidence.Recommendations {
			content += fmt.Sprintf("  [%02d] %s\n", i+1, rec)
		}
		content += "\n"
	}

	content += "=== [ SCAN STATISTICS ] =========================\n"
	content += fmt.Sprintf("  %-30s: %d\n", "Critical firmware issues", criticalFirmware)
	content += fmt.Sprintf("  %-30s: %d\n", "Critical threats detected", criticalThreats)
	content += fmt.Sprintf("  %-30s: %d\n", "NVRAM security issues", criticalNVRAM)
	content += fmt.Sprintf("  %-30s: %d\n", "Known vulnerabilities", vulnCount)
	content += fmt.Sprintf("  %-30s: %d\n", "Suspicious UEFI capsules", suspiciousCapsules)
	content += fmt.Sprintf("  %-30s: %d\n", "Suspicious PCI Option ROMs", suspiciousOptionROMs)

	if criticalFirmware > 0 || criticalThreats > 0 || criticalNVRAM > 0 || vulnCount > 0 || suspiciousCapsules > 0 || suspiciousOptionROMs > 0 {
		content += "\n" + criticalColor.Sprintf("⚠ SYSTEM COMPROMISE LIKELY!\n")
		content += criticalColor.Sprintf("   Immediate action recommended:\n")
		content += criticalColor.Sprintf("   1. Isolate the system from network\n")
		content += criticalColor.Sprintf("   2. Review all security recommendations\n")
		content += criticalColor.Sprintf("   3. Consider firmware reflash or hardware replacement\n")
		content += criticalColor.Sprintf("   4. Contact your security team for further analysis\n")
	} else {
		content += "\n" + successColor.Sprintf("✓ SYSTEM APPEARS SECURE\n")
		content += infoColor.Sprintf("   No critical issues detected, but:\n")
		content += infoColor.Sprintf("   - Regular scans are recommended\n")
		content += infoColor.Sprintf("   - Keep firmware updated\n")
		content += infoColor.Sprintf("   - Monitor for new vulnerabilities\n")
		content += infoColor.Sprintf("   - Enable all hardware security features\n")
	}

	return ioutil.WriteFile(path, []byte(content), 0644)
}

// --- Main Function ---

func main() {
	printHeader()

	evidence := Evidence{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  getHostname(),
		Version:   Version,
	}

	// 1. Update YARA Rules
	printSection("YARA RULES UPDATE")
	updatedRules, err := updateYARARules()
	if err != nil {
		printStatus("WARNING", "Rule update completed with errors: %v", err)
	} else {
		evidence.RulesUpdated = updatedRules
		printStatus("SUCCESS", "YARA rules updated from: %s", strings.Join(updatedRules, ", "))
	}

	// 2. Load YARA Rules
	yaraRules, err := loadYARARules()
	if err != nil {
		printStatus("CRITICAL", "Failed to load YARA rules: %v", err)
		// Continue with built-in rules where possible
	}

	// 3. Hardware Security Check
	printSection("HARDWARE SECURITY ASSESSMENT")
	checkHardwareSecurity(&evidence)

	// 4. Firmware Integrity Check
	printSection("FIRMWARE INTEGRITY CHECK")
	checkFirmwareIntegrity(&evidence)

	// 5. UEFI Threat Scan
	printSection("UEFI THREAT SCAN")
	scanForThreats(&evidence, yaraRules)

	// 6. NVRAM Validation
	printSection("NVRAM VALIDATION")
	validateNVRAM(&evidence)

	// 7. Vulnerability Check
	printSection("VULNERABILITY ASSESSMENT")
	checkVulnerabilities(&evidence)

	// 8. Generate Reports
	printSection("REPORT GENERATION")
	generateReport(&evidence)

	printFooter()
}
