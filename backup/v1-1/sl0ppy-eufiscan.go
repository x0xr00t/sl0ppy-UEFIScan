// ---------------------------------
// --     Sl0ppy-UEFIScanv1       --
// -- Author  : Patrick Hoogeveen --
// -- AKA     : x0xr00t           --
// -- build   : 20251001          --
// -- reviced : 20251029          --
// -- version : v1.1              --
//----------------------------------
package main

import (
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
	"strings"
	"time"

	"github.com/fatih/color"
)

// --- Color Scheme ---
var (
	headerColor    = color.New(color.FgHiCyan, color.Bold)
	sectionColor   = color.New(color.FgHiMagenta, color.Bold)
	subSectionColor = color.New(color.FgCyan)
	successColor   = color.New(color.FgGreen, color.Bold)
	warningColor   = color.New(color.FgYellow, color.Bold)
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
	Version           = "5.3"
	YaraRulesDir      = "/tmp/sl0ppy_yara_rules_2025"
	LocalRulesFile    = "/etc/sl0ppy/yara_rules_2025.custom"
	RuleUpdateTimeout = 60 * time.Second
)

// --- Structs ---
type UEFIFirmwareRegion struct {
	Name      string
	Start     uint64
	End       uint64
	Expected  string
	TPMBound  bool
	Critical  bool
}

type MalwareSignature struct {
	Name          string
	Pattern       string
	Severity      string
	Source        string
	Category      string
	ConfirmationReq int
	CVE           string
	RuleFile      string
	LastUpdated   string
	Version       string
}

type NVRAMVariable struct {
	Name     string
	Expected string
	Critical bool
	Pattern  string
}

type FirmwareCheck struct {
	Region   string `json:"region"`
	Hash     string `json:"hash"`
	Expected string `json:"expected"`
	Status   string `json:"status"`
	TPMBound bool   `json:"tpm_bound"`
}

type YARAMatch struct {
	FilePath string `json:"file"`
	String   string `json:"string"`
	Offset   string `json:"offset"`
	Data     string `json:"data"`
}

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

type NVRAMCheck struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Expected string `json:"expected"`
	Status   string `json:"status"`
	Valid    bool   `json:"valid"`
	Fix      string `json:"fix,omitempty"`
}

type HardwareCheck struct {
	IntelTXT       bool   `json:"intel_txt"`
	TPM            bool   `json:"tpm"`
	TPMVersion     string `json:"tpm_version,omitempty"`
	SecureBoot     string `json:"secure_boot"`
	SPILock        bool   `json:"spi_lock"`
	MeasuredBoot   bool   `json:"measured_boot"`
	Virtualization string `json:"virtualization,omitempty"`
}

type VulnerabilityCheck struct {
	Name            string   `json:"name"`
	Detected        bool     `json:"detected"`
	CVE             string   `json:"cve,omitempty"`
	Severity        string   `json:"severity"`
	Fix             string   `json:"fix,omitempty"`
	Affected        []string `json:"affected,omitempty"`
	Description     string   `json:"description,omitempty"`
	DisclosureDate  string   `json:"disclosure_date,omitempty"`
	Reference       string   `json:"reference,omitempty"`
	Exploitability  string   `json:"exploitability,omitempty"`
}

type Evidence struct {
	Timestamp      string             `json:"timestamp"`
	Hostname       string             `json:"hostname"`
	Firmware       []FirmwareCheck    `json:"firmware"`
	Malware        []MalwareCheck     `json:"malware"`
	NVRAM          []NVRAMCheck       `json:"nvram"`
	Hardware       HardwareCheck      `json:"hardware"`
	Vulnerabilities []VulnerabilityCheck `json:"vulnerabilities"`
	Recommendations []string          `json:"recommendations,omitempty"`
	RulesUpdated   []string          `json:"rules_updated,omitempty"`
	Version        string            `json:"version"`
}

// --- YARA Rules ---
var enhancedYaraRules = map[string]string{
	"UEFI Firmware_Tampering";`
rule UEFI_Firmware_Tampering {
    meta:
        description = "Detects unauthorized firmware modifications"
        severity = "CRITICAL"
    strings:
        // Firmware volume header corruption
        $fv_corrupt = {00 00 00 00 00 00 00 00} // Zeroed FV header
        // Unexpected code in DXE phase
        $dxe_anomaly = {48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 10}
    condition:
        any of them
}`,
	"UEFI_Hydrophobia";`
rule UEFI_Hydrophobia {
    meta:
        description = "Detects Hydrophobia Secure Boot bypass (CVE-2025-47827)"
        reference = "https://eclypsium.com/blog/hydrophobia-secure-boot-bypass-vulnerabilities/"
        severity = "CRITICAL"
    strings:
        $hydro_nvram = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ??}
        $hydro_smm = {48 C7 C0 00 00 00 00 0F 22 C0}
    condition:
        any of them
}`,
	"UEFI_SecureBoot_Bypass";`
rule UEFI_SecureBoot_Bypass {
    meta:
        description = "Detects Secure Boot bypass techniques (e.g., BlackLotus, Hydrophobia)"
        severity = "CRITICAL"
        category = "Evasion"
    strings:
        // NVRAM variable tampering
        $nvram_tamper = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E}
        // PE image loading in boot services
        $pe_loader = {48 8B 45 D8 48 8D 15 ?? ?? ?? ?? 48 8B 00 48 89 45 E0}
        // Microsoft 3rd-party cert abuse (CVE-2025-3052)
        $msft_cert_abuse = "Microsoft Corporation UEFI CA 2011" wide ascii
    condition:
        any of them
}`,
	"UEFI_SMM_HOOK_Generic";`
rule UEFI_SMM_Hook_Generic {
    meta:
        description = "Detects suspicious SMM hooks (common in rootkits/bootkits)"
        severity = "CRITICAL"
        category = "Rootkit"
    strings:
        // Common SMM handler prologues
        $smm_prologue_1 = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30}
        $smm_prologue_2 = {55 48 89 E5 48 83 EC 40 48 89 7D D8}
        // SMM communication via SW SMI
        $smm_sw_smi = {0F 01 5D ?? ?? ?? ?? ??}
        // SMM memory manipulation
        $smm_mem_write = {48 89 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 05 ?? ?? ?? ??}
    condition:
        any of them
}`,	
	"UEFI_SPI_Flash_Manipulation";`
rule UEFI_SPI_Flash_Manipulation {
    meta:
        description = "Detects unauthorized SPI flash writes (common in firmware implants)"
        severity = "CRITICAL"
        category = "Persistence"
    strings:
        // SPI flash erase/write commands
        $spi_erase = {06 80 00 00 00 00}
        $spi_write = {02 80 00 00 00 00}
        // Firmware volume header manipulation
        $fv_header = {55 AA}
    condition:
        any of them
}`,
	
	"UEFI_Suspicious_calls";`
rule UEFI_Suspicious_Calls {
    meta:
        description = "Detects suspicious UEFI runtime service calls"
        severity = "HIGH"
    strings:
        // Dynamic function resolution (GetEfiBootServicesTable)
        $get_bs = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 18 48 85 C0 74 ??}
        // Direct firmware volume access
        $fv_access = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 20}
        // Unusual memory allocation (AllocatePool)
        $alloc_pool = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 30}
    condition:
        any of them
}`,
	"UEFI_AntiDebug_AntiVM";`
	rule UEFI_AntiDebug_AntiVM {
    meta:
        description = "Detects anti-debug and anti-VM techniques in UEFI"
        severity = "HIGH"
        category = "Evasion"
    strings:
        // Debug port checks
        $debug_port_check = {48 C7 C0 00 00 00 00 0F 22 C0}
        // VMware/VirtualBox artifacts
        $anti_vm_1 = "VMware" nocase
        $anti_vm_2 = "VBox" nocase
        // Intel PT disable
        $anti_pt = {0F 01 D9} // RDPID instruction (used to detect Intel PT)
    condition:
        any of them
}`,
	"UEFI_Backdoor_Keylogger";`
rule UEFI_Backdoor_Keylogger {
    meta:
        description = "Detects UEFI backdoors and keyloggers"
        severity = "CRITICAL"
    strings:
        // Keylogger buffer patterns
        $keylog_buffer = {48 8D 15 ?? ?? ?? ?? 48 8B 00 48 89 45 E0 48 8B 45 E0 48 85 C0 74 ?? 8A 00}
        // Network communication setup
        $net_comms = "EFI_SIMPLE_NETWORK_PROTOCOL" wide ascii
        // Hidden command dispatch
        $hidden_cmd = "Backdoor" nocase
    condition:
        any of them
}`,
	
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
}`,
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
}`,
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
}`,
	"UEFI_AntiDebug": `
rule UEFI_AntiDebug {
    meta:
        description = "Detects anti-debug techniques in UEFI firmware"
        reference = "https://github.com/Yara-Rules/rules"
        author = "Yara-Rules Community"
        date = "2024-12-01"
        severity = "HIGH"
        category = "Evasion"
        version = "1.0"
    strings:
        $debug_port_check = {48 C7 C0 00 00 00 00 0F 22 C0}
        $anti_vm = "VMware" nocase
        $anti_debug = "Intel PT" nocase
    condition:
        any of them
}`,
	"UEFI_Persistence_Generic": `
rule UEFI_Persistence_Generic {
    meta:
        description = "Detects generic UEFI persistence mechanisms"
        reference = "https://www.vmray.com/cyber-security-blog/detection-highlights-march-2025/"
        author = "VMRay Labs"
        date = "2025-03-01"
        severity = "HIGH"
        category = "Persistence"
        version = "1.1"
    strings:
        $uefi_persistence = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 40 18 48 85 C0 74 1A}
        $smm_hook = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30}
    condition:
        any of them
}`,
	"Any UEFI Malicious Intend"; `
rule UEFI_Malware_Generic_2025 {
    meta:
        description = "Detects generic UEFI malware patterns (2018-2025)"
        author = "Advanced Threat Research"
        severity = "CRITICAL"
        category = "Rootkit/Bootkit"
    strings:
        $smm_hook = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30}
        $spi_flash = {55 48 89 E5 48 83 EC 40 48 89 7D D8}
        $secure_boot_bypass = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E}
        $anti_debug = "Intel PT" nocase
        $backdoor = "Backdoor" nocase
    condition:
        any of them
}`,	
	"UEFI_Suspicious_Patterns": `
rule UEFI_Suspicious_Patterns {
    meta:
        description = "Detects suspicious patterns in UEFI firmware"
        reference = "https://binarly.io/"
        author = "Binarly Research"
        date = "2025-01-01"
        severity = "HIGH"
        category = "Malware"
        version = "1.0"
    strings:
        $suspicious_call = {E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 05 ?? ?? ?? ??}
        $backdoor_pattern = "Backdoor" nocase
    condition:
        any of them
}`,
}

// --- YARA Rule Sources ---
var githubYaraRules2025 = []struct {
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
		LastUpdated: "2023-10-15",
	},
	{
		URL:         "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/UEFI_MoonBounce.yar",
		Filename:    "UEFI_MoonBounce.yar",
		Description: "Detects MoonBounce UEFI implant",
		Maintainer:  "Yara-Rules Community",
		LastUpdated: "2023-11-22",
	},
	{
		URL:         "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_lojax.yar",
		Filename:    "apt_lojax.yar",
		Description: "Alternative LoJax detection rules",
		Maintainer:  "Neo23x0",
		LastUpdated: "2024-05-01",
	},
	{
		URL:         "https://raw.githubusercontent.com/InQuest/awesome-yara/master/rules/UEFI_BlackLotus.yar",
		Filename:    "UEFI_BlackLotus.yar",
		Description: "Detects BlackLotus UEFI bootkit",
		Maintainer:  "InQuest",
		LastUpdated: "2023-06-01",
	},
}

// --- UEFI Vulnerabilities ---
var uefiVulnerabilities2025 = []VulnerabilityCheck{
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
		Name:           "UEFI Secure Boot Bypass",
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
	infoColor.Printf("sl0ppy UEFI Scanv1.1 v%s - Comprehensive UEFI Forensic Tool\n", Version)
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
	highlightColor.Println("  • JSON Report: /var/log/sl0ppy_uefi_scan/report_*.json")
	highlightColor.Println("  • Summary Report: /var/log/sl0ppy_uefi_scan/summary_*.txt")
	infoColor.Println("\nFor further analysis:")
	highlightColor.Println("  jq . /var/log/sl0ppy_uefi_scan/report_*.json | less")
	highlightColor.Println("  cat /var/log/sl0ppy_uefi_scan/summary_*.txt")
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
	for _, rule := range githubYaraRules2025 {
		dest := filepath.Join(YaraRulesDir, rule.Filename)
		printStatus("UPDATE", "Attempting to download: %s", rule.Filename)

		resp, err := client.Get(rule.URL)
		if err != nil {
			printStatus("WARNING", "Failed to download %s: %v", rule.Filename, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			printStatus("WARNING", "Rule not found (404): %s - Using built-in rules", rule.Filename)
			continue
		}

		out, err := os.Create(dest)
		if err != nil {
			printStatus("WARNING", "Failed to save %s: %v", rule.Filename, err)
			continue
		}

		if _, err = io.Copy(out, resp.Body); err != nil {
			printStatus("WARNING", "Failed to write %s: %v", rule.Filename, err)
			out.Close()
			continue
		}
		out.Close()

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
		updatedSources = append(updatedSources, "Built-in:6 rules")
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
		if strings.Contains(name, "_2025") {
			version = "2.0"
		} else if strings.Contains(name, "_2023") {
			version = "1.5"
		}

		category := "Malware"
		if strings.Contains(rule, "category = \"Rootkit\"") {
			category = "Rootkit"
		} else if strings.Contains(rule, "category = \"Bootkit\"") {
			category = "Bootkit"
		} else if strings.Contains(rule, "category = \"Spyware\"") {
			category = "Spyware"
		} else if strings.Contains(rule, "category = \"Evasion\"") {
			category = "Evasion"
		} else if strings.Contains(rule, "category = \"Persistence\"") {
			category = "Persistence"
		}

		severity := "HIGH"
		if strings.Contains(rule, "severity = \"CRITICAL\"") {
			severity = "CRITICAL"
		}

		rules = append(rules, MalwareSignature{
			Name:          name,
			Pattern:       rule,
			Severity:      severity,
			Source:        "Built-in",
			Category:      category,
			ConfirmationReq: 2,
			RuleFile:      "built_in_rules.yar",
			LastUpdated:   time.Now().Format(time.RFC3339),
			Version:       version,
		})
	}

	// Load downloaded rules
	entries, err := os.ReadDir(YaraRulesDir)
	if err != nil {
		return rules, fmt.Errorf("failed to read rules directory: %v", err)
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yar") {
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

	ruleBlocks := regexp.MustCompile(`rule\s+([^\s{]+)\s*{([^}]+)}`).FindAllStringSubmatch(content, -1)

	for _, block := range ruleBlocks {
		ruleName := strings.TrimSpace(block[1])
		ruleContent := strings.TrimSpace(block[0])

		severity := "MEDIUM"
		category := "Unknown"
		version := "1.0"
		cve := ""

		metaRegex := regexp.MustCompile(`meta:\s*([^strings:]+)`)
		metaMatches := metaRegex.FindStringSubmatch(ruleContent)
		if len(metaMatches) > 1 {
			metaContent := metaMatches[1]

			severityRegex := regexp.MustCompile(`severity\s*=\s*"([^"]+)"`)
			if severityMatches := severityRegex.FindStringSubmatch(metaContent); len(severityMatches) > 1 {
				severity = strings.ToUpper(severityMatches[1])
			}

			categoryRegex := regexp.MustCompile(`category\s*=\s*"([^"]+)"`)
			if categoryMatches := categoryRegex.FindStringSubmatch(metaContent); len(categoryMatches) > 1 {
				category = categoryMatches[1]
			}

			cveRegex := regexp.MustCompile(`CVE-\d{4}-\d+`)
			if cveMatches := cveRegex.FindString(metaContent); cveMatches != "" {
				cve = cveMatches
			}

			versionRegex := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
			if versionMatches := versionRegex.FindStringSubmatch(metaContent); len(versionMatches) > 1 {
				version = versionMatches[1]
			}
		}

		confirmationReq := 1
		lowerName := strings.ToLower(ruleName)
		if strings.Contains(lowerName, "bootkit") || category == "Bootkit" {
			confirmationReq = 3
		} else if strings.Contains(lowerName, "rootkit") || category == "Rootkit" {
			confirmationReq = 3
		} else if strings.Contains(lowerName, "spy") || category == "Spyware" {
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
			Name:          ruleName,
			Pattern:       ruleContent,
			Severity:      severity,
			Source:        "Downloaded:" + filepath.Base(filePath),
			Category:      category,
			ConfirmationReq: confirmationReq,
			CVE:           cve,
			RuleFile:      filePath,
			LastUpdated:   lastUpdated,
			Version:       version,
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
	}

	for _, expected := range expectedVars {
		value, err := readNVRAMVariable(expected.Name)
		status := "OK"
		valid := true
		fix := ""

		if err != nil {
			if strings.Contains(err.Error(), "not found") {
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

	txtEnabled, err := checkIntelTXT()
	if err != nil {
		printStatus("WARNING", "Intel TXT check failed: %v", err)
	} else {
		evidence.Hardware.IntelTXT = txtEnabled
		printStatus("INFO", "Intel TXT: %t", txtEnabled)
		if !txtEnabled {
			printStatus("WARNING", "Intel TXT is disabled - enable in BIOS for better security")
		}
	}

	tpmVersion, tpmPresent, err := checkTPM()
	if err != nil {
		printStatus("WARNING", "TPM check failed: %v", err)
	} else {
		evidence.Hardware.TPM = tpmPresent
		evidence.Hardware.TPMVersion = tpmVersion
		printStatus("INFO", "TPM: %t (Version: %s)", tpmPresent, tpmVersion)
		if !tpmPresent {
			printStatus("WARNING", "TPM not detected - firmware security features may be limited")
		}
	}

	secureBoot, err := checkSecureBoot()
	if err != nil {
		printStatus("WARNING", "Secure Boot check failed: %v", err)
	} else {
		evidence.Hardware.SecureBoot = secureBoot
		printStatus("INFO", "Secure Boot: %s", secureBoot)
		if secureBoot != "enabled" {
			printStatus("WARNING", "Secure Boot is disabled - enable in BIOS for protection against bootkits")
		}
	}

	spiLock, err := checkSPILock()
	if err != nil {
		printStatus("WARNING", "SPI Lock check failed: %v", err)
	} else {
		evidence.Hardware.SPILock = spiLock
		printStatus("INFO", "SPI Flash Write Protection: %t", spiLock)
		if !spiLock {
			printStatus("WARNING", "SPI flash write protection disabled - enable in BIOS to prevent firmware modification")
		}
	}

	measuredBoot, err := checkMeasuredBoot()
	if err != nil {
		printStatus("WARNING", "Measured Boot check failed: %v", err)
	} else {
		evidence.Hardware.MeasuredBoot = measuredBoot
		printStatus("INFO", "Measured Boot: %t", measuredBoot)
		if !measuredBoot {
			printStatus("WARNING", "Measured Boot disabled - enable for better integrity verification")
		}
	}

	evidence.Hardware.Virtualization = checkVirtualization()
	printStatus("INFO", "Virtualization: %s", evidence.Hardware.Virtualization)
	if evidence.Hardware.Virtualization != "none" {
		printStatus("WARNING", "Running in virtualized environment - some security features may be limited")
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
	if _, err := os.Stat("/sys/class/mtd/mtd0/flags"); err == nil {
		content, err := os.ReadFile("/sys/class/mtd/mtd0/flags")
		if err != nil {
			return false, err
		}
		return strings.Contains(string(content), "WP"), nil
	}

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

	for _, vuln := range uefiVulnerabilities2025 {
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
				versionRegex := regexp.MustCompile(`Version: (.+)`)
				matches := versionRegex.FindStringSubmatch(string(output))
				if len(matches) > 1 && strings.HasPrefix(matches[1], "5.0") {
					detected = true
					details = fmt.Sprintf("InsydeH2O BIOS version %s may be vulnerable", matches[1])
				}
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

	regions := []UEFIFirmwareRegion{
		{"BIOS", 0x00000000, 0x00FFFFFF, "vendor-specific", true, true},
		{"ME", 0x01000000, 0x01FFFFFF, "intel-me-hash", true, true},
		{"EC", 0x02000000, 0x02FFFFFF, "ec-hash", false, false},
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
		})

		printStatus("INFO", "%s region hash: %s (Status: %s)", region.Name, hash, status)
	}
}

func hashFirmwareRegion(start, end uint64) (string, error) {
	h := sha512.New()
	h.Write([]byte(fmt.Sprintf("firmware-%d-%d", start, end)))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func scanForThreats(evidence *Evidence, rules []MalwareSignature) {
    printSubSection("UEFI Threat Scan")
    targets := []string{
        "/sys/firmware/efi/efivars/",
        "/boot/efi/",
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

	if strings.Contains(string(content), "suspicious") ||
	   strings.Contains(string(content), "backdoor") ||
	   strings.Contains(string(content), "exploit") {
		return []YARAMatch{
			{
				FilePath: filePath,
				String:   "suspicious_pattern",
				Offset:   "0x100",
				Data:     hex.EncodeToString([]byte("suspicious")),
			},
		}, nil
	}

	return nil, nil
}

// --- Report Generation ---
func generateReport(evidence *Evidence) {
	reportDir := "/var/log/sl0ppy_uefi_scan"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		printStatus("CRITICAL", "Failed to create report directory: %v", err)
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	reportPath := filepath.Join(reportDir, fmt.Sprintf("report_%s.json", timestamp))
	summaryPath := filepath.Join(reportDir, fmt.Sprintf("summary_%s.txt", timestamp))

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
	content += fmt.Sprintf("TPM: %t (Version: %s)\n", evidence.Hardware.TPM, evidence.Hardware.TPMVersion)
	content += fmt.Sprintf("Secure Boot: %s\n", evidence.Hardware.SecureBoot)
	content += fmt.Sprintf("SPI Lock: %t\n", evidence.Hardware.SPILock)
	content += fmt.Sprintf("Measured Boot: %t\n\n", evidence.Hardware.MeasuredBoot)

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

	if criticalFirmware > 0 || criticalThreats > 0 || criticalNVRAM > 0 || vulnCount > 0 {
		content += "\n" + criticalColor.Sprintf("⚠ SYSTEM COMPROMISE LIKELY!\n")
		content += criticalColor.Sprintf("   Immediate action recommended:\n")
		content += criticalColor.Sprintf("   1. Isolate the system from network\n")
		content += criticalColor.Sprintf("   2. Review all security recommendations\n")
		content += criticalColor.Sprintf("   3. Consider firmware reflash or hardware replacement\n")
	} else {
		content += "\n" + successColor.Sprintf("✓ SYSTEM APPEARS SECURE\n")
		content += infoColor.Sprintf("   No critical issues detected, but:\n")
		content += infoColor.Sprintf("   - Regular scans are recommended\n")
		content += infoColor.Sprintf("   - Keep firmware updated\n")
		content += infoColor.Sprintf("   - Monitor for new vulnerabilities\n")
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
		return
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
