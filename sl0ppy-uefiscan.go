package main

import (
	"bytes"
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
	sectionColor   = color.New(color.FgCyan, color.Bold)
	infoColor      = color.New(color.FgHiBlue)
	successColor   = color.New(color.FgGreen)
	warningColor   = color.New(color.FgYellow)
	criticalColor  = color.New(color.FgRed, color.Bold)
	highlightColor = color.New(color.FgHiMagenta, color.Bold)
	debugColor     = color.New(color.FgHiBlack)
	okStatus       = successColor.Sprintf("✓ OK")
	warnStatus     = warningColor.Sprintf("⚠ WARNING")
	critStatus     = criticalColor.Sprintf("✗ CRITICAL")
	errorStatus    = criticalColor.Sprintf("✗ ERROR")
)

// --- Config ---
const (
	Version            = "1.0"
	YaraRulesDir       = "/tmp/sl0ppy_yara_rules"
	GitHubRulesRepo    = "https://raw.githubusercontent.com/Yara-Rules/rules/master"
	MISPFeedURL        = "https://www.misp-project.org/feeds/yara"
	LocalRulesFile     = "/etc/sl0ppy/yara_rules.custom"
	RuleUpdateTimeout  = 30 * time.Second
	MaxRuleAge         = 24 * time.Hour
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

type MalwareCheck struct {
	Name       string `json:"name"`
	Detected   bool   `json:"detected"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
	Category   string `json:"category"`
	Confidence string `json:"confidence"`
	Indicators int    `json:"indicators"`
	CVE        string `json:"cve,omitempty"`
	RuleFile   string `json:"rule_file,omitempty"`
}

type NVRAMCheck struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Expected string `json:"expected"`
	Status   string `json:"status"`
	Valid    bool   `json:"valid"`
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
	Name     string `json:"name"`
	Detected bool   `json:"detected"`
	CVE      string `json:"cve,omitempty"`
	Severity string `json:"severity"`
	Fix      string `json:"fix,omitempty"`
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

// --- Global Variables ---
var (
	trustedHashes = map[string]string{
		"BIOS Region": "a1b2c3d4e5f6...", // Replace with actual TPM-bound hashes
		"ME Region":   "b2c3d4e5f6...",
		"EC Region":   "c3d4e5f6g7...",
	}

	uefiVulnerabilities = []VulnerabilityCheck{
		{Name: "SMM Callout Vulnerability", CVE: "CVE-2023-20569", Severity: "CRITICAL", Fix: "Update BIOS to latest version"},
		{Name: "TianoCore Buffer Overflow", CVE: "CVE-2022-31705", Severity: "CRITICAL", Fix: "Apply vendor patch"},
		{Name: "Intel ME Privilege Escalation", CVE: "CVE-2022-34303", Severity: "HIGH", Fix: "Update Intel ME firmware"},
		{Name: "AMI BIOS SMM Vulnerability", CVE: "CVE-2021-28210", Severity: "CRITICAL", Fix: "Update AMI BIOS"},
		{Name: "UEFI Variable Authentication Bypass", CVE: "CVE-2022-28739", Severity: "CRITICAL", Fix: "Enable Secure Boot"},
		{Name: "SPI Flash Protection Bypass", CVE: "CVE-2023-1109", Severity: "CRITICAL", Fix: "Enable BIOS write protection"},
	}

	githubYaraRules = []struct {
		URL      string
		Filename string
	}{
		{GitHubRulesRepo + "/malware/APT_LoJax.yar", "APT_LoJax.yar"},
		{GitHubRulesRepo + "/malware/UEFI_MoonBounce.yar", "UEFI_MoonBounce.yar"},
		{GitHubRulesRepo + "/malware/UEFI_FinFisher.yar", "UEFI_FinFisher.yar"},
		{GitHubRulesRepo + "/malware/UEFI_ESPecter.yar", "UEFI_ESPecter.yar"},
		{GitHubRulesRepo + "/malware/UEFI_BlackLotus.yar", "UEFI_BlackLotus.yar"},
		{GitHubRulesRepo + "/malware/UEFI_MosaicRegressor.yar", "UEFI_MosaicRegressor.yar"},
		{GitHubRulesRepo + "/malware/UEFI_VectorEDK.yar", "UEFI_VectorEDK.yar"},
		{GitHubRulesRepo + "/malware/UEFI_EspionageBootkit.yar", "UEFI_EspionageBootkit.yar"},
	}
)

// --- Main Function ---
func main() {
	printHeader()

	evidence := Evidence{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  getHostname(),
		Version:   Version,
	}

	// Step 0: Update YARA rules
	printSection("Updating YARA Rules")
	updatedRules, err := updateYARARules()
	if err != nil {
		printStatus("WARNING", "Failed to update YARA rules: %v", err)
	} else {
		evidence.RulesUpdated = updatedRules
		printStatus("INFO", "Updated YARA rules from: %s", strings.Join(updatedRules, ", "))
	}

	// Load all YARA rules
	yaraRules, err := loadYARARules()
	if err != nil {
		printStatus("CRITICAL", "Failed to load YARA rules: %v", err)
		return
	}
	printStatus("INFO", "Loaded %d YARA rules", len(yaraRules))

	// Step 1: System Information
	printSection("System Information")
	checkSystemInfo(&evidence)

	// Step 2: Firmware Integrity
	printSection("Firmware Integrity Check")
	checkFirmwareIntegrity(&evidence)

	// Step 3: Threat Scan
	printSection("UEFI Threat Scan")
	scanForThreats(&evidence, yaraRules)

	// Step 4: NVRAM Validation
	printSection("NVRAM Validation")
	validateNVRAM(&evidence)

	// Step 5: Hardware Security
	printSection("Hardware Security Check")
	checkHardwareSecurity(&evidence)

	// Step 6: Vulnerability Check
	printSection("UEFI Vulnerability Check")
	checkVulnerabilities(&evidence)

	// Step 7: Generate Report
	printSection("Generating Forensic Report")
	generateReport(&evidence)

	printFooter()
}

// --- Output Formatting ---
func printHeader() {
	headerColor.Println("==================================================")
	headerColor.Println("=            sl0ppy UEFI Scanner v" + Version + "           =")
	headerColor.Println("=          [ FULL COVERAGE UEFI ANALYSIS ]        =")
	headerColor.Println("==================================================")
	infoColor.Println("\n⚠️  Run with sudo for full functionality!")
	infoColor.Println("⚠︸  Example: sudo ./sl0ppy-uefiscan\n")
}

func printSection(title string) {
	fmt.Println()
	sectionColor.Println("┌───────────────────────────────────────────────")
	sectionColor.Printf("│ %s\n", title)
	sectionColor.Println("└───────────────────────────────────────────────")
}

func printStatus(level, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	switch level {
	case "INFO":
		fmt.Printf("  [%s] %s\n", infoColor.Sprintf("INFO"), msg)
	case "WARNING":
		fmt.Printf("  [%s] %s\n", warnStatus, msg)
	case "CRITICAL":
		fmt.Printf("  [%s] %s\n", critStatus, msg)
	case "ERROR":
		fmt.Printf("  [%s] %s\n", errorStatus, msg)
	case "SUCCESS":
		fmt.Printf("  [%s] %s\n", okStatus, msg)
	default:
		fmt.Printf("  [%s] %s\n", level, msg)
	}
}

func printFooter() {
	fmt.Println()
	headerColor.Println("==================================================")
	successColor.Println("Scan completed successfully!")
	infoColor.Println("Reports saved to: /var/log/sl0ppy_uefi_scan/")
	headerColor.Println("==================================================")
}

// --- YARA Rule Management ---
func updateYARARules() ([]string, error) {
	var updatedSources []string
	if err := os.MkdirAll(YaraRulesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rules directory: %v", err)
	}

	needsUpdate, err := checkRuleFreshness()
	if err != nil {
		return nil, err
	}
	if !needsUpdate {
		printStatus("INFO", "Rules are up-to-date (last updated within %s)", MaxRuleAge)
		return []string{"cached"}, nil
	}

	client := http.Client{Timeout: RuleUpdateTimeout}
	for _, rule := range githubYaraRules {
		dest := filepath.Join(YaraRulesDir, rule.Filename)
		if err := downloadWithClient(&client, rule.URL, dest); err != nil {
			printStatus("WARNING", "Failed to update %s: %v", rule.Filename, err)
		} else {
			updatedSources = append(updatedSources, "GitHub:"+rule.Filename)
			printStatus("INFO", "Updated %s from GitHub", rule.Filename)
		}
	}

	mispFile := filepath.Join(YaraRulesDir, "misp_uefi_rules.yar")
	if err := downloadWithClient(&client, MISPFeedURL, mispFile); err != nil {
		printStatus("WARNING", "Failed to update MISP rules: %v", err)
	} else {
		updatedSources = append(updatedSources, "MISP")
		printStatus("INFO", "Updated MISP rules")
	}

	if _, err := os.Stat(LocalRulesFile); err == nil {
		if err := copyFile(LocalRulesFile, filepath.Join(YaraRulesDir, "local_custom.yar")); err != nil {
			printStatus("WARNING", "Failed to copy local rules: %v", err)
		} else {
			updatedSources = append(updatedSources, "Local")
			printStatus("INFO", "Loaded local custom rules")
		}
	}

	// Built-in rules
	builtInRules := filepath.Join(YaraRulesDir, "built_in.yar")
	builtInContent := `
rule CriticalUEFIMalware {
    meta:
        description = "Critical UEFI malware patterns"
        author = "sl0ppy"
    strings:
        $lojax1 = {48 89 5C 24 F8 48 89 6C 24}
        $lojax2 = {48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24}
        $moonbounce1 = {55 48 89 E5 48 83 EC 30}
        $moonbounce2 = {48 89 7D E8 48 89 55 E0}
        $espionage1 = {48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 0D ?? ?? ?? ?? 48 33 C9 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 00 48 85 C0 74 ?? FF 15}
        $espionage2 = {48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 0D ?? ?? ?? ?? 48 33 C9 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 00 48 85 C0 74 ?? FF 15}
    condition:
        any of them
}
`
	if err := os.WriteFile(builtInRules, []byte(builtInContent), 0644); err != nil {
		printStatus("WARNING", "Failed to write built-in rules: %v", err)
	} else {
		updatedSources = append(updatedSources, "Built-in")
	}

	return updatedSources, nil
}

func downloadWithClient(client *http.Client, urlStr, dest string) error {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return fmt.Errorf("bad request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status: %d %s", resp.StatusCode, resp.Status)
	}
	outFile, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create file error: %v", err)
	}
	defer outFile.Close()
	_, err = io.Copy(outFile, resp.Body)
	return err
}

func checkRuleFreshness() (bool, error) {
	entries, err := os.ReadDir(YaraRulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	if len(entries) == 0 {
		return true, nil
	}
	now := time.Now()
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yar") {
			continue
		}
		filePath := filepath.Join(YaraRulesDir, e.Name())
		fi, err := os.Stat(filePath)
		if err != nil {
			continue
		}
		if now.Sub(fi.ModTime()) < MaxRuleAge {
			return false, nil
		}
	}
	return true, nil
}

func loadYARARules() ([]MalwareSignature, error) {
	var rules []MalwareSignature
	defaultRules := []MalwareSignature{
		{
			Name: "LoJax_Fallback",
			Pattern: `rule LoJax_Fallback {
    meta:
        description = "LoJax bootkit pattern"
        author = "sl0ppy"
    strings:
        $a = {48 89 5C 24 F8 48 89 6C 24}
    condition:
        $a
}`,
			Severity:      "CRITICAL",
			Source:        "Built-in",
			Category:      "Bootkit",
			ConfirmationReq: 1,
		},
	}

	entries, err := os.ReadDir(YaraRulesDir)
	if err != nil {
		return defaultRules, fmt.Errorf("failed to read rules directory: %v", err)
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
		printStatus("WARNING", "No YARA rules found, using built-in defaults")
		return defaultRules, nil
	}

	return rules, nil
}

func parseYARAFile(filePath, content string) ([]MalwareSignature, error) {
	var rules []MalwareSignature
	ruleBlocks := regexp.MustCompile(`rule\s+([^\s{]+)\s*{([^}]+)}`).FindAllStringSubmatch(content, -1)
	for _, block := range ruleBlocks {
		ruleName := strings.TrimSpace(block[1])
		ruleContent := strings.TrimSpace(block[0])
		severity := "HIGH"
		category := "Malware"
		confirmationReq := 1
		cve := ""
		lastUpdated := "unknown"
		lowerName := strings.ToLower(ruleName)
		if strings.Contains(lowerName, "bootkit") {
			category = "Bootkit"
			severity = "CRITICAL"
			confirmationReq = 2
		} else if strings.Contains(lowerName, "rootkit") {
			category = "Rootkit"
			severity = "CRITICAL"
			confirmationReq = 2
		} else if strings.Contains(lowerName, "spy") {
			category = "Spyware"
			severity = "HIGH"
			confirmationReq = 2
		} else if strings.Contains(lowerName, "rat") {
			category = "RAT"
			severity = "CRITICAL"
			confirmationReq = 2
		}
		if strings.Contains(lowerName, "cve") {
			cveMatch := regexp.MustCompile(`cve-?\d{4}-\d+`).FindString(lowerName)
			if cveMatch != "" {
				cve = strings.ToUpper(cveMatch)
			}
		}
		fileInfo, err := os.Stat(filePath)
		if err == nil {
			lastUpdated = fileInfo.ModTime().Format(time.RFC3339)
		}
		rules = append(rules, MalwareSignature{
			Name:          ruleName,
			Pattern:       ruleContent,
			Severity:      severity,
			Source:        "AutoUpdated:" + filepath.Base(filePath),
			Category:      category,
			ConfirmationReq: confirmationReq,
			CVE:           cve,
			RuleFile:      filePath,
			LastUpdated:   lastUpdated,
		})
	}
	return rules, nil
}

// --- Helper Functions ---
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// --- System Information ---
func checkSystemInfo(evidence *Evidence) {
	cmd := exec.Command("systemd-detect-virt")
	output, err := cmd.Output()
	if err == nil {
		virt := strings.TrimSpace(string(output))
		if virt != "none" {
			evidence.Hardware.Virtualization = virt
			printStatus("INFO", "Running in virtualized environment: %s", virt)
		} else {
			evidence.Hardware.Virtualization = "baremetal"
			printStatus("INFO", "Running on bare metal")
		}
	}

	cmd = exec.Command("lscpu")
	output, err = cmd.Output()
	if err == nil {
		printStatus("INFO", "CPU Information:\n%s", strings.TrimSpace(string(output)))
	}

	cmd = exec.Command("cat", "/etc/os-release")
	output, err = cmd.Output()
	if err == nil {
		printStatus("INFO", "OS Information:\n%s", strings.TrimSpace(string(output)))
	}
}

// --- Firmware Integrity ---
func checkFirmwareIntegrity(evidence *Evidence) {
	regions := []UEFIFirmwareRegion{
		{Name: "BIOS Region", Start: 0x1000000, End: 0x2000000, Expected: trustedHashes["BIOS Region"], TPMBound: true, Critical: true},
		{Name: "ME Region", Start: 0x3000000, End: 0x4000000, Expected: trustedHashes["ME Region"], TPMBound: true, Critical: true},
		{Name: "EC Region", Start: 0x5000000, End: 0x6000000, Expected: trustedHashes["EC Region"], TPMBound: false, Critical: false},
	}

	for _, region := range regions {
		hash, err := readAndHashRegion(region.Start, region.End)
		status := "OK"
		if err != nil {
			status = fmt.Sprintf("ERROR: %v", err)
			printStatus("WARNING", "%s: %v", region.Name, err)
			if region.Critical {
				printStatus("WARNING", "Critical firmware region could not be read!")
				evidence.Recommendations = append(evidence.Recommendations,
					fmt.Sprintf("Investigate why %s could not be read (permission issue?)", region.Name))
			}
		} else if region.Expected != "" && hash != region.Expected {
			status = "CRITICAL: Hash mismatch (possible tampering)"
			printStatus("CRITICAL", "%s: Expected %s, got %s", region.Name, region.Expected, hash)
			evidence.Recommendations = append(evidence.Recommendations,
				fmt.Sprintf("Investigate %s tampering (expected: %s, got: %s)", region.Name, region.Expected, hash))
		} else if region.TPMBound {
			printStatus("SUCCESS", "%s: %s (TPM-bound)", region.Name, hash)
		} else if region.Critical {
			printStatus("WARNING", "%s: %s (not TPM-bound)", region.Name, hash)
			evidence.Recommendations = append(evidence.Recommendations,
				fmt.Sprintf("Bind %s to TPM for anti-tampering protection", region.Name))
		} else {
			printStatus("INFO", "%s: %s", region.Name, hash)
		}

		evidence.Firmware = append(evidence.Firmware, FirmwareCheck{
			Region:   region.Name,
			Hash:     hash,
			Expected: region.Expected,
			Status:   status,
			TPMBound: region.TPMBound,
		})
	}

	spiLock, err := checkSPILock()
	if err != nil {
		printStatus("WARNING", "SPI lock check failed: %v", err)
	} else if spiLock {
		printStatus("SUCCESS", "SPI flash write protection is enabled")
		evidence.Hardware.SPILock = true
	} else {
		printStatus("CRITICAL", "SPI flash write protection is disabled!")
		evidence.Hardware.SPILock = false
		evidence.Recommendations = append(evidence.Recommendations,
			"Enable BIOS write protection (SPI lock) to prevent firmware flashing attacks")
	}

	checkFirmwareUpdates(evidence)
}

func readAndHashRegion(start, end uint64) (string, error) {
	data, err := readMemory(start, end)
	if err == nil {
		h := sha512.Sum512(data)
		return hex.EncodeToString(h[:]), nil
	}

	printStatus("WARNING", "Falling back to dmidecode for firmware reading...")
	cmd := exec.Command("sudo", "dmidecode", "-t", "bios")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to read firmware via dmidecode: %v", err)
	}
	h := sha512.Sum512(output)
	return hex.EncodeToString(h[:]), nil
}

func readMemory(start, end uint64) ([]byte, error) {
	cmd := exec.Command("sudo", "dd", "if=/dev/mem", fmt.Sprintf("bs=1"), fmt.Sprintf("skip=%d", start), fmt.Sprintf("count=%d", end-start), "status=none")
	output, err := cmd.Output()
	if err == nil {
		return output, nil
	}

	memFile, err := os.OpenFile("/dev/mem", os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/mem: %v (try running with sudo)", err)
	}
	defer memFile.Close()

	_, err = memFile.Seek(int64(start), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to 0x%x: %v", start, err)
	}

	data := make([]byte, end-start)
	_, err = memFile.Read(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read memory: %v", err)
	}

	return data, nil
}

func checkSPILock() (bool, error) {
	cmd := exec.Command("sudo", "flashrom", "--wp-status")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("flashrom failed: %v", err)
	}
	return strings.Contains(string(output), "WP: enabled"), nil
}

func checkFirmwareUpdates(evidence *Evidence) {
	cmd := exec.Command("sudo", "dmidecode", "-t", "bios")
	output, err := cmd.Output()
	if err != nil {
		printStatus("WARNING", "Failed to check BIOS version: %v", err)
		return
	}

	versionRegex := regexp.MustCompile(`Version: (.+)`)
	matches := versionRegex.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		biosVersion := matches[1]
		printStatus("INFO", "Current BIOS version: %s", biosVersion)
		evidence.Recommendations = append(evidence.Recommendations,
			fmt.Sprintf("Verify BIOS version %s is the latest available from your vendor", biosVersion))
	}

	cmd = exec.Command("sudo", "intelmetool")
	_, err = cmd.Output()
	if err != nil {
		printStatus("WARNING", "Intel ME tools not available - cannot check ME firmware version")
		evidence.Recommendations = append(evidence.Recommendations,
			"Install intelmetool to check Intel ME firmware version")
	} else {
		evidence.Recommendations = append(evidence.Recommendations,
			"Check Intel ME firmware version with: sudo intelmetool")
	}
}

// --- Threat Scanning ---
func scanForThreats(evidence *Evidence, yaraRules []MalwareSignature) {
	for _, sig := range yaraRules {
		printStatus("INFO", "Scanning for %s (%s, %s, last updated: %s)...",
			sig.Name, sig.Category, sig.Source, sig.LastUpdated)

		indicators := 0
		yaraDetected := false

		// 1. YARA Scan
		detected, err := scanWithYARA(sig.Pattern, "/sys/firmware/efi/efivars/")
		if err != nil {
			printStatus("WARNING", "YARA scan for %s failed: %v", sig.Name, err)
			continue
		}
		if detected {
			yaraDetected = true
			indicators++
		}

		// 2. NVRAM Anomalies (only for Spyware/RAT)
		if (sig.Category == "Spyware" || sig.Category == "RAT") && !yaraDetected {
			for _, nvramVar := range getNVRAMVars() {
				if nvramVar.Critical {
					value, _ := readNVRAMVariable(nvramVar.Name)
					if value == "" || strings.Contains(value, "00000000") {
						indicators++
						break
					}
				}
			}
		}

		// 3. Suspicious Module Check (only for Rootkit/Bootkit)
		if (sig.Category == "Rootkit" || sig.Category == "Bootkit") && !yaraDetected {
			files, _ := filepath.Glob("/sys/firmware/efi/efivars/*smm*")
			if len(files) > 0 {
				indicators++
			}
		}

		// Determine confidence level
		confidence := "Low"
		detectedFinal := false

		if yaraDetected && indicators >= sig.ConfirmationReq {
			confidence = "High"
			detectedFinal = true
		} else if yaraDetected || indicators > 0 {
			confidence = "Medium"
		}

		// Log results
		if detectedFinal {
			printStatus("CRITICAL", "%s (%s, %s) detected! Confidence: %s (%d/%d indicators)",
				sig.Name, sig.Category, sig.CVE, confidence, indicators, sig.ConfirmationReq)
		} else if confidence == "Medium" {
			printStatus("WARNING", "%s (%s, %s) possible! Confidence: %s (%d/%d indicators)",
				sig.Name, sig.Category, sig.CVE, confidence, indicators, sig.ConfirmationReq)
		} else {
			printStatus("INFO", "%s (%s, %s): Not found", sig.Name, sig.Category, sig.CVE)
		}

		// Add to evidence
		evidence.Malware = append(evidence.Malware, MalwareCheck{
			Name:       sig.Name,
			Detected:   detectedFinal,
			Severity:   sig.Severity,
			Source:     sig.Source,
			Category:   sig.Category,
			Confidence: confidence,
			Indicators: indicators,
			CVE:        sig.CVE,
			RuleFile:   sig.RuleFile,
		})
	}
}

func scanWithYARA(rule, target string) (bool, error) {
	// Create a temporary file for the YARA rule
	ruleFile, err := os.CreateTemp("", "yara_rule_*.yar")
	if err != nil {
		return false, fmt.Errorf("failed to create temp YARA file: %v", err)
	}
	defer os.Remove(ruleFile.Name())

	// Write the rule to the temporary file
	_, err = ruleFile.WriteString(rule)
	if err != nil {
		ruleFile.Close()
		return false, fmt.Errorf("failed to write YARA rule: %v", err)
	}
	ruleFile.Close()

	// Verify YARA is installed
	if _, err := exec.LookPath("yara"); err != nil {
		return false, fmt.Errorf("YARA is not installed. Install it with: sudo apt install yara")
	}

	// Execute the YARA command
	cmd := exec.Command("yara", "-w", ruleFile.Name(), target)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if ok {
			// YARA returns exit code 1 when no matches are found
			if exitError.ExitCode() == 1 {
				return false, nil
			}
			return false, fmt.Errorf("YARA scan failed with exit code %d: %s", exitError.ExitCode(), stderr.String())
		}
		return false, fmt.Errorf("YARA scan failed: %v", err)
	}

	return true, nil
}

// --- NVRAM Validation ---
func getNVRAMVars() []NVRAMVariable {
	return []NVRAMVariable{
		{Name: "BootOrder", Expected: "", Critical: true, Pattern: `^([0-9A-F]{4},?)+$`},
		{Name: "Boot####", Expected: "", Critical: false, Pattern: `^([0-9A-F]{4},?)+$`},
		{Name: "PK", Expected: "", Critical: true, Pattern: `^[0-9A-F]+$`},
		{Name: "KEK", Expected: "", Critical: true, Pattern: `^[0-9A-F]+$`},
		{Name: "db", Expected: "", Critical: true, Pattern: `^[0-9A-F]+$`},
		{Name: "dbx", Expected: "", Critical: true, Pattern: `^[0-9A-F]+$`},
		{Name: "OsIndications", Expected: "", Critical: false, Pattern: `^[0-9A-F]+$`},
		{Name: "ConIn", Expected: "", Critical: false, Pattern: `^[0-9A-F]+$`},
		{Name: "ConOut", Expected: "", Critical: false, Pattern: `^[0-9A-F]+$`},
		{Name: "ErrOut", Expected: "", Critical: false, Pattern: `^[0-9A-F]+$`},
		{Name: "Timeout", Expected: "", Critical: false, Pattern: `^[0-9A-F]+$`},
		{Name: "BootNext", Expected: "", Critical: false, Pattern: `^[0-9A-F]+$`},
		{Name: "SetupMode", Expected: "", Critical: true, Pattern: `^[0-9A-F]+$`},
		{Name: "AuditMode", Expected: "", Critical: true, Pattern: `^[0-9A-F]+$`},
		{Name: "DeployedMode", Expected: "", Critical: true, Pattern: `^[0-9A-F]+$`},
	}
}

func validateNVRAM(evidence *Evidence) {
	nvramVars := getNVRAMVars()
	for _, nvramVar := range nvramVars {
		value, err := readNVRAMVariable(nvramVar.Name)
		status := "OK"
		valid := true
		if err != nil {
			status = fmt.Sprintf("ERROR: %v", err)
			valid = false
			printStatus("WARNING", "%s: %v", nvramVar.Name, err)
		} else if nvramVar.Pattern != "" {
			matched, _ := regexp.MatchString(nvramVar.Pattern, value)
			if !matched {
				status = "CRITICAL: Invalid format (possible tampering)"
				valid = false
				printStatus("CRITICAL", "%s: Value '%s' does not match expected pattern", nvramVar.Name, value)
			}
		} else if nvramVar.Expected != "" && value != nvramVar.Expected {
			status = "CRITICAL: Unexpected value (possible tampering)"
			valid = false
			printStatus("CRITICAL", "%s: Expected '%s', got '%s'", nvramVar.Name, nvramVar.Expected, value)
		} else if nvramVar.Critical && (value == "" || value == "00000000" || len(value) < 4) {
			status = "WARNING: Critical NVRAM variable empty or default"
			valid = false
			printStatus("WARNING", "%s: Value is '%s' (default/empty)", nvramVar.Name, value)
		} else {
			if matches, _ := regexp.MatchString(`(?:[A-Fa-f0-9]\s*){8,}`, value); !matches {
				status = "WARNING: NVRAM value format suspicious"
				valid = false
				printStatus("WARNING", "%s: Value '%s' (unexpected format)", nvramVar.Name, value)
			} else {
				printStatus("INFO", "%s: '%s'", nvramVar.Name, value)
			}
		}
		evidence.NVRAM = append(evidence.NVRAM, NVRAMCheck{
			Name:     nvramVar.Name,
			Value:    value,
			Expected: nvramVar.Expected,
			Status:   status,
			Valid:    valid,
		})
	}
	checkSecureBootVariables(evidence)
}

func readNVRAMVariable(name string) (string, error) {
	files, err := filepath.Glob(fmt.Sprintf("/sys/firmware/efi/efivars/%s-*", name))
	if err != nil {
		return "", fmt.Errorf("failed to find NVRAM variable: %v", err)
	}
	if len(files) == 0 {
		return "", fmt.Errorf("NVRAM variable %s not found", name)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		return "", fmt.Errorf("failed to read NVRAM variable: %v", err)
	}
	return hex.EncodeToString(data), nil
}

func checkSecureBootVariables(evidence *Evidence) {
	printStatus("INFO", "\n--- Secure Boot Variables Check ---")
	criticalVars := []struct {
		Name      string
		Desc      string
		Recommend string
	}{
		{"PK", "Platform Key", "Set a proper Platform Key (PK) for Secure Boot"},
		{"KEK", "Key Exchange Key", "Set a proper Key Exchange Key (KEK) for Secure Boot"},
		{"SetupMode", "Secure Boot Setup Mode", "Disable SetupMode to fully enable Secure Boot"},
	}
	for _, varInfo := range criticalVars {
		value, err := readNVRAMVariable(varInfo.Name)
		if err != nil {
			printStatus("WARNING", "Failed to read %s: %v", varInfo.Name, err)
			evidence.Recommendations = append(evidence.Recommendations,
				fmt.Sprintf("Investigate why %s could not be read", varInfo.Name))
		} else if value == "" || value == "00000000" {
			printStatus("CRITICAL", "%s (%s) is empty or default!", varInfo.Name, varInfo.Desc)
			evidence.Recommendations = append(evidence.Recommendations,
				varInfo.Recommend,
				fmt.Sprintf("Run: sudo mokutil --disable-validation (for SetupMode)"))
		} else {
			printStatus("INFO", "%s (%s) is set", varInfo.Name, varInfo.Desc)
		}
	}
	nonCriticalVars := []struct {
		Name string
		Desc string
	}{
		{"db", "Allowed Signatures Database"},
		{"dbx", "Forbidden Signatures Database"},
	}
	for _, varInfo := range nonCriticalVars {
		value, err := readNVRAMVariable(varInfo.Name)
		if err != nil {
			printStatus("WARNING", "Failed to read %s: %v", varInfo.Name, err)
		} else if value == "" || value == "00000000" {
			printStatus("WARNING", "%s (%s) is empty or default!", varInfo.Name, varInfo.Desc)
			evidence.Recommendations = append(evidence.Recommendations,
				fmt.Sprintf("Review %s for proper signatures", varInfo.Name))
		} else {
			printStatus("INFO", "%s (%s) is set", varInfo.Name, varInfo.Desc)
		}
	}
}

// --- Hardware Security ---
func checkHardwareSecurity(evidence *Evidence) {
	txtEnabled, err := checkIntelTXT()
	if err != nil {
		printStatus("WARNING", "Intel TXT check: %v", err)
		evidence.Hardware.IntelTXT = false
	} else if txtEnabled {
		printStatus("SUCCESS", "Intel TXT is enabled.")
		evidence.Hardware.IntelTXT = true
	} else {
		printStatus("WARNING", "Intel TXT is not enabled.")
		evidence.Hardware.IntelTXT = false
		evidence.Recommendations = append(evidence.Recommendations,
			"Enable Intel TXT in BIOS for additional protection against firmware attacks")
	}

	tpmVersion, tpmEnabled, err := checkTPM()
	if err != nil {
		printStatus("WARNING", "TPM check: %v", err)
		evidence.Hardware.TPM = false
	} else if tpmEnabled {
		printStatus("SUCCESS", "TPM %s is present and accessible.", tpmVersion)
		evidence.Hardware.TPM = true
		evidence.Hardware.TPMVersion = tpmVersion

		measuredBoot, err := checkMeasuredBoot()
		if err != nil {
			printStatus("WARNING", "Measured Boot check: %v", err)
		} else if measuredBoot {
			printStatus("SUCCESS", "Measured Boot is enabled (TPM PCRs are extended)")
			evidence.Hardware.MeasuredBoot = true
		} else {
			printStatus("WARNING", "Measured Boot is not detected")
			evidence.Hardware.MeasuredBoot = false
			evidence.Recommendations = append(evidence.Recommendations,
				"Enable Measured Boot for attestation and anti-rollback protection")
		}
	} else {
		printStatus("WARNING", "TPM is not found or accessible.")
		evidence.Hardware.TPM = false
		evidence.Recommendations = append(evidence.Recommendations,
			"Enable and configure TPM 2.0 for secure boot and measured boot")
	}

	secureBoot, err := checkSecureBoot()
	if err != nil {
		printStatus("WARNING", "Secure Boot check: %v", err)
		evidence.Hardware.SecureBoot = "unknown"
	} else {
		printStatus("INFO", "Secure Boot is %s.", secureBoot)
		evidence.Hardware.SecureBoot = secureBoot
		if secureBoot != "enabled" {
			evidence.Recommendations = append(evidence.Recommendations,
				"Enable Secure Boot to prevent unauthorized UEFI modifications")
		}
	}

	checkSuspiciousModules(evidence)
}

// --- Vulnerability Checks ---
func checkVulnerabilities(evidence *Evidence) {
	printStatus("INFO", "\n--- UEFI Vulnerability Check ---")
	for _, vuln := range uefiVulnerabilities {
		detected := false
		switch vuln.CVE {
		case "CVE-2023-20569":
			files, _ := filepath.Glob("/sys/firmware/efi/efivars/*smm*")
			if len(files) > 3 {
				detected = true
			}
		case "CVE-2022-31705":
			files, _ := filepath.Glob("/sys/firmware/efi/efivars/*dxe*")
			if len(files) > 5 {
				detected = true
			}
		case "CVE-2022-34303":
			cmd := exec.Command("sudo", "intelmetool")
			_, err := cmd.Output()
			if err != nil {
				detected = true
			}
		case "CVE-2021-28210":
			cmd := exec.Command("sudo", "dmidecode", "-t", "bios")
			output, _ := cmd.Output()
			if strings.Contains(string(output), "American Megatrends") {
				versionRegex := regexp.MustCompile(`Version: (.+)`)
				matches := versionRegex.FindStringSubmatch(string(output))
				if len(matches) > 1 && strings.HasPrefix(matches[1], "5.") {
					detected = true
				}
			}
		}
		if detected {
			printStatus("CRITICAL", "Vulnerability detected: %s (%s)", vuln.Name, vuln.CVE)
			printStatus("CRITICAL", "    Severity: %s", vuln.Severity)
			printStatus("CRITICAL", "    Fix: %s", vuln.Fix)
		} else {
			printStatus("INFO", "%s (%s): Not detected", vuln.Name, vuln.CVE)
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

// --- Helper Functions ---
func checkIntelTXT() (bool, error) {
	cmd := exec.Command("sudo", "dmesg")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("Intel TXT check failed: %v", err)
	}
	if strings.Contains(string(output), "tboot") {
		return true, nil
	}
	if _, err := os.Stat("/sys/kernel/security/tboot"); err == nil {
		return true, nil
	}
	cmd = exec.Command("grep", "tboot", "/proc/cpuinfo")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return true, nil
	}
	return false, nil
}

func checkTPM() (string, bool, error) {
	cmd := exec.Command("tpm2_getrandom", "8")
	err := cmd.Run()
	if err == nil {
		cmd = exec.Command("tpm2_getcap", "tpm-properties-fixed")
		output, err := cmd.Output()
		if err == nil {
			if strings.Contains(string(output), "TPM 2.0") {
				return "2.0", true, nil
			}
			return "1.2", true, nil
		}
		return "unknown", true, nil
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		cmd = exec.Command("cat", "/sys/class/tpm/tpm0/tpm_version")
		output, err := cmd.Output()
		if err == nil {
			version := strings.TrimSpace(string(output))
			if strings.HasPrefix(version, "2.") {
				return "2.0", true, nil
			}
			return "1.2", true, nil
		}
		return "unknown", true, nil
	}
	return "", false, fmt.Errorf("TPM not found or accessible")
}

func checkSecureBoot() (string, error) {
	cmd := exec.Command("mokutil", "--sb-state")
	output, err := cmd.CombinedOutput()
	if err == nil {
		if strings.Contains(string(output), "SecureBoot enabled") {
			return "enabled", nil
		}
		return "disabled", nil
	}
	if _, err := os.Stat("/sys/firmware/efi/efivars/SecureBoot-*"); err == nil {
		return "enabled", nil
	}
	cmd = exec.Command("test", "-d", "/sys/firmware/efi")
	if err = cmd.Run(); err == nil {
		cmd = exec.Command("cat", "/sys/firmware/efi/efivars/SecureBoot-*/data")
		output, err := cmd.CombinedOutput()
		if err == nil && len(output) > 0 && output[0] == 1 {
			return "enabled", nil
		}
		return "disabled", nil
	}
	return "unknown", fmt.Errorf("Secure Boot check failed")
}

func checkMeasuredBoot() (bool, error) {
	if _, err := os.Stat("/sys/kernel/security/ima/ascii_runtime_measurements"); err == nil {
		return true, nil
	}
	if _, err := os.Stat("/sys/kernel/security/tpm0/binary_bios_measurements"); err == nil {
		return true, nil
	}
	cmd := exec.Command("dmesg")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	if strings.Contains(string(output), "measured boot") ||
	   strings.Contains(string(output), "TPM event log") ||
	   strings.Contains(string(output), "IMA:") {
		return true, nil
	}
	return false, nil
}

func checkSuspiciousModules(evidence *Evidence) {
	printStatus("INFO", "\n--- Suspicious UEFI Modules Check ---")
	modules := []struct {
		Name     string
		Pattern  string
		Critical bool
		Desc     string
	}{
		{"SMM Modules", "*smm*", true, "System Management Mode modules (common target for rootkits)"},
		{"DXE Modules", "*dxe*", true, "Driver Execution Environment modules (common for bootkits)"},
		{"PEI Modules", "*pei*", true, "Pre-EFI Initialization modules (early boot attacks)"},
		{"Runtime Modules", "*runtime*", false, "UEFI runtime services (persistent modules)"},
		{"Unknown Modules", "*-unknown-*", true, "Unrecognized UEFI variables (potentially malicious)"},
	}
	for _, module := range modules {
		files, err := filepath.Glob(fmt.Sprintf("/sys/firmware/efi/efivars/%s", module.Pattern))
		if err != nil {
			printStatus("WARNING", "Failed to check %s: %v", module.Name, err)
			continue
		}
		if len(files) > 0 {
			severity := "WARNING"
			if module.Critical {
				severity = "CRITICAL"
			}
			printStatus(severity, "%s found (%d): %s", module.Name, len(files), module.Desc)
			for _, file := range files {
				printStatus(severity, "  - %s", filepath.Base(file))
				data, _ := os.ReadFile(file)
				hexData := hex.EncodeToString(data)
				if len(hexData) > 0 {
					displayHex := hexData
					if len(hexData) > 32 {
						displayHex = hexData[:32] + "..."
					}
					printStatus(severity, "    Content: %s", displayHex)
					if strings.Contains(hexData, "48895c24f8") {
						printStatus("WARNING", "    ⚠ Suspicious pattern found in module content!")
					}
				}
			}
		} else {
			printStatus("INFO", "No suspicious %s found.", module.Name)
		}
	}
}

// --- Recommendations ---
func generateRecommendations(evidence *Evidence) {
	printStatus("INFO", "\n--- Security Recommendations ---")
	var critical, high, medium []string
	for _, fw := range evidence.Firmware {
		if strings.Contains(fw.Status, "CRITICAL") {
			critical = append(critical,
				fmt.Sprintf("Investigate %s firmware tampering (current hash: %s)", fw.Region, fw.Hash))
		} else if strings.Contains(fw.Status, "WARNING") && fw.TPMBound == false {
			high = append(high,
				fmt.Sprintf("Bind %s firmware hash to TPM for anti-tampering protection", fw.Region))
		}
	}
	for _, malware := range evidence.Malware {
		if malware.Detected && malware.Confidence == "High" {
			critical = append(critical,
				fmt.Sprintf("Immediately investigate %s (%s) infection (CVE: %s, Source: %s)",
					malware.Name, malware.Category, malware.CVE, malware.Source))
			if malware.Category == "Bootkit" || malware.Category == "Rootkit" {
				critical = append(critical,
					"  → Consider wiping and reinstalling the system from known-good media",
					"  → Use hardware write protection during recovery")
			}
		} else if malware.Detected && malware.Confidence == "Medium" {
			high = append(high,
				fmt.Sprintf("Review system for potential %s (%s) activity (Source: %s)",
					malware.Name, malware.Category, malware.Source))
		}
	}
	for _, nvram := range evidence.NVRAM {
		if !nvram.Valid {
			for _, varDef := range getNVRAMVars() {
				if varDef.Name == nvram.Name && varDef.Critical {
					high = append(high,
						fmt.Sprintf("Restore %s to a known-good state (current: '%s')", nvram.Name, nvram.Value))
					if nvram.Name == "PK" || nvram.Name == "KEK" {
						high = append(high,
							"  → Use your vendor's tools to reset Secure Boot keys",
							"  → Example: sudo mokutil --reset")
					}
					break
				}
			}
		}
	}
	for _, vuln := range evidence.Vulnerabilities {
		if vuln.Detected {
			high = append(high,
				fmt.Sprintf("Apply patch for %s (%s): %s", vuln.Name, vuln.CVE, vuln.Fix))
		}
	}
	if !evidence.Hardware.IntelTXT {
		medium = append(medium, "Enable Intel TXT in BIOS for additional protection against firmware attacks")
	}
	if !evidence.Hardware.TPM {
		high = append(high, "Enable and configure TPM 2.0 in BIOS for secure boot and measured boot")
	}
	if evidence.Hardware.SecureBoot != "enabled" {
		high = append(high, "Enable Secure Boot in BIOS to prevent unauthorized UEFI modifications")
	}
	if !evidence.Hardware.SPILock {
		high = append(high, "Enable BIOS write protection (SPI lock) to prevent firmware flashing attacks")
	}
	if !evidence.Hardware.MeasuredBoot {
		medium = append(medium, "Enable Measured Boot for attestation and anti-rollback protection")
	}
	evidence.Recommendations = append(evidence.Recommendations, critical...)
	evidence.Recommendations = append(evidence.Recommendations, high...)
	evidence.Recommendations = append(evidence.Recommendations, medium...)
	for i, rec := range critical {
		criticalColor.Printf("  [%02d] %s\n", i+1, rec)
	}
	offset := len(critical)
	for i, rec := range high {
		warningColor.Printf("  [%02d] %s\n", offset+i+1, rec)
	}
	offset += len(high)
	for i, rec := range medium {
		infoColor.Printf("  [%02d] %s\n", offset+i+1, rec)
	}
}

// --- Forensic Reporting ---
func generateReport(evidence *Evidence) {
	reportDir := "/var/log/sl0ppy_uefi_scan"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		printStatus("CRITICAL", "Failed to create report directory: %v", err)
		return
	}
	timestamp := time.Now().Format("20060102_150405")
	report, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		printStatus("CRITICAL", "Failed to generate JSON report: %v", err)
	} else {
		reportPath := filepath.Join(reportDir, fmt.Sprintf("report_%s.json", timestamp))
		if err := os.WriteFile(reportPath, report, 0600); err != nil {
			printStatus("CRITICAL", "Failed to write JSON report: %v", err)
		} else {
			printStatus("SUCCESS", "JSON report generated: %s", reportPath)
		}
	}
	summaryPath := filepath.Join(reportDir, fmt.Sprintf("summary_%s.txt", timestamp))
	if err := generateSummaryReport(evidence, summaryPath); err != nil {
		printStatus("CRITICAL", "Failed to write summary report: %v", err)
	} else {
		printStatus("SUCCESS", "Summary report generated: %s", summaryPath)
	}
	printStatus("INFO", "To analyze later:")
	infoColor.Println("    jq . " + filepath.Join(reportDir, fmt.Sprintf("report_%s.json", timestamp)))
	infoColor.Println("    cat " + summaryPath)
}

func generateSummaryReport(evidence *Evidence, path string) error {
	content := fmt.Sprintf(
		"==================================================\n"+
			"=            sl0ppy UEFI Scan Summary v%s           =\n"+
			"=          [ FULL COVERAGE UEFI ANALYSIS ]        =\n"+
			"==================================================\n\n"+
			"Hostname: %s\n"+
			"Timestamp: %s\n"+
			"Rules Updated From: %s\n"+
			"Virtualization: %s\n\n"+
			"=== [ Firmware Integrity ] =======================\n",
		evidence.Version, evidence.Hostname, evidence.Timestamp,
		strings.Join(evidence.RulesUpdated, ", "), evidence.Hardware.Virtualization)
	criticalFirmware := 0
	for _, fw := range evidence.Firmware {
		status := "OK"
		if strings.Contains(fw.Status, "CRITICAL") {
			status = criticalColor.Sprintf("CRITICAL")
			criticalFirmware++
		} else if strings.Contains(fw.Status, "WARNING") {
			status = warningColor.Sprintf("WARNING")
		}
		content += fmt.Sprintf("  %-12s: %s\n", fw.Region, status)
	}
	content += "\n=== [ UEFI Threats ] ============================\n"
	criticalThreats := 0
	for _, malware := range evidence.Malware {
		if malware.Detected {
			criticalThreats++
			severityColor := warningColor
			if malware.Severity == "CRITICAL" {
				severityColor = criticalColor
			}
			content += fmt.Sprintf("  %-20s %-12s %s (%d indicators)\n",
				severityColor.Sprintf(malware.Name),
				severityColor.Sprintf("["+malware.Severity+"]"),
				malware.Category,
				malware.Indicators)
			content += fmt.Sprintf("    Source: %s, CVE: %s\n",
				malware.Source, malware.CVE)
		}
	}
	if criticalThreats == 0 {
		content += "  " + successColor.Sprintf("No threats detected") + "\n"
	}
	content += "\n=== [ NVRAM Status ] ============================\n"
	criticalNVRAM := 0
	for _, nvram := range evidence.NVRAM {
		if !nvram.Valid {
			criticalNVRAM++
		}
		status := "OK"
		if !nvram.Valid {
			status = criticalColor.Sprintf("INVALID")
		}
		content += fmt.Sprintf("  %-15s: %s\n", nvram.Name, status)
	}
	content += "\n=== [ Hardware Security ] =======================\n"
	content += fmt.Sprintf("  %-18s: %t\n", "Intel TXT", evidence.Hardware.IntelTXT)
	content += fmt.Sprintf("  %-18s: %t (v%s)\n", "TPM", evidence.Hardware.TPM, evidence.Hardware.TPMVersion)
	content += fmt.Sprintf("  %-18s: %s\n", "Secure Boot", evidence.Hardware.SecureBoot)
	content += fmt.Sprintf("  %-18s: %t\n", "SPI Lock", evidence.Hardware.SPILock)
	content += fmt.Sprintf("  %-18s: %t\n", "Measured Boot", evidence.Hardware.MeasuredBoot)
	content += "\n=== [ Vulnerabilities ] =========================\n"
	vulnCount := 0
	for _, vuln := range evidence.Vulnerabilities {
		if vuln.Detected {
			vulnCount++
			severityColor := warningColor
			if vuln.Severity == "CRITICAL" {
				severityColor = criticalColor
			}
			content += fmt.Sprintf("  %-30s %-12s %s\n",
				vuln.Name,
				severityColor.Sprintf("["+vuln.Severity+"]"),
				vuln.CVE)
			content += fmt.Sprintf("    Fix: %s\n", vuln.Fix)
		}
	}
	if vulnCount == 0 {
		content += "  " + successColor.Sprintf("No vulnerabilities detected") + "\n"
	}
	content += "\n=== [ Security Recommendations ] ===============\n"
	for i, rec := range evidence.Recommendations {
		content += fmt.Sprintf("  [%02d] %s\n", i+1, rec)
	}
	content += "\n=== [ Scan Statistics ] =========================\n"
	content += fmt.Sprintf("  %-30s: %d\n", "Critical firmware issues", criticalFirmware)
	content += fmt.Sprintf("  %-30s: %d\n", "Critical threats detected", criticalThreats)
	content += fmt.Sprintf("  %-30s: %d\n", "NVRAM issues found", criticalNVRAM)
	content += fmt.Sprintf("  %-30s: %d\n", "Vulnerabilities found", vulnCount)
	if criticalFirmware > 0 || criticalThreats > 0 || criticalNVRAM > 0 || vulnCount > 0 {
		content += "\n" + criticalColor.Sprintf("⚠ SYSTEM MAY BE COMPROMISED! Immediate action recommended.") + "\n"
	} else {
		content += "\n" + successColor.Sprintf("✓ No critical issues found.") + "\n"
	}
	return ioutil.WriteFile(path, []byte(content), 0644)
}
