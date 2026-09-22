// ---------------------------------
// --     Sl0ppy-UEFIScan         --
// -- Author  : Patrick Hoogeveen --
// -- AKA     : x0xr00t           --
// -- build   : 20251001          --
// -- revised : 20260922          --
// -- version : v1.4.1            --
//                                //
// 0x0x0x0x0x0x0x0x0x0x0x0x0x0x0x //
// A Team sl0ppyr00t build.       //
// This is a golang UEFISCANNER.  //
// 0x0x0x0x0x0x0x0x0x0x0x0x0x0x0x //
//----------------------------------
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	version                 = "10.5"
	maxRead                 = 32 * 1024 * 1024
	maxFirmwareImageDefault = 256 * 1024 * 1024
)

type Status string

const (
	PASS    Status = "PASS"
	WARN    Status = "WARN"
	FAIL    Status = "FAIL"
	UNKNOWN Status = "UNKNOWN"
	NA      Status = "NOT_APPLICABLE"
)

type Finding struct {
	ID           string `json:"id"`
	Check        string `json:"check,omitempty"`
	ObservedAt   string `json:"observed_at,omitempty"`
	Method       string `json:"method,omitempty"`
	EvidenceHash string `json:"evidence_hash,omitempty"`
	Category     string `json:"category"`
	Title        string `json:"title"`
	Status       Status `json:"status"`
	Severity     string `json:"severity,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
	Source       string `json:"source,omitempty"`
}

type SignatureMatch struct {
	Rule, File string
	Offset     int64
	Evidence   string
}

type FirmwareSectionReport struct {
	Offset        uint64 `json:"offset"`
	Size          uint64 `json:"size"`
	HeaderSize    uint64 `json:"header_size"`
	PayloadOffset uint64 `json:"payload_offset"`
	Type          uint8  `json:"type"`
	TypeName      string `json:"type_name"`
	PECOFF        bool   `json:"pe_coff"`
	GUID          string `json:"guid,omitempty"`
	Text          string `json:"text,omitempty"`
	SHA512        string `json:"sha512"`
}

type FirmwareFileReport struct {
	Offset         uint64                  `json:"offset"`
	Size           uint64                  `json:"size"`
	HeaderSize     uint64                  `json:"header_size"`
	NameGUID       string                  `json:"name_guid"`
	Type           uint8                   `json:"type"`
	TypeName       string                  `json:"type_name"`
	ExecutionClass string                  `json:"execution_class"`
	Attributes     uint8                   `json:"attributes"`
	State          uint8                   `json:"state"`
	Name           string                  `json:"name,omitempty"`
	HeaderChecksum bool                    `json:"header_checksum_valid"`
	DataChecksum   bool                    `json:"data_checksum_valid"`
	SHA512         string                  `json:"sha512"`
	Sections       []FirmwareSectionReport `json:"sections,omitempty"`
}

type FirmwareVolumeReport struct {
	Offset              uint64               `json:"offset"`
	Length              uint64               `json:"length"`
	HeaderLength        uint16               `json:"header_length"`
	FilesystemGUID      string               `json:"filesystem_guid"`
	Revision            uint8                `json:"revision"`
	Attributes          uint32               `json:"attributes"`
	HeaderChecksumValid bool                 `json:"header_checksum_valid"`
	FileAreaAligned     bool                 `json:"file_area_aligned"`
	Files               int                  `json:"files"`
	PEIFiles            int                  `json:"pei_files"`
	DXEFiles            int                  `json:"dxe_files"`
	SMMFiles            int                  `json:"smm_files"`
	RawFiles            int                  `json:"raw_files"`
	SectionCount        int                  `json:"section_count"`
	SectionTypes        map[string]int       `json:"section_types,omitempty"`
	FFSTypes            map[string]int       `json:"ffs_types,omitempty"`
	FilesDetail         []FirmwareFileReport `json:"files_detail,omitempty"`
}

type FirmwareImageEvidence struct {
	Source          string `json:"source"`
	Path            string `json:"path,omitempty"`
	Size            int64  `json:"size"`
	SHA512          string `json:"sha512"`
	FirmwareVolumes int    `json:"firmware_volumes"`
	Parser          string `json:"parser"`
}

type ThreatHit struct {
	Mode       string `json:"mode"`
	Kind       string `json:"kind"`
	Family     string `json:"family,omitempty"`
	Technique  string `json:"technique,omitempty"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Location   string `json:"location"`
	Offset     int64  `json:"offset,omitempty"`
	Indicator  string `json:"indicator"`
	Context    string `json:"context,omitempty"`
	Method     string `json:"method"`
	Reference  string `json:"reference,omitempty"`
}

type ThreatScanReport struct {
	Enabled               bool                `json:"enabled"`
	Coverage              string              `json:"coverage"`
	Profile               string              `json:"profile"`
	Targets               int                 `json:"targets"`
	Artifacts             int                 `json:"artifacts"`
	UniqueArtifacts       int                 `json:"unique_artifacts"`
	FirmwareModules       int                 `json:"firmware_modules"`
	NestedFirmwareVolumes int                 `json:"nested_firmware_volumes"`
	SignatureVerified     int                 `json:"signature_verified"`
	SignatureInvalid      int                 `json:"signature_invalid"`
	SignatureUnknown      int                 `json:"signature_unknown"`
	ModuleAnomalies       int                 `json:"module_anomalies"`
	Indicators            int                 `json:"indicators"`
	HighConfidence        int                 `json:"high_confidence"`
	YARAMatches           int                 `json:"yara_matches"`
	StructuralHits        int                 `json:"structural_hits"`
	StringHits            int                 `json:"string_hits"`
	FamilyHits            map[string]int      `json:"family_hits,omitempty"`
	TechniqueHits         map[string]int      `json:"technique_hits,omitempty"`
	CoverageGaps          []string            `json:"coverage_gaps,omitempty"`
	Hits                  []ThreatHit         `json:"hits,omitempty"`
	seen                  map[string]struct{} `json:"-"`
	seenArtifacts         map[string]struct{} `json:"-"`
}

type Summary struct {
	Pass, Warn, Fail, Unknown, NA int
	Score                         float64
	Assessment                    string
}

type Report struct {
	Schema          string                 `json:"schema"`
	Scanner         string                 `json:"scanner"`
	Version         string                 `json:"version"`
	Timestamp       string                 `json:"timestamp"`
	Hostname        string                 `json:"hostname,omitempty"`
	OS              string                 `json:"os"`
	Arch            string                 `json:"arch"`
	Root            bool                   `json:"root"`
	Dependencies    map[string]string      `json:"dependencies"`
	Findings        []Finding              `json:"findings"`
	Matches         []SignatureMatch       `json:"matches,omitempty"`
	FirmwareImage   *FirmwareImageEvidence `json:"firmware_image,omitempty"`
	FirmwareVolumes []FirmwareVolumeReport `json:"firmware_volumes,omitempty"`
	MalwareScan     *ThreatScanReport      `json:"malware_scan,omitempty"`
	SpywareScan     *ThreatScanReport      `json:"spyware_scan,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
	Summary         Summary                `json:"summary"`
	Verbose         int                    `json:"verbose"`
	ForensicsLevel  int                    `json:"forensics_level"`
	LogDirectory    string                 `json:"log_directory,omitempty"`
	IDSequence      map[string]int         `json:"-"`
}

type Config struct {
	OutputDir, YaraDir, Baseline, Scan, Only, Exclude, LogDir, FirmwareImage string
	MaxFile                                                                  int64
	MaxFirmwareImage                                                         int64
	CommandTimeout                                                           time.Duration
	UseFlashrom, NoColor                                                     bool
	Verbose                                                                  int
	Forensics                                                                int
	UpdateYARA, LegacyForensic                                               bool
	Malware, Spyware                                                         bool
}

var logFile *os.File
var logMu sync.Mutex

var cfg Config
var currentReport *Report
var runtimeFirmwareImage string
var checks = map[string]func(*Report){
	"dependencies": checkDependencies, "platform": checkPlatform, "secureboot": checkSecureBoot, "tpm": checkTPM,
	"measuredboot": checkMeasuredBoot, "spilock": checkSPILock, "virtualization": checkVirtualization, "nvram": checkNVRAM,
	"firmware-sources": checkFirmwareSources, "bootchain": checkBootChain, "kernel-integrity": checkKernelIntegrity,
	"persistence": checkPersistence, "modules": checkModules, "processes": checkProcesses, "initramfs": checkInitramfs,
	"bootentries": checkBootEntries, "security-controls": checkSecurityControls, "efi-attributes": checkEFIAttributes,
	"ima": checkIMA, "mounts": checkMounts, "updates": checkUpdates, "kernel-posture": checkKernelPosture,
	"kernel-config": checkKernelConfig, "fs-integrity": checkFSIntegrity, "evidence": checkEvidence, "efi-content": checkEFIContent,
	"cve-indicators": checkCVEIndicators, "baseline": checkBaseline,
	"forensic-yara": checkForensicYARA, "firmware-forensics": checkFirmwareForensics,
	"vuln-knowledge": checkVulnerabilityKnowledgeBase, "deep-forensics": checkDeepForensics,
	"secureboot-policy": checkSecureBootPolicy, "efi-var-integrity": checkEFIVariableIntegrity,
	"boot-security": checkBootSecurity, "fwupd-security": checkFWUPDSecurity,
	"iommu": checkIOMMU, "kernel-lockdown": checkKernelLockdown,
	"kernel-taint": checkKernelTaint, "kernel-cmdline": checkKernelCommandLine,
	"kexec": checkKexecProtection, "tpm-eventlog": checkTPMEventLog,
	"acpi-integrity": checkACPIIntegrity, "firmware-update-path": checkFirmwareUpdatePath,
	"efi-mount": checkEFIMount, "debug-surfaces": checkDebugSurfaces, "module-signatures": checkModuleSignatures,
	"verity": checkVerity, "sbat": checkSBAT, "platform-management": checkPlatformManagement, "tpm-pcr7": checkTPMPCR7,
	"firmware-capsules": checkFirmwareCapsules, "secureboot-keys": checkSecureBootKeys,
	"tpm-deep": checkTPMDeepInspection, "smm-security": checkSMMExposure, "dxe-integrity": checkDXEIntegrity,
	"nvram-forensics": checkNVRAMForensics, "hardware-rot": checkHardwareRootOfTrust,
	"uefi-shell": checkUEFIShellAndEFIApps, "pci-option-rom": checkPCIOptionROMs,
	"virtualization-escape":  checkVirtualizationEscapeIndicators,
	"firmware-volume-parser": checkFirmwareVolumeParser,
	"malware-scan":           checkMalwareScan, "spyware-scan": checkSpywareScan,
	"threat-intel-2026": check2026MalwareThreatIntel, "spyware-intel-2026": check2026SpywareThreatIntel,
	"anti-rollback": checkAntiRollback, "side-channels": checkSideChannelMitigations,
	"microcode": checkMicrocodePosture, "capsule-results": checkCapsuleResults,
}

func main() {
	flag.StringVar(&cfg.OutputDir, "out", "./uefiscan-report", "report directory")
	flag.StringVar(&cfg.YaraDir, "yara", "", "directory containing YARA rules")
	flag.StringVar(&cfg.Baseline, "baseline", "", "trusted baseline JSON produced by this scanner")
	flag.Int64Var(&cfg.MaxFile, "max-file", maxRead, "maximum file size to inspect")
	flag.DurationVar(&cfg.CommandTimeout, "timeout", 20*time.Second, "maximum duration for a single external command")
	flag.BoolVar(&cfg.UseFlashrom, "flashrom", false, "use flashrom read-only probing/acquisition when available")
	flag.StringVar(&cfg.Scan, "scan", "all", "all, quick, deep, firmware, host, integrity, malware, spyware, or comma-separated checks")
	flag.IntVar(&cfg.Verbose, "verbose", 1, "terminal verbosity 0-3")
	flag.IntVar(&cfg.Forensics, "forensics", 3, "forensic depth 1-5")
	flag.StringVar(&cfg.LogDir, "log", "", "optional log directory; empty disables file logging")
	flag.StringVar(&cfg.FirmwareImage, "firmware-image", "", "read-only firmware/SPI image to parse into FV/FFS/section evidence")
	flag.Int64Var(&cfg.MaxFirmwareImage, "max-firmware-image", maxFirmwareImageDefault, "maximum firmware image size to load for FV/FFS parsing")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "disable terminal colors")
	flag.StringVar(&cfg.Only, "only", "", "comma-separated finding IDs to display in terminal")
	flag.StringVar(&cfg.Exclude, "exclude", "", "comma-separated check names to exclude")
	flag.BoolVar(&cfg.UpdateYARA, "update-yara", false, "download the configured defensive YARA rule set")
	flag.BoolVar(&cfg.LegacyForensic, "legacy-forensic", true, "retain compatibility forensic/YARA/firmware evidence checks")
	flag.BoolVar(&cfg.Malware, "malware", false, "run the read-only EFI/firmware malware detection pipeline")
	flag.BoolVar(&cfg.Spyware, "spyware", false, "run the read-only EFI/firmware spyware detection pipeline")
	list := flag.Bool("list-checks", false, "list available checks")
	flag.Parse()
	if *list {
		listChecks()
		return
	}
	if cfg.Verbose < 0 || cfg.Verbose > 3 {
		fmt.Fprintln(os.Stderr, "--verbose must be 0, 1, 2, or 3")
		os.Exit(2)
	}
	if cfg.Forensics < 1 || cfg.Forensics > 5 {
		fmt.Fprintln(os.Stderr, "--forensics must be between 1 and 5")
		os.Exit(2)
	}
	if cfg.MaxFile <= 0 {
		fmt.Fprintln(os.Stderr, "--max-file must be greater than zero")
		os.Exit(2)
	}
	if cfg.MaxFirmwareImage <= 0 {
		fmt.Fprintln(os.Stderr, "--max-firmware-image must be greater than zero")
		os.Exit(2)
	}
	if cfg.CommandTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "--timeout must be greater than zero")
		os.Exit(2)
	}
	if err := initLog(); err != nil {
		fmt.Fprintf(os.Stderr, "log initialization failed: %v\n", err)
		os.Exit(2)
	}
	defer closeLog()

	printHeader()
	logf(1, "start version=%s scan=%s verbose=%d forensics=%d flashrom=%t malware=%t spyware=%t", version, cfg.Scan, cfg.Verbose, cfg.Forensics, cfg.UseFlashrom, cfg.Malware, cfg.Spyware)

	host, _ := os.Hostname()
	r := &Report{Schema: "sl0ppy-UEFIScan/v1.4.1", Scanner: "sl0ppy-UEFIScan", Version: version, Timestamp: time.Now().UTC().Format(time.RFC3339), Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Root: os.Geteuid() == 0, Dependencies: map[string]string{}, IDSequence: map[string]int{}, Verbose: cfg.Verbose, ForensicsLevel: cfg.Forensics, LogDirectory: cfg.LogDir}
	add(r, "CORE-002", "core", "Forensic assessment profile", PASS, "info", "high", fmt.Sprintf("forensics level %d/5: %s; terminal verbosity %d/3", cfg.Forensics, forensicLevelName(cfg.Forensics), cfg.Verbose), "increase --forensics when deeper artifact collection is required; use --verbose for more terminal detail", "configuration")
	if !r.Root {
		add(r, "CORE-001", "core", "Scanner privileges", WARN, "medium", "high", "running without root; firmware variables and integrity interfaces may be incomplete", "run as root for the deepest read-only assessment", "process EUID")
	}

	if cfg.UpdateYARA {
		if sources, err := updateDefensiveYARARules(); err != nil {
			add(r, "YARA-UPD-001", "yara", "Defensive YARA rule update", UNKNOWN, "medium", "medium", err.Error(), "verify network access and trusted rule sources", "YARA update")
		} else {
			add(r, "YARA-UPD-001", "yara", "Defensive YARA rule update", PASS, "info", "high", strings.Join(sources, ", "), "none", "YARA update")
		}
	}

	// Explicit threat group aliases are equivalent to the dedicated flags.
	for _, group := range strings.Split(cfg.Scan, ",") {
		switch strings.TrimSpace(group) {
		case "malware":
			cfg.Malware = true
		case "spyware":
			cfg.Spyware = true
		}
	}
	selected := selectChecks(cfg.Scan)
	if cfg.Malware || cfg.Spyware {
		overlap := map[string]bool{"forensic-yara": true, "firmware-forensics": true, "firmware-volume-parser": true, "dxe-integrity": true, "nvram-forensics": true, "uefi-shell": true, "efi-content": true}
		filtered := selected[:0]
		for _, name := range selected {
			if !overlap[name] {
				filtered = append(filtered, name)
			}
		}
		selected = filtered
	}
	if cfg.Malware {
		selected = appendUnique(selected, "malware-scan")
		selected = appendUnique(selected, "threat-intel-2026")
	}
	if cfg.Spyware {
		selected = appendUnique(selected, "spyware-scan")
		selected = appendUnique(selected, "spyware-intel-2026")
	}
	if (cfg.Malware || cfg.Spyware) && (strings.TrimSpace(cfg.FirmwareImage) != "" || cfg.UseFlashrom) {
		selected = appendUnique(selected, "firmware-volume-parser")
		selected = appendUnique(selected, "firmware-forensics")
	}
	sort.Strings(selected)
	runCount := 0
	skipCount := 0
	for _, name := range selected {
		if excluded(name) {
			logf(2, "skip excluded check=%s", name)
			skipCount++
			continue
		}
		minLevel := forensicLevelForCheck(name)
		if minLevel > 0 && cfg.Forensics < minLevel {
			if cfg.Verbose >= 2 {
				fmt.Printf("  %s %-24s %s\n", dim("↳"), name, dim(fmt.Sprintf("skipped at forensics %d/5; requires %d/5", cfg.Forensics, minLevel)))
			}
			logf(2, "skip forensic-depth check=%s required=%d current=%d", name, minLevel, cfg.Forensics)
			skipCount++
			continue
		}
		before := len(r.Findings)
		if fn, ok := checks[name]; ok {
			runCount++
			start := time.Now()
			if cfg.Verbose >= 1 {
				fmt.Printf("  %s %-24s", cyan("•"), name)
			}
			fn(r)
			elapsed := time.Since(start).Round(time.Millisecond)
			added := len(r.Findings) - before
			if cfg.Verbose >= 1 {
				fmt.Printf(" %s  %d finding%s  (%s)\n", green("✓"), added, plural(added), elapsed)
			}
			logf(1, "check=%s findings=%d duration=%s", name, added, elapsed)
		}
	}
	logf(1, "checks completed=%d skipped=%d findings=%d matches=%d", runCount, skipCount, len(r.Findings), len(r.Matches))
	buildSummary(r)
	addRecommendations(r)
	if err := writeReports(r, cfg.OutputDir); err != nil {
		fmt.Printf("%s report write error: %v\n", red("[!]"), err)
		logf(1, "report write error: %v", err)
	}
	if cfg.Verbose >= 2 {
		printAllFindings(r)
	}
	currentReport = r
	printImpactOverview(r)
	printThreatScanDetails(r)
	printSummary(r.Summary)
	if runtimeFirmwareImage != "" {
		_ = os.Remove(runtimeFirmwareImage)
		runtimeFirmwareImage = ""
	}
	logf(1, "complete score=%.2f assessment=%s", r.Summary.Score, r.Summary.Assessment)
}

func printHeader() {
	fmt.Println(cyan("╔══════════════════════════════════════════════════════════════╗"))
	fmt.Printf("%s\n", cyan(fmt.Sprintf("║ %-60s ║", "sl0ppy-UEFIScan v"+version+" | x0xr00t")))
	fmt.Printf("%s\n", dim(fmt.Sprintf("║ %-60s ║", "Defensive UEFI / firmware security assessment")))
	fmt.Printf("%s\n", dim(fmt.Sprintf("║ %-60s ║", "Read-only • evidence-first • no firmware/NVRAM writes")))
	fmt.Printf("%s\n", dim(fmt.Sprintf("║ %-60s ║", "Unknown means insufficient evidence, not compromise")))
	fmt.Println(cyan("╚══════════════════════════════════════════════════════════════╝"))
	fmt.Printf("  Forensics: %s  |  Verbose: %s  |  Malware: %s  |  Spyware: %s  |  Log: %s\n", severityLabel(fmt.Sprintf("%d/5 %s", cfg.Forensics, forensicLevelName(cfg.Forensics))), severityLabel(fmt.Sprintf("%d/3", cfg.Verbose)), boolLabel(cfg.Malware), boolLabel(cfg.Spyware), logLabel())
}

func listChecks() {
	names := make([]string, 0, len(checks))
	for n := range checks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Println(n)
	}
}
func selectChecks(s string) []string {
	if s == "all" || s == "" {
		n := make([]string, 0, len(checks))
		for k := range checks {
			// Threat hunting is opt-in. Normal/all assessments retain the full
			// security posture pipeline without running malware/spyware scanning.
			if k == "malware-scan" || k == "spyware-scan" || k == "threat-intel-2026" || k == "spyware-intel-2026" {
				continue
			}
			n = append(n, k)
		}
		sort.Strings(n)
		return n
	}
	groups := map[string][]string{"quick": {"platform", "secureboot", "secureboot-policy", "tpm", "bootchain", "boot-security", "kernel-integrity", "kernel-lockdown", "security-controls", "evidence"}, "malware": {"malware-scan", "threat-intel-2026"}, "spyware": {"spyware-scan", "spyware-intel-2026"}, "deep": {"all"}, "firmware": {"platform", "secureboot", "secureboot-policy", "secureboot-keys", "sbat", "tpm", "tpm-deep", "tpm-pcr7", "measuredboot", "tpm-eventlog", "spilock", "nvram", "nvram-forensics", "efi-var-integrity", "efi-mount", "firmware-sources", "firmware-update-path", "fwupd-security", "platform-management", "hardware-rot", "firmware-capsules", "capsule-results", "anti-rollback", "bootchain", "boot-security", "bootentries", "efi-attributes", "efi-content", "dxe-integrity", "uefi-shell", "pci-option-rom", "firmware-volume-parser", "baseline", "acpi-integrity"}, "host": {"platform", "processes", "modules", "module-signatures", "persistence", "initramfs", "mounts", "kernel-integrity", "kernel-posture", "kernel-config", "kernel-lockdown", "kernel-taint", "kernel-cmdline", "kexec", "iommu", "verity", "side-channels", "microcode", "virtualization-escape", "security-controls", "debug-surfaces", "updates"}, "integrity": {"secureboot", "secureboot-policy", "secureboot-keys", "sbat", "tpm", "tpm-deep", "tpm-pcr7", "measuredboot", "tpm-eventlog", "kernel-integrity", "kernel-lockdown", "kernel-taint", "kernel-cmdline", "kexec", "ima", "verity", "side-channels", "microcode", "fs-integrity", "initramfs", "bootentries", "efi-content", "efi-var-integrity", "dxe-integrity", "uefi-shell", "anti-rollback", "firmware-volume-parser", "baseline"}}
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		xs := groups[p]
		if p == "deep" {
			xs = nil
			for k := range checks {
				if k == "malware-scan" || k == "spyware-scan" || k == "threat-intel-2026" || k == "spyware-intel-2026" {
					continue
				}
				xs = append(xs, k)
			}
		} else if len(xs) == 0 {
			xs = []string{p}
		}
		for _, x := range xs {
			if !seen[x] && x != "all" {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	sort.Strings(out)
	return out
}
func appendUnique(items []string, value string) []string {
	for _, x := range items {
		if x == value {
			return items
		}
	}
	return append(items, value)
}

func boolLabel(v bool) string {
	if v {
		return green("ON")
	}
	return dim("OFF")
}

func excluded(name string) bool {
	for _, x := range strings.Split(cfg.Exclude, ",") {
		if strings.TrimSpace(x) == name {
			return true
		}
	}
	return false
}

func add(r *Report, id, cat, title string, status Status, severity, confidence, evidence, remediation, source string) {
	if r.IDSequence == nil {
		r.IDSequence = map[string]int{}
	}
	base := id
	r.IDSequence[base]++
	if r.IDSequence[base] > 1 {
		id = fmt.Sprintf("%s-%d", base, r.IDSequence[base])
	}
	severity = normalizeSeverity(severity)
	f := Finding{
		ID: id, Check: cat, Category: cat, Title: title, Status: status,
		Severity: severity, Confidence: strings.ToLower(confidence), Evidence: evidence,
		Remediation: remediation, Source: source,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Method:     source,
	}
	if strings.TrimSpace(evidence) != "" {
		h := sha512.Sum512([]byte(normalizeEvidence(evidence)))
		f.EvidenceHash = hex.EncodeToString(h[:])
	}
	r.Findings = append(r.Findings, f)
	logf(2, "finding id=%s status=%s severity=%s confidence=%s title=%s evidence=%s remediation=%s", id, status, severity, confidence, title, oneLine(evidence, 500), oneLine(remediation, 500))
	if cfg.Verbose >= 2 {
		printFindingCompact(f, cfg.Verbose >= 3)
	}
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.CommandTimeout)
	defer cancel()
	logf(3, "exec %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	errText := strings.TrimSpace(stderr.String())
	if ctx.Err() != nil {
		result := truncate(out+" "+errText, 5000)
		logf(3, "exec timeout %s output=%s", name, oneLine(result, 1200))
		return result, fmt.Errorf("command timeout: %w", ctx.Err())
	}
	if err != nil {
		if errText != "" {
			if out != "" {
				out += "\n"
			}
			out += errText
		}
		logf(3, "exec failed %s err=%v output=%s", name, err, oneLine(out, 1200))
		return truncate(out, 5000), err
	}
	logf(3, "exec ok %s output=%s", name, oneLine(out, 1200))
	return out, nil
}

func exists(p string) bool { _, e := os.Stat(p); return e == nil }
func readText(p string, max int64) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if max <= 0 {
		max = maxRead
	}
	lr := io.LimitReader(f, max+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return "", err
	}
	if int64(len(b)) > max {
		return string(b[:max]), fmt.Errorf("truncated")
	}
	return string(b), nil
}
func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 128*1024)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashBytes(b []byte) string {
	h := sha512.Sum512(b)
	return hex.EncodeToString(h[:])
}
func checkDependencies(r *Report) {
	cmds := []string{"efibootmgr", "mokutil", "fwupdmgr", "tpm2_getcap", "tpm2_pcrread", "flashrom", "dmidecode", "yara", "lsblk", "findmnt", "aa-status", "sestatus", "getenforce"}
	for _, c := range cmds {
		p, e := exec.LookPath(c)
		if e == nil {
			r.Dependencies[c] = p
		} else {
			r.Dependencies[c] = "missing"
		}
	}
	present := 0
	for _, v := range r.Dependencies {
		if v != "missing" {
			present++
		}
	}
	status := PASS
	if present < 3 {
		status = WARN
	}
	add(r, "DEP-001", "dependencies", "Security tooling inventory", status, "low", "high", fmt.Sprintf("%d/%d optional security utilities available; missing tools do not imply compromise", present, len(cmds)), "install only the tools needed for the checks you intend to run; rerun for deeper evidence", "PATH lookup")
}
func checkPlatform(r *Report) {
	efi := exists("/sys/firmware/efi") || exists("/sys/firmware/efi/efivars")
	if efi {
		add(r, "PLAT-001", "platform", "UEFI runtime interface", PASS, "info", "high", "/sys/firmware/efi is present", "none", "/sys/firmware/efi")
	} else {
		add(r, "PLAT-001", "platform", "UEFI runtime interface", UNKNOWN, "medium", "high", "UEFI runtime interface not visible", "verify firmware boot mode and kernel EFI support", "/sys/firmware/efi")
	}
}

func checkSecureBoot(r *Report) {
	if out, e := run("mokutil", "--sb-state"); e == nil {
		low := strings.ToLower(out)
		if strings.Contains(low, "enabled") {
			add(r, "SB-001", "secureboot", "Secure Boot enabled", PASS, "high", "high", out, "none", "mokutil --sb-state")
		} else if strings.Contains(low, "disabled") {
			add(r, "SB-001", "secureboot", "Secure Boot enabled", WARN, "high", "high", out+"; disabled is a control-state finding, not proof of compromise", "enable Secure Boot after validating signed boot components when required by the platform policy", "mokutil --sb-state")
		} else {
			add(r, "SB-001", "secureboot", "Secure Boot state", UNKNOWN, "high", "medium", out, "verify Secure Boot state in firmware UI", "mokutil")
		}
		return
	}
	b, e := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if e != nil {
		add(r, "SB-001", "secureboot", "Secure Boot state", UNKNOWN, "high", "medium", "SecureBoot EFI variable unavailable", "verify firmware state with vendor tooling", "efivarfs")
		return
	}
	if len(b) > 4 && b[4] == 1 {
		add(r, "SB-001", "secureboot", "Secure Boot enabled", PASS, "high", "high", "SecureBoot variable value is 1", "none", "efivarfs")
	} else {
		add(r, "SB-001", "secureboot", "Secure Boot enabled", WARN, "high", "high", "SecureBoot variable value is not 1; disabled is not proof of compromise", "enable Secure Boot when required by the platform policy", "efivarfs")
	}
}

func checkTPM(r *Report) {
	found := false
	for _, p := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if exists(p) {
			found = true
		}
	}
	if !found {
		add(r, "TPM-001", "tpm", "TPM device present", UNKNOWN, "high", "high", "no TPM character device detected", "verify TPM/firmware security configuration", "/dev/tpm*")
		return
	}
	if out, e := run("tpm2_getcap", "properties-fixed"); e == nil {
		add(r, "TPM-001", "tpm", "TPM device present", PASS, "high", "high", truncate(out, 800), "none", "tpm2_getcap")
		add(r, "TPM-002", "tpm", "TPM properties readable", PASS, "medium", "high", "tpm2_getcap properties-fixed succeeded", "none", "tpm2_getcap")
	} else {
		add(r, "TPM-001", "tpm", "TPM device present", PASS, "high", "high", "TPM device node present", "none", "/dev/tpm*")
		add(r, "TPM-002", "tpm", "TPM properties readable", UNKNOWN, "medium", "medium", "TPM exists but tpm2_getcap failed", "install/configure tpm2-tools and retry", "tpm2_getcap")
	}
}

func checkMeasuredBoot(r *Report) {
	p := "/sys/kernel/security/ima/ascii_runtime_measurements"
	if !exists(p) {
		add(r, "MB-001", "measuredboot", "IMA runtime measurements", UNKNOWN, "high", "high", "IMA measurement interface unavailable", "enable IMA if your platform supports measured boot", "securityfs")
		return
	}
	s, e := readText(p, 4*1024*1024)
	if e != nil {
		add(r, "MB-001", "measuredboot", "IMA runtime measurements", UNKNOWN, "high", "medium", e.Error(), "run with appropriate privileges", "IMA")
		return
	}
	lines := strings.Count(s, "\n")
	if lines > 0 {
		add(r, "MB-001", "measuredboot", "IMA runtime measurements", PASS, "medium", "high", fmt.Sprintf("%d measurement records readable", lines), "none", "IMA runtime measurements")
	} else {
		add(r, "MB-001", "measuredboot", "IMA runtime measurements", WARN, "medium", "high", "IMA interface exists but contains no readable records", "review IMA policy and boot configuration", "IMA runtime measurements")
	}
	if out, e := run("tpm2_pcrread"); e == nil {
		add(r, "MB-002", "measuredboot", "TPM PCR values readable", PASS, "high", "high", truncate(out, 1200), "none", "tpm2_pcrread")
	} else {
		add(r, "MB-002", "measuredboot", "TPM PCR values readable", UNKNOWN, "high", "medium", "tpm2_pcrread failed", "verify TPM tools and access", "tpm2_pcrread")
	}
}

func checkSPILock(r *Report) {
	if !cfg.UseFlashrom {
		add(r, "SPI-000", "spilock", "SPI write-protection check", NA, "medium", "high", "flashrom check disabled by default", "rerun with -flashrom for read-only --wp-status probing", "configuration")
		return
	}
	if _, e := exec.LookPath("flashrom"); e != nil {
		add(r, "SPI-001", "spilock", "SPI write protection", UNKNOWN, "high", "high", "flashrom is not installed", "install flashrom and rerun -flashrom", "PATH")
		return
	}
	out, e := run("flashrom", "--wp-status")
	if e != nil {
		add(r, "SPI-001", "spilock", "SPI write protection", UNKNOWN, "high", "medium", truncate(out, 1200), "verify SPI protection using vendor tooling or flashrom on supported hardware", "flashrom --wp-status")
		return
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "write protection is enabled") || strings.Contains(low, "wp enabled") {
		add(r, "SPI-001", "spilock", "SPI write protection", PASS, "high", "high", truncate(out, 1200), "none", "flashrom --wp-status")
	} else {
		add(r, "SPI-001", "spilock", "SPI write protection", WARN, "high", "high", truncate(out, 1200), "review BIOS/SPI write-protection controls", "flashrom --wp-status")
	}
}

func checkVirtualization(r *Report) {
	dmi, _ := readText("/sys/class/dmi/id/product_name", 200)
	vm := false
	for _, x := range []string{"kvm", "qemu", "vmware", "virtualbox", "microsoft corporation", "bochs", "xen"} {
		if strings.Contains(strings.ToLower(dmi), x) {
			vm = true
		}
	}
	if vm {
		add(r, "VIRT-001", "platform", "Virtualization detected", WARN, "medium", "high", strings.TrimSpace(dmi), "interpret firmware findings in the context of the hypervisor", "DMI")
	} else {
		add(r, "VIRT-001", "platform", "Virtualization detected", PASS, "info", "medium", "no common virtualization product string found", "none", "DMI")
	}
}

func checkNVRAM(r *Report) {
	dir := "/sys/firmware/efi/efivars"
	if !exists(dir) {
		add(r, "NVRAM-001", "nvram", "UEFI NVRAM inventory", UNKNOWN, "high", "high", "efivarfs unavailable", "boot in UEFI mode and mount efivarfs if appropriate", "efivarfs")
		return
	}
	// UEFI global-variable GUID is shared by SecureBoot/PK/KEK/db/dbx.
	// Boot variables use the EFI global-variable namespace with their own GUIDs.
	vars := []struct {
		name, guid string
		critical   bool
	}{
		{"SecureBoot", "8be4df61-93ca-11d2-aa0d-00e098032b8c", true},
		{"PK", "8be4df61-93ca-11d2-aa0d-00e098032b8c", true},
		{"KEK", "8be4df61-93ca-11d2-aa0d-00e098032b8c", true},
		{"db", "8be4df61-93ca-11d2-aa0d-00e098032b8c", true},
		{"dbx", "8be4df61-93ca-11d2-aa0d-00e098032b8c", true},
		{"BootOrder", "8be4df02-93ca-11d2-aa0d-00e098032b8c", false},
		{"BootCurrent", "8be4df01-93ca-11d2-aa0d-00e098032b8c", false},
		{"Timeout", "8be4df02-93ca-11d2-aa0d-00e098032b8c", false},
	}
	for _, v := range vars {
		p := filepath.Join(dir, v.name+"-"+v.guid)
		b, err := os.ReadFile(p)
		if err != nil {
			if v.name == "Timeout" {
				// Timeout is optional/platform-dependent.
				continue
			}
			add(r, "NVRAM-"+safeID(v.name), "nvram", v.name, UNKNOWN, "medium", "high", "variable unavailable; absence may be platform-specific", "verify firmware variable state and compare against the platform baseline", "efivarfs")
			continue
		}
		if len(b) <= 4 {
			add(r, "NVRAM-"+safeID(v.name), "nvram", v.name, UNKNOWN, "medium", "high", "variable exists but contains no payload", "validate variable contents with firmware tooling", "efivarfs")
			continue
		}
		if v.name == "SecureBoot" {
			state := b[4] == 1
			add(r, "NVRAM-SecureBoot", "nvram", "SecureBoot variable", func() Status {
				if state {
					return PASS
				}
				return WARN
			}(), "high", "high", fmt.Sprintf("value=%d; disabled is not proof of compromise", b[4]), "enable Secure Boot if required by the platform security baseline", "efivarfs")
			continue
		}
		add(r, "NVRAM-"+safeID(v.name), "nvram", v.name, PASS, "medium", "high", fmt.Sprintf("variable present; %d bytes including EFI attributes", len(b)), "parse EFI signature lists and compare against a trusted platform baseline", "efivarfs")
	}
}

func checkFirmwareSources(r *Report) {
	vals := map[string]string{}
	for _, k := range []string{"bios_vendor", "bios_version", "bios_date", "board_vendor", "board_name", "product_name"} {
		v, e := readText("/sys/class/dmi/id/"+k, 1024)
		if e == nil {
			vals[k] = strings.TrimSpace(v)
		}
	}
	if len(vals) < 2 {
		add(r, "FW-001", "firmware-sources", "Firmware metadata", UNKNOWN, "medium", "medium", "limited DMI firmware metadata", "verify firmware identity in vendor tooling", "/sys/class/dmi/id")
		return
	}
	parts := []string{}
	for k, v := range vals {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	add(r, "FW-001", "firmware-sources", "Firmware identity metadata", PASS, "info", "high", strings.Join(parts, "; "), "compare vendor/model/version/date against a trusted OEM baseline", "DMI sysfs")
}

func checkBootChain(r *Report) {
	cmd, _ := readText("/proc/cmdline", 8192)
	if cmd == "" {
		add(r, "BOOT-001", "bootchain", "Kernel command line", UNKNOWN, "high", "high", "/proc/cmdline unavailable", "run on a Linux host with procfs", "/proc/cmdline")
		return
	}
	suspicious := []string{}
	for _, x := range []string{"init=", "rd.break", "rd.shell", "ima_appraise=0", "module.sig_enforce=0", "lockdown=none", "enforcing=0", "selinux=0"} {
		if strings.Contains(cmd, x) {
			suspicious = append(suspicious, x)
		}
	}
	if len(suspicious) > 0 {
		add(r, "BOOT-001", "bootchain", "Suspicious boot parameters", WARN, "high", "high", strings.Join(suspicious, ", ")+" | "+cmd, "review bootloader configuration and remove unnecessary weakening parameters", "/proc/cmdline")
	} else {
		add(r, "BOOT-001", "bootchain", "Kernel command line posture", PASS, "medium", "high", cmd, "none", "/proc/cmdline")
	}
	if strings.Contains(cmd, "lsm=") {
		add(r, "BOOT-002", "bootchain", "LSM boot configuration", PASS, "medium", "high", extractToken(cmd, "lsm="), "ensure required LSMs such as lockdown/integrity/mandatory access control are present where appropriate", "/proc/cmdline")
	} else if lsm, err := readText("/sys/kernel/security/lsm", 4096); err == nil && strings.TrimSpace(lsm) != "" {
		add(r, "BOOT-002", "bootchain", "LSM boot configuration", PASS, "medium", "high", "no explicit lsm= parameter; active runtime LSM stack: "+strings.TrimSpace(lsm), "compare the active LSM stack with the organization's kernel baseline", "/sys/kernel/security/lsm")
	} else {
		add(r, "BOOT-002", "bootchain", "LSM boot configuration", UNKNOWN, "medium", "medium", "no explicit lsm= parameter and runtime LSM stack unavailable", "review /sys/kernel/security/lsm and kernel config", "/proc/cmdline + securityfs")
	}
}

func checkKernelIntegrity(r *Report) {
	l, _ := readText("/sys/kernel/security/lockdown", 1024)
	if l != "" {
		low := strings.ToLower(strings.TrimSpace(l))
		if strings.Contains(low, "[integrity]") || strings.Contains(low, "[confidentiality]") {
			add(r, "KERN-001", "kernel-integrity", "Kernel lockdown", PASS, "high", "high", strings.TrimSpace(l), "none", "/sys/kernel/security/lockdown")
		} else {
			add(r, "KERN-001", "kernel-integrity", "Kernel lockdown", WARN, "high", "high", strings.TrimSpace(l), "review lockdown policy; Secure Boot often enables lockdown on supported EFI systems", "kernel lockdown")
		}
	} else {
		add(r, "KERN-001", "kernel-integrity", "Kernel lockdown", UNKNOWN, "high", "medium", "lockdown interface unavailable", "verify CONFIG_SECURITY_LOCKDOWN_LSM and active boot mode", "kernel securityfs")
	}
	taint, _ := readText("/proc/sys/kernel/tainted", 128)
	if strings.TrimSpace(taint) == "0" {
		add(r, "KERN-002", "kernel-integrity", "Kernel taint state", PASS, "medium", "high", "kernel tainted value is 0", "none", "/proc/sys/kernel/tainted")
	} else if taint != "" {
		add(r, "KERN-002", "kernel-integrity", "Kernel taint state", WARN, "medium", "high", "kernel tainted value="+strings.TrimSpace(taint), "decode taint flags and investigate relevant causes", "/proc/sys/kernel/tainted")
	} else {
		add(r, "KERN-002", "kernel-integrity", "Kernel taint state", UNKNOWN, "medium", "medium", "taint interface unavailable", "review kernel logs/configuration", "procfs")
	}
	lsm, _ := readText("/sys/kernel/security/lsm", 4096)
	if strings.TrimSpace(lsm) != "" {
		add(r, "KERN-003", "kernel-integrity", "Active LSM stack", PASS, "medium", "high", strings.TrimSpace(lsm), "none", "/sys/kernel/security/lsm")
	} else {
		add(r, "KERN-003", "kernel-integrity", "Active LSM stack", UNKNOWN, "medium", "medium", "LSM interface unavailable", "verify securityfs and kernel configuration", "securityfs")
	}
}

func checkPersistence(r *Report) {
	paths := []string{"/etc/ld.so.preload", "/etc/profile", "/etc/profile.d", "/etc/systemd/system", "/usr/lib/systemd/system", "/etc/cron.d", "/etc/cron.daily", "/etc/rc.local"}
	for _, p := range paths {
		if !exists(p) {
			continue
		}
		if p == "/etc/ld.so.preload" {
			b, e := os.ReadFile(p)
			if e == nil && strings.TrimSpace(string(b)) != "" {
				add(r, "PERS-001", "persistence", "Dynamic linker preload entries", WARN, "high", "high", truncate(string(b), 1200), "validate every listed library and remove unauthorized preload entries", "/etc/ld.so.preload")
			} else {
				add(r, "PERS-001", "persistence", "Dynamic linker preload entries", PASS, "high", "high", "file absent or empty", "none", "/etc/ld.so.preload")
			}
		}
	}
	add(r, "PERS-002", "persistence", "Persistence locations reviewed", PASS, "medium", "medium", "checked common systemd/cron/profile locations for presence; content triage is limited", "perform file ownership/hash review for enterprise baseline validation", "filesystem")
}

func checkModules(r *Report) {
	s, e := readText("/proc/modules", 4*1024*1024)
	if e != nil {
		add(r, "MOD-001", "modules", "Loaded kernel modules", UNKNOWN, "medium", "high", e.Error(), "run with access to /proc/modules", "procfs")
		return
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	suspicious := []string{}
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) > 0 {
			n := strings.ToLower(f[0])
			for _, k := range []string{"rootkit", "hide", "hook", "lkrg"} {
				if strings.Contains(n, k) {
					suspicious = append(suspicious, n)
				}
			}
		}
	}
	if len(suspicious) > 0 {
		add(r, "MOD-001", "modules", "Loaded module name indicators", WARN, "high", "medium", strings.Join(suspicious, ", "), "verify module provenance, signature and hash against a trusted baseline", "/proc/modules")
	} else {
		add(r, "MOD-001", "modules", "Loaded kernel modules", PASS, "medium", "medium", fmt.Sprintf("%d loaded modules enumerated; no builtin name indicators", len(lines)), "validate module signatures and hashes for stronger assurance", "/proc/modules")
	}
}

func checkProcesses(r *Report) {
	ps, e := run("ps", "-eo", "pid,uid,user,comm,args", "--no-headers")
	if e != nil {
		add(r, "PROC-001", "processes", "Process inventory", UNKNOWN, "medium", "high", e.Error(), "install procps or inspect /proc", "ps")
		return
	}
	listeners, _ := run("ss", "-lntup")
	add(r, "PROC-001", "processes", "Process inventory", PASS, "info", "high", fmt.Sprintf("%d process records collected", len(strings.Split(strings.TrimSpace(ps), "\n"))), "none", "ps")
	if listeners != "" {
		add(r, "PROC-002", "processes", "Listening socket inventory", PASS, "medium", "high", truncate(listeners, 2000), "review exposed services against an approved baseline", "ss")
	} else {
		add(r, "PROC-002", "processes", "Listening socket inventory", UNKNOWN, "medium", "medium", "ss unavailable or returned no data", "review listening services manually", "ss")
	}
}

func checkInitramfs(r *Report) {
	kernel := runtimeKernel()
	patterns := []string{
		"/boot/initrd*", "/boot/initramfs*", "/boot/init*img",
		"/usr/lib/modules/" + kernel + "/init*", "/usr/lib/modules/" + kernel + "/*init*",
	}
	seen := map[string]bool{}
	var matches []string
	for _, pattern := range patterns {
		ms, _ := filepath.Glob(pattern)
		for _, p := range ms {
			if !seen[p] {
				seen[p] = true
				matches = append(matches, p)
			}
		}
	}
	if len(matches) == 0 {
		if exists("/usr/lib/modules/" + kernel) {
			add(r, "INIT-001", "initramfs", "Initramfs inventory", UNKNOWN, "medium", "medium", "no conventional initramfs filename discovered for active kernel; distribution-specific boot layout may be in use", "inspect the active bootloader entry and distribution-specific initramfs layout", "/boot + /usr/lib/modules")
		} else {
			add(r, "INIT-001", "initramfs", "Initramfs inventory", UNKNOWN, "medium", "high", "active kernel module directory unavailable", "verify kernel installation and boot layout", "/boot")
		}
		return
	}
	sort.Strings(matches)
	for _, p := range matches {
		if h, e := hashFile(p); e == nil {
			add(r, "INIT-"+safeID(filepath.Base(p)), "initramfs", "Initramfs SHA-512", PASS, "medium", "high", filepath.Base(p)+" sha512="+h, "compare hash to a trusted package/boot baseline", "filesystem hash")
		} else {
			add(r, "INIT-"+safeID(filepath.Base(p)), "initramfs", "Initramfs inventory", UNKNOWN, "medium", "medium", e.Error(), "verify permissions and boot layout", "filesystem")
		}
	}
}

func checkBootEntries(r *Report) {
	if out, e := run("efibootmgr", "-v"); e == nil {
		add(r, "BOOTENT-001", "bootentries", "UEFI boot entries", PASS, "medium", "high", truncate(out, 4000), "compare boot entries, paths and hashes against an approved baseline", "efibootmgr")
	} else {
		add(r, "BOOTENT-001", "bootentries", "UEFI boot entries", UNKNOWN, "medium", "medium", "efibootmgr unavailable or failed", "install efibootmgr and rerun", "efibootmgr")
	}
	for _, p := range []string{"/boot/efi/EFI/BOOT/BOOTX64.EFI", "/boot/efi/EFI/debian/grubx64.efi", "/boot/efi/EFI/ubuntu/shimx64.efi"} {
		if exists(p) {
			h, e := hashFile(p)
			if e == nil {
				add(r, "BOOTENT-"+safeID(filepath.Base(p)), "bootentries", "EFI binary hash", PASS, "medium", "high", p+" sha512="+h, "compare with a trusted vendor/package baseline", "filesystem hash")
			}
		}
	}
}

func checkSecurityControls(r *Report) {
	vals := map[string]string{"ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope", "unprivileged_userns_clone": "/proc/sys/kernel/unprivileged_userns_clone", "randomize_va_space": "/proc/sys/kernel/randomize_va_space"}
	for k, p := range vals {
		v, e := readText(p, 128)
		if e != nil {
			add(r, "CTRL-"+safeID(k), "security-controls", k, UNKNOWN, "medium", "high", e.Error(), "verify distribution-specific security control", "sysctl")
			continue
		}
		add(r, "CTRL-"+safeID(k), "security-controls", k, PASS, "medium", "high", strings.TrimSpace(v), "compare against organizational hardening policy", "sysctl")
	}
}

func checkEFIAttributes(r *Report) {
	dir := "/sys/firmware/efi/efivars"
	ents, e := os.ReadDir(dir)
	if e != nil {
		add(r, "ATTR-001", "efi-attributes", "EFI variable attributes", UNKNOWN, "medium", "high", e.Error(), "run in UEFI mode with efivarfs", "efivarfs")
		return
	}
	suspicious := 0
	for _, ent := range ents {
		p := filepath.Join(dir, ent.Name())
		b, e := os.ReadFile(p)
		if e != nil || len(b) < 4 {
			continue
		}
		attr := binary.LittleEndian.Uint32(b[:4])
		name := strings.ToLower(ent.Name())
		if strings.HasPrefix(name, "secureboot-") || strings.HasPrefix(name, "pk-") || strings.HasPrefix(name, "kek-") || strings.HasPrefix(name, "db-") || strings.HasPrefix(name, "dbx-") {
			if attr&1 == 0 {
				suspicious++
			}
		}
	}
	if suspicious > 0 {
		add(r, "ATTR-001", "efi-attributes", "Security-variable NVRAM attributes", WARN, "medium", "medium", fmt.Sprintf("%d security-related EFI variables lack the EFI_VARIABLE_NON_VOLATILE attribute", suspicious), "validate each variable against firmware specification and platform baseline; do not assume anomaly equals compromise", "efivarfs attributes")
	} else {
		add(r, "ATTR-001", "efi-attributes", "Security-variable NVRAM attributes", PASS, "medium", "medium", "no obvious nonvolatile-attribute anomaly detected in selected security variables", "parse EFI signature lists for stronger validation", "efivarfs")
	}
}

func checkIMA(r *Report) {
	p := "/sys/kernel/security/integrity/ima"
	if !exists(p) {
		add(r, "IMA-001", "ima", "IMA interface", UNKNOWN, "medium", "high", "IMA securityfs directory unavailable", "enable/configure IMA where required", "securityfs")
		return
	}
	pol := filepath.Join(p, "policy")
	if exists(pol) {
		b, e := os.ReadFile(pol)
		if e == nil {
			add(r, "IMA-001", "ima", "IMA policy readable", PASS, "medium", "high", truncate(string(b), 3000), "compare policy with the organization's measurement/appraisal policy", "IMA policy")
		}
	}
	m := filepath.Join(p, "ascii_runtime_measurements")
	if exists(m) {
		b, e := os.ReadFile(m)
		if e == nil {
			add(r, "IMA-002", "ima", "IMA runtime log", PASS, "medium", "high", fmt.Sprintf("%d bytes of runtime measurement data readable", len(b)), "preserve measurements for attestation/forensics", "IMA")
		}
	}
}

func checkMounts(r *Report) {
	out, e := run("findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS")
	if e != nil {
		add(r, "MNT-001", "mounts", "Mount inventory", UNKNOWN, "medium", "high", e.Error(), "install util-linux/findmnt", "findmnt")
		return
	}
	weak := []string{}
	for _, ln := range strings.Split(out, "\n") {
		low := strings.ToLower(ln)
		if strings.Contains(low, " /tmp ") && !strings.Contains(low, "nodev") {
			weak = append(weak, ln)
		}
		if strings.Contains(low, " /home ") && !strings.Contains(low, "nodev") { /* informational only */
		}
	}
	if len(weak) > 0 {
		add(r, "MNT-001", "mounts", "Mount hardening observations", WARN, "low", "medium", truncate(strings.Join(weak, "\n"), 2500), "apply nodev/nosuid/noexec where compatible with workload and policy", "findmnt")
	} else {
		add(r, "MNT-001", "mounts", "Mount inventory", PASS, "info", "high", truncate(out, 2500), "review against workload-specific policy", "findmnt")
	}
}

func checkUpdates(r *Report) {
	if out, e := run("fwupdmgr", "get-updates"); e == nil {
		if strings.Contains(strings.ToLower(out), "no updatable devices") || strings.TrimSpace(out) == "" {
			add(r, "UPD-001", "updates", "Firmware update inventory", PASS, "medium", "medium", "fwupdmgr reports no immediately available firmware updates", "keep firmware update metadata current", "fwupdmgr")
		} else {
			add(r, "UPD-001", "updates", "Firmware update inventory", WARN, "medium", "medium", truncate(out, 3000), "review available OEM firmware updates before deployment", "fwupdmgr get-updates")
		}
	} else {
		add(r, "UPD-001", "updates", "Firmware update inventory", NA, "medium", "high", "fwupdmgr unavailable or update metadata could not be queried; vendor-specific firmware tooling may be in use", "use OEM/vendor firmware tooling for authoritative update inventory", "fwupdmgr")
	}
}

func checkKernelPosture(r *Report) {
	checks := map[string]string{"ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope", "userns": "/proc/sys/kernel/unprivileged_userns_clone", "randomize_va_space": "/proc/sys/kernel/randomize_va_space"}
	for n, p := range checks {
		v, e := readText(p, 128)
		if e != nil {
			continue
		}
		v = strings.TrimSpace(v)
		status := PASS
		sev := "medium"
		if n == "ptrace_scope" && v == "0" {
			status = WARN
		}
		if n == "randomize_va_space" && v != "2" {
			status = WARN
		}
		add(r, "POST-"+safeID(n), "kernel-posture", n, status, sev, "high", v, "align with a documented enterprise kernel-hardening baseline", "sysctl")
	}
}

func checkKernelConfig(r *Report) {
	paths := []string{"/boot/config-" + runtimeKernel(), "/proc/config.gz"}
	var data string
	var src string
	for _, p := range paths {
		if strings.HasSuffix(p, ".gz") {
			if out, e := run("zcat", p); e == nil {
				data = out
				src = p
				break
			}
		} else if s, e := readText(p, 8*1024*1024); e == nil {
			data = s
			src = p
			break
		}
	}
	if data == "" {
		add(r, "KCFG-001", "kernel-config", "Kernel security configuration", UNKNOWN, "medium", "medium", "kernel configuration unavailable", "install/enable access to the running kernel config", "kernel config")
		return
	}
	wanted := []string{"CONFIG_SECURITY_LOCKDOWN_LSM=", "CONFIG_IMA=", "CONFIG_EFI=", "CONFIG_MODULE_SIG=", "CONFIG_MODULE_SIG_FORCE=", "CONFIG_BPF_UNPRIV_DEFAULT_OFF=", "CONFIG_RANDOMIZE_BASE="}
	for _, k := range wanted {
		line := findConfig(data, k)
		if line == "" {
			add(r, "KCFG-"+safeID(k), "kernel-config", k, UNKNOWN, "medium", "medium", "setting not found", "verify distribution-specific kernel configuration", "")
		} else {
			st := PASS
			if strings.HasSuffix(k, "FORCE=") && strings.Contains(line, "=y") == false {
				st = WARN
			}
			add(r, "KCFG-"+safeID(k), "kernel-config", k, st, "medium", "high", line, "compare against a hardened kernel configuration baseline", "")
		}
	}
	add(r, "KCFG-000", "kernel-config", "Kernel config source", PASS, "info", "high", src, "none", "kernel config")
}

func checkFSIntegrity(r *Report) {
	targets := []string{"/boot/vmlinuz-" + runtimeKernel(), "/boot/System.map-" + runtimeKernel()}
	found := 0
	for _, p := range targets {
		if exists(p) {
			h, e := hashFile(p)
			if e == nil {
				found++
				add(r, "FSI-"+safeID(filepath.Base(p)), "fs-integrity", "Boot artifact SHA-512", PASS, "high", "high", p+" sha512="+h, "compare with a trusted package/image baseline", "filesystem hash")
			}
		}
	}
	if found == 0 {
		add(r, "FSI-001", "fs-integrity", "Boot artifact hashes", UNKNOWN, "high", "medium", "no standard running-kernel boot artifacts found", "identify distribution-specific kernel artifacts", "filesystem")
	}
}

func checkEvidence(r *Report) {
	sources := []string{"/sys/firmware/efi", "/sys/firmware/efi/efivars", "/sys/kernel/security", "/proc/cmdline", "/proc/modules", "/proc/sys/kernel/tainted"}
	ok := 0
	for _, p := range sources {
		if exists(p) {
			ok++
		}
	}
	if ok == len(sources) {
		add(r, "EVID-001", "evidence", "Evidence collection coverage", PASS, "info", "high", fmt.Sprintf("%d/%d primary runtime evidence surfaces available", ok, len(sources)), "none", "runtime evidence inventory")
	} else {
		add(r, "EVID-001", "evidence", "Evidence collection coverage", WARN, "medium", "high", fmt.Sprintf("%d/%d primary runtime evidence surfaces available", ok, len(sources)), "treat missing evidence as an assessment limitation", "runtime evidence inventory")
	}
}

func checkEFIContent(r *Report) {
	roots := []string{"/boot/efi/EFI", "/boot/efi"}
	count := 0
	matches := 0
	indicators := []string{"lojax", "moonbounce", "blacklotus", "mosaicregressor", "finfisher", "finspy", "trickboot", "uefi rootkit", "firmware implant", "smm hook", "smm callout", "nvram tamper", "secureboot bypass", "spi flash write", "bootkit"}
	for _, root := range roots {
		if !exists(root) {
			continue
		}
		_ = filepath.Walk(root, func(p string, info fs.FileInfo, e error) error {
			if e != nil || info == nil || info.IsDir() {
				return nil
			}
			if info.Size() > cfg.MaxFile {
				return nil
			}
			data, er := os.ReadFile(p)
			if er != nil {
				return nil
			}
			count++
			low := strings.ToLower(string(data))
			for _, x := range indicators {
				if i := strings.Index(low, x); i >= 0 {
					matches++
					r.Matches = append(r.Matches, SignatureMatch{Rule: x, File: p, Offset: int64(i), Evidence: printable(string(data[max(0, i-80):min(len(data), i+len(x)+80)]))})
				}
			}
			return nil
		})
	}
	if matches > 0 {
		add(r, "EFI-001", "efi-content", "Built-in firmware-content indicators", WARN, "high", "low", fmt.Sprintf("%d heuristic indicator matches across %d EFI files", matches, count), "preserve artifacts and perform manual/vendor-assisted forensic validation; string matches alone do not prove compromise", "EFI file scan")
	} else {
		add(r, "EFI-001", "efi-content", "Built-in firmware-content indicators", PASS, "high", "medium", fmt.Sprintf("%d EFI files inspected; no builtin indicator strings matched", count), "use trusted firmware images and signature validation for stronger assurance", "EFI file scan")
	}
}

func scanYARA(r *Report, dir string) {
	if _, e := exec.LookPath("yara"); e != nil {
		add(r, "YARA-001", "efi-content", "External YARA scan", UNKNOWN, "medium", "high", "yara binary unavailable", "install a trusted YARA package and rerun with -yara", "PATH")
		return
	}
	rules := []string{}
	for _, ext := range []string{"*.yar", "*.yara"} {
		fs, _ := filepath.Glob(filepath.Join(dir, ext))
		rules = append(rules, fs...)
	}
	if len(rules) == 0 {
		add(r, "YARA-001", "efi-content", "External YARA scan", UNKNOWN, "medium", "high", "no .yar/.yara files found", "provide a trusted YARA rule directory", "-yara")
		return
	}
	targets := []string{}
	for _, t := range []string{"/boot/efi", "/sys/firmware/efi/efivars"} {
		if exists(t) {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		add(r, "YARA-001", "efi-content", "External YARA scan", NA, "medium", "high", "no readable EFI scan target is mounted", "run on a UEFI Linux host with the EFI System Partition mounted when appropriate", "filesystem")
		return
	}
	matched := 0
	ruleRuns := 0
	for _, rule := range rules {
		for _, target := range targets {
			ruleRuns++
			out, err := run("yara", "-s", "-r", rule, target)
			// YARA exit code 1 means matches; run() intentionally returns an error,
			// so non-empty stdout is the authoritative match signal here.
			lines := strings.Split(out, "\n")
			local := 0
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "warning:") {
					continue
				}
				if strings.Contains(line, ": $") || strings.Contains(line, " $") {
					matched++
					local++
					r.Matches = append(r.Matches, parseYARAMatchLine(line, rule))
				}
			}
			if local > 0 {
				continue
			}
			if err != nil && strings.TrimSpace(out) != "" && cfg.Verbose >= 3 {
				fmt.Printf("    %s YARA command: %s\n", dim("·"), oneLine(out, 500))
			}
		}
	}
	if matched > 0 {
		add(r, "YARA-001", "efi-content", "External YARA rule matches", WARN, "critical", "medium", fmt.Sprintf("%d string-level YARA matches from %d rule/target runs; matches are indicators, not proof of compromise", matched, ruleRuns), "preserve matched artifacts, verify the rule provenance, compare against trusted firmware images, and manually validate the matched rule context", "yara -s")
	} else {
		add(r, "YARA-001", "efi-content", "External YARA rule scan", PASS, "medium", "medium", fmt.Sprintf("%d rule/target runs completed with no parsed string matches", ruleRuns), "maintain trusted rule provenance and periodically refresh rules", "yara -s")
	}
}

func parseYARAMatchLine(line, ruleFile string) SignatureMatch {
	// Typical YARA -s output is approximately: rule:target: $string: 0xOFFSET: data
	parts := strings.Split(line, ":")
	m := SignatureMatch{Rule: filepath.Base(ruleFile), Evidence: printable(line)}
	if len(parts) >= 1 {
		m.Rule = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		m.File = strings.TrimSpace(parts[1])
	}
	offsetRe := regexp.MustCompile(`0x[0-9A-Fa-f]+`)
	if x := offsetRe.FindString(line); x != "" {
		m.Offset = parseHexOffset(x)
	}
	if i := strings.Index(line, "$"); i >= 0 {
		end := strings.Index(line[i:], ":")
		if end >= 0 {
			m.Rule = m.Rule + "/" + strings.TrimSpace(line[i:i+end])
		}
	}
	return m
}
func checkCVEIndicators(r *Report) {
	osrel, _ := readText("/etc/os-release", 4096)
	kern, _ := run("uname", "-r")
	vendor, _ := readText("/sys/class/dmi/id/bios_vendor", 256)
	bios, _ := readText("/sys/class/dmi/id/bios_version", 256)
	model, _ := readText("/sys/class/dmi/id/product_name", 512)
	evidence := fmt.Sprintf("os=%s | kernel=%s | bios_vendor=%s | bios_version=%s | model=%s", oneLine(osrel, 700), strings.TrimSpace(kern), strings.TrimSpace(vendor), strings.TrimSpace(bios), strings.TrimSpace(model))
	add(r, "CVE-INV-001", "cve-indicators", "CVE applicability inventory", NA, "medium", "high", truncate(evidence, 2500), "correlate exact OEM firmware/component versions with current vendor advisories; generic indicators are not sufficient to declare a CVE applicable", "local version inventory")
}
func checkBaseline(r *Report) {
	if cfg.Baseline == "" {
		add(r, "BASE-000", "baseline", "Trusted baseline comparison", NA, "high", "high", "no baseline supplied", "run a known-good reference host with -baseline output and compare it on subsequent scans", "configuration")
		return
	}
	b, e := os.ReadFile(cfg.Baseline)
	if e != nil {
		add(r, "BASE-001", "baseline", "Trusted baseline comparison", UNKNOWN, "high", "high", e.Error(), "provide a readable baseline JSON", "-baseline")
		return
	}
	var base Report
	if e = json.Unmarshal(b, &base); e != nil {
		add(r, "BASE-001", "baseline", "Trusted baseline comparison", UNKNOWN, "high", "high", e.Error(), "provide a valid sl0ppy-UEFIScan JSON report", "baseline JSON")
		return
	}
	baseMap := map[string]Finding{}
	for _, f := range base.Findings {
		baseMap[f.ID] = f
	}
	changed := 0
	statusChanged := 0
	for _, f := range r.Findings {
		if old, ok := baseMap[f.ID]; ok {
			if old.EvidenceHash != "" && f.EvidenceHash != "" {
				if old.EvidenceHash != f.EvidenceHash {
					changed++
				}
			} else if normalizeEvidence(old.Evidence) != normalizeEvidence(f.Evidence) {
				changed++
			}
			if old.Status != f.Status {
				statusChanged++
			}
		}
	}
	if changed == 0 && statusChanged == 0 {
		add(r, "BASE-001", "baseline", "Trusted baseline comparison", PASS, "high", "high", "no evidence changes detected for finding IDs shared with baseline", "none", "trusted baseline")
	} else {
		add(r, "BASE-001", "baseline", "Trusted baseline comparison", WARN, "high", "high", fmt.Sprintf("%d shared evidence records changed; %d finding statuses changed relative to baseline", changed, statusChanged), "review changed firmware, boot, kernel and security-control evidence; baseline comparison is not proof of compromise", "trusted baseline")
	}
}

func buildSummary(r *Report) {
	var s Summary
	total := 0
	for _, f := range r.Findings {
		switch f.Status {
		case PASS:
			s.Pass++
		case WARN:
			s.Warn++
		case FAIL:
			s.Fail++
		case UNKNOWN:
			s.Unknown++
		case NA:
			s.NA++
		}
		if f.Status != NA {
			total++
		}
	}
	s.Score = 0
	if total > 0 {
		weighted := float64(s.Pass) + 0.35*float64(s.Unknown) + 0.15*float64(s.Warn)
		s.Score = 100 * weighted / float64(total)
	}
	switch {
	case s.Fail > 0:
		s.Assessment = "REVIEW_REQUIRED: one or more checks reported FAIL."
	case s.Warn > 0:
		s.Assessment = "REVIEW_RECOMMENDED: warnings require contextual validation."
	case s.Unknown > 0:
		s.Assessment = "INCOMPLETE: some checks could not be verified."
	default:
		s.Assessment = "NO_ISSUES_DETECTED_BY_COMPLETED_CHECKS"
	}
	if len(r.Matches) > 0 {
		s.Assessment += " INDICATORS_FOUND_REQUIRING_MANUAL_REVIEW."
	}
	r.Summary = s
}
func addRecommendations(r *Report) {
	r.Recommendations = []string{"Interpret SCORE as an evidence-weighted posture metric, not a probability of compromise.", "Treat UNKNOWN as incomplete evidence, not as proof of compromise.", "Maintain a trusted firmware/boot-chain baseline from a known-good platform state.", "Validate Secure Boot PK/KEK/db/dbx contents as EFI signature lists rather than presence-only checks.", "Use TPM PCR measurements and IMA logs for measured-boot/remote-attestation workflows where supported.", "Correlate firmware versions and CVEs with current OEM/vendor advisories rather than generic indicators.", "Review all WARN/FAIL findings and preserve relevant artifacts before remediation."}
	if r.MalwareScan != nil {
		r.Recommendations = append(r.Recommendations, "For malware indicators, preserve the raw firmware image and exact matched module offsets before remediation; verify signatures and hashes against a trusted OEM image.")
	}
	if r.SpywareScan != nil {
		r.Recommendations = append(r.Recommendations, "For spyware indicators, correlate collection+network+persistence evidence and avoid treating generic UEFI network/runtime-service strings as proof of surveillance.")
	}
}

func printAllFindings(r *Report) {
	fmt.Println("\n" + cyan("┌─ ALL FINDINGS ───────────────────────────────────────────────┐"))
	order := []Status{FAIL, WARN, UNKNOWN, PASS, NA}
	for _, st := range order {
		items := []Finding{}
		for _, f := range r.Findings {
			if f.Status == st && selectedID(f.ID) {
				items = append(items, f)
			}
		}
		if len(items) == 0 {
			continue
		}
		fmt.Printf("%s %s %s\n", statusColor(st), strings.Repeat("─", 56), fmt.Sprintf("%d", len(items)))
		for _, f := range items {
			printFindingDetailed(f)
		}
	}
	if len(r.Matches) > 0 {
		fmt.Printf("\n%s %s\n", yellow("SIGNATURE / YARA INDICATORS"), dim(fmt.Sprintf("(%d)", len(r.Matches))))
		for _, m := range r.Matches {
			fmt.Printf("  %s %s @ %s:%d\n", yellow("MATCH"), m.Rule, m.File, m.Offset)
			if m.Evidence != "" {
				fmt.Printf("    %s %s\n", dim("↳"), oneLine(m.Evidence, 1000))
			}
		}
	}
}

func printFindingCompact(f Finding, includeEvidence bool) {
	impact := impactLevel(f.Severity)
	fmt.Printf("    %s %-11s %-8s %-8s %s | %s\n", statusColor(f.Status), f.ID, impactColor(impact), strings.ToUpper(f.Confidence), f.Category, f.Title)
	if cfg.Verbose >= 3 || includeEvidence {
		if f.Evidence != "" {
			fmt.Printf("      %s %s\n", dim("evidence:"), oneLine(f.Evidence, 900))
		}
		if f.Remediation != "" {
			fmt.Printf("      %s %s\n", dim("action:"), oneLine(f.Remediation, 900))
		}
	}
}

func printFindingDetailed(f Finding) {
	fmt.Printf("\n  %s %s  %s\n", statusColor(f.Status), f.ID, f.Title)
	fmt.Printf("    %-12s %s\n", "Category:", f.Category)
	fmt.Printf("    %-12s %s\n", "Impact:", impactColor(impactLevel(f.Severity)))
	fmt.Printf("    %-12s %s\n", "Severity:", severityColor(f.Severity))
	fmt.Printf("    %-12s %s\n", "Confidence:", strings.ToUpper(f.Confidence))
	if f.Evidence != "" {
		fmt.Printf("    %-12s %s\n", "Evidence:", oneLine(f.Evidence, 2200))
	}
	if f.Remediation != "" {
		fmt.Printf("    %-12s %s\n", "Remediate:", oneLine(f.Remediation, 2200))
	}
	if f.Source != "" {
		fmt.Printf("    %-12s %s\n", "Source:", f.Source)
	}
}

func printImpactOverview(r *Report) {
	fmt.Println("\n" + cyan("╔══════════════════════════════════════════════════════════════╗"))
	fmt.Printf("%s\n", cyan(fmt.Sprintf("║ %-60s ║", "IMPACT & REMEDIATION OVERVIEW")))
	fmt.Println(cyan("╚══════════════════════════════════════════════════════════════╝"))

	groups := map[string][]Finding{"HIGH": {}, "MEDIUM": {}, "LOW": {}, "INFO": {}, "N/A": {}}
	for _, f := range r.Findings {
		if !selectedID(f.ID) {
			continue
		}
		impact := impactLevel(f.Severity)
		if f.Status == NA {
			impact = "N/A"
		}
		groups[impact] = append(groups[impact], f)
	}
	order := []string{"HIGH", "MEDIUM", "LOW", "INFO", "N/A"}
	for _, impact := range order {
		items := groups[impact]
		if len(items) == 0 {
			continue
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Status != items[j].Status {
				return statusRank(items[i].Status) < statusRank(items[j].Status)
			}
			return items[i].ID < items[j].ID
		})
		fmt.Printf("\n%s %s\n", impactColor(impact), dim(fmt.Sprintf("(%d)", len(items))))
		fmt.Println(dim("────────────────────────────────────────────────────────────────"))
		for _, f := range items {
			fmt.Printf("%s %s %s %s\n", statusColor(f.Status), f.ID, severityColor(f.Severity), f.Title)
			if f.Evidence != "" {
				fmt.Printf("  Evidence : %s\n", oneLine(f.Evidence, 1100))
			}
			if strings.TrimSpace(f.Remediation) == "" || strings.EqualFold(strings.TrimSpace(f.Remediation), "none") {
				fmt.Printf("  Remediate: %s\n", dim("No remediation required."))
			} else {
				fmt.Printf("  Remediate: %s\n", oneLine(f.Remediation, 1400))
			}
		}
	}
	fmt.Printf("\n%s\n", dim("Impact mapping: critical/high → HIGH • medium → MEDIUM • low → LOW • info → INFO. NOT_APPLICABLE is separated because it is not an issue."))
}

func selectedID(id string) bool {
	if strings.TrimSpace(cfg.Only) == "" {
		return true
	}
	for _, x := range strings.Split(cfg.Only, ",") {
		if strings.TrimSpace(x) == id {
			return true
		}
	}
	return false
}
func printThreatScanDetails(r *Report) {
	printOne := func(title string, sr *ThreatScanReport, mode string) {
		if sr == nil || !sr.Enabled {
			return
		}
		fmt.Printf("\n%s\n", cyan("╔"+strings.Repeat("═", 76)+"╗"))
		fmt.Printf("%s\n", cyan(boxTitle(title+" • THREAT HUNT OVERVIEW", 78)))
		fmt.Printf("%s\n", cyan("╚"+strings.Repeat("═", 76)+"╝"))
		fmt.Printf("  %-24s %s\n", "Hunt profile:", sr.Profile)
		fmt.Printf("  %-24s %s\n", "Coverage:", sr.Coverage)
		fmt.Printf("  %-24s %d\n", "Targets:", sr.Targets)
		fmt.Printf("  %-24s %d\n", "Unique artifacts:", sr.UniqueArtifacts)
		fmt.Printf("  %-24s %d\n", "Firmware modules:", sr.FirmwareModules)
		fmt.Printf("  %-24s %d\n", "Nested firmware volumes:", sr.NestedFirmwareVolumes)
		fmt.Printf("  %-24s %d\n", "Module anomalies:", sr.ModuleAnomalies)
		fmt.Printf("  %-24s %d / %d / %d\n", "Module signatures (ok/bad/unknown):", sr.SignatureVerified, sr.SignatureInvalid, sr.SignatureUnknown)
		fmt.Printf("  %-24s %d\n", "Indicators:", sr.Indicators)
		fmt.Printf("  %-24s %d\n", "High-confidence:", sr.HighConfidence)
		fmt.Printf("  %-24s %d\n", "YARA matches:", sr.YARAMatches)
		fmt.Printf("  %-24s %d\n", "Structural hits:", sr.StructuralHits)
		fmt.Printf("  %-24s %d\n", "String/behavior hits:", sr.StringHits)
		fmt.Printf("\n%s\n", cyan("FAMILY / TECHNIQUE BREAKDOWN"))
		fmt.Println(strings.Repeat("─", 78))
		if len(sr.FamilyHits) == 0 {
			fmt.Printf("  %s No family-level indicators recorded.\n", green("✓"))
		} else {
			type pair struct {
				k string
				v int
			}
			ps := make([]pair, 0, len(sr.FamilyHits))
			for k, v := range sr.FamilyHits {
				ps = append(ps, pair{k, v})
			}
			sort.Slice(ps, func(i, j int) bool {
				if ps[i].v != ps[j].v {
					return ps[i].v > ps[j].v
				}
				return ps[i].k < ps[j].k
			})
			for _, x := range ps {
				fmt.Printf("  %-48s %3d\n", oneLine(x.k, 48), x.v)
			}
		}
		if len(sr.TechniqueHits) > 0 {
			fmt.Printf("\n%s\n", cyan("TOP TECHNIQUES"))
			ks := make([]string, 0, len(sr.TechniqueHits))
			for k := range sr.TechniqueHits {
				ks = append(ks, k)
			}
			sort.Slice(ks, func(i, j int) bool {
				if sr.TechniqueHits[ks[i]] != sr.TechniqueHits[ks[j]] {
					return sr.TechniqueHits[ks[i]] > sr.TechniqueHits[ks[j]]
				}
				return ks[i] < ks[j]
			})
			lim := len(ks)
			if lim > 10 {
				lim = 10
			}
			for _, k := range ks[:lim] {
				fmt.Printf("  %-60s %3d\n", oneLine(k, 60), sr.TechniqueHits[k])
			}
		}
		fmt.Printf("\n%s\n", cyan("DETAILED FINDINGS"))
		fmt.Println(strings.Repeat("─", 78))
		sorted := append([]ThreatHit(nil), sr.Hits...)
		sev := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
		sort.SliceStable(sorted, func(i, j int) bool {
			a, b := sev[strings.ToUpper(sorted[i].Severity)], sev[strings.ToUpper(sorted[j].Severity)]
			if a != b {
				return a < b
			}
			if sorted[i].Family != sorted[j].Family {
				return sorted[i].Family < sorted[j].Family
			}
			return sorted[i].Location < sorted[j].Location
		})
		lim := len(sorted)
		if cfg.Verbose < 2 && lim > 30 {
			lim = 30
		}
		if lim == 0 {
			fmt.Printf("  %s No targeted %s indicators were produced.\n", green("✓"), strings.ToLower(mode))
		}
		for i := 0; i < lim; i++ {
			h := sorted[i]
			fmt.Printf("  %s %-18s %-8s %-8s %s\n", severityColor(h.Severity), h.Kind, h.Severity, h.Confidence, oneLine(h.Indicator, 90))
			fmt.Printf("      Family    : %s\n", oneLine(h.Family, 180))
			fmt.Printf("      Technique : %s\n", oneLine(h.Technique, 180))
			fmt.Printf("      Location  : %s\n", oneLine(h.Location, 1400))
			if h.Offset >= 0 {
				fmt.Printf("      Offset    : 0x%x\n", h.Offset)
			}
			fmt.Printf("      Evidence  : %s\n", oneLine(h.Context, 1500))
			fmt.Printf("      Method    : %s\n", oneLine(h.Method, 500))
			if h.Reference != "" {
				fmt.Printf("      Reference : %s\n", oneLine(h.Reference, 700))
			}
			fmt.Printf("      Remediate : %s\n", oneLine(threatRemediation(h.Family, h.Technique), 1600))
		}
		if len(sorted) > lim {
			fmt.Printf("      %s\n", dim(fmt.Sprintf("... %d additional indicators omitted at verbosity %d; use --verbose 2/3 for full detail.", len(sorted)-lim, cfg.Verbose)))
		}
		if len(sr.CoverageGaps) > 0 {
			fmt.Printf("\n%s\n", yellow("COVERAGE LIMITATIONS"))
			for _, g := range uniqueStrings(sr.CoverageGaps) {
				fmt.Printf("  %s %s\n", yellow("!"), oneLine(g, 1400))
			}
		}
		fmt.Printf("\n%s\n", cyan("HUNT ASSESSMENT"))
		if len(sr.Hits) == 0 && len(sr.CoverageGaps) == 0 {
			fmt.Printf("  %s No targeted %s indicators were observed in the collected evidence; this is not proof of absence.\n", green("PASS"), strings.ToLower(mode))
		} else if len(sr.Hits) == 0 {
			fmt.Printf("  %s No targeted %s indicators were observed, but coverage limitations remain.\n", yellow("REVIEW"), strings.ToLower(mode))
		} else {
			fmt.Printf("  %s %d %s indicator(s) require analyst validation. Preserve the exact artifact, hash, offset and module context before remediation.\n", yellow("REVIEW"), len(sr.Hits), strings.ToLower(mode))
		}
	}
	printOne("MALWARE", r.MalwareScan, "MALWARE")
	printOne("SPYWARE", r.SpywareScan, "SPYWARE")
}

func printSummary(s Summary) {
	width := 78
	line := strings.Repeat("═", width)
	thin := strings.Repeat("─", width)

	fmt.Printf("\n%s\n", cyan("╔"+strings.Repeat("═", width-2)+"╗"))
	fmt.Printf("%s\n", cyan(boxTitle("FINAL SUMMARY & SECURITY POSTURE", width)))
	fmt.Printf("%s\n", cyan("╚"+strings.Repeat("═", width-2)+"╝"))

	applicable := s.Pass + s.Warn + s.Fail + s.Unknown
	resolved := s.Pass
	unresolved := s.Warn + s.Fail + s.Unknown
	verification := 0.0
	if applicable > 0 {
		verification = 100 * float64(resolved) / float64(applicable)
	}

	fmt.Printf("\n%s\n", cyan("STATUS BREAKDOWN"))
	fmt.Println(thin)
	printSummaryStat("PASS", s.Pass, green, applicable)
	printSummaryStat("WARN", s.Warn, yellow, applicable)
	printSummaryStat("FAIL", s.Fail, red, applicable)
	printSummaryStat("UNKNOWN", s.Unknown, cyan, applicable)
	printSummaryStat("NOT_APPLICABLE", s.NA, dim, 0)

	fmt.Printf("\n%s\n", cyan("POSTURE METRICS"))
	fmt.Println(thin)
	fmt.Printf("  %-24s %d\n", "Applicable findings:", applicable)
	fmt.Printf("  %-24s %d\n", "Verified PASS:", resolved)
	fmt.Printf("  %-24s %d\n", "Requires review:", unresolved)
	fmt.Printf("  %-24s %s\n", "Verification coverage:", fmt.Sprintf("%.2f%%", verification))
	fmt.Printf("  %-24s %s\n", "Evidence-weighted score:", scoreGrade(s.Score))
	fmt.Printf("  %-24s %s\n", "Score formula:", dim("PASS=1.00  UNKNOWN=0.35  WARN=0.15  FAIL=0.00  N/A excluded"))

	fmt.Printf("\n%s\n", cyan("IMPACT BREAKDOWN"))
	fmt.Println(thin)
	fmt.Printf("  %-10s %4d   %s\n", impactColor("HIGH"), countImpactFindings("HIGH"), dim("critical/high security effect"))
	fmt.Printf("  %-10s %4d   %s\n", impactColor("MEDIUM"), countImpactFindings("MEDIUM"), dim("security-control weakness / contextual review"))
	fmt.Printf("  %-10s %4d   %s\n", impactColor("LOW"), countImpactFindings("LOW"), dim("limited security impact / hygiene"))
	fmt.Printf("  %-10s %4d   %s\n", impactColor("INFO"), countImpactFindings("INFO"), dim("informational evidence"))
	fmt.Printf("  %-10s %4d   %s\n", impactColor("N/A"), countImpactFindings("N/A"), dim("not applicable / unavailable by design"))

	fmt.Printf("\n%s\n", cyan("ANALYST INTERPRETATION"))
	fmt.Println(thin)
	fmt.Printf("  %s\n", assessmentExplanation(s))

	fmt.Printf("\n%s\n", cyan("ACTION QUEUE"))
	fmt.Println(thin)
	if unresolved == 0 {
		fmt.Printf("  %s No WARN, FAIL, or UNKNOWN findings require follow-up.\n", green("✓"))
	} else {
		printActionQueue()
	}

	fmt.Printf("\n%s\n", cyan("EXECUTIVE RESULT"))
	fmt.Println(thin)
	fmt.Printf("  %-24s %s\n", "Assessment:", s.Assessment)
	fmt.Printf("  %-24s %s\n", "Score:", scoreGrade(s.Score))
	fmt.Printf("  %-24s %s\n", "Open review items:", statusBreakdownText(s))
	fmt.Printf("  %-24s %s\n", "Interpretation:", dim("The score is a posture metric, not a probability of compromise."))

	fmt.Printf("\n%s\n", cyan(line))
}

func boxTitle(title string, width int) string {
	inner := width - 4
	if len(title) > inner {
		title = title[:inner]
	}
	left := (inner - len(title)) / 2
	right := inner - len(title) - left
	return "║" + strings.Repeat(" ", left) + title + strings.Repeat(" ", right) + "║"
}

func printSummaryStat(label string, value int, colorFn func(string) string, denominator int) {
	pct := ""
	if denominator > 0 {
		pct = fmt.Sprintf("%6.2f%%", 100*float64(value)/float64(denominator))
	}
	fmt.Printf("  %-16s %5d  %9s\n", colorFn(label), value, pct)
}

func countImpactFindings(target string) int {
	count := 0
	for _, f := range currentReport.Findings {
		impact := impactLevel(f.Severity)
		if f.Status == NA {
			impact = "N/A"
		}
		if impact == target {
			count++
		}
	}
	return count
}

func statusBreakdownText(s Summary) string {
	parts := []string{}
	if s.Fail > 0 {
		parts = append(parts, fmt.Sprintf("%d FAIL", s.Fail))
	}
	if s.Warn > 0 {
		parts = append(parts, fmt.Sprintf("%d WARN", s.Warn))
	}
	if s.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d UNKNOWN", s.Unknown))
	}
	if len(parts) == 0 {
		return green("none")
	}
	return strings.Join(parts, ", ")
}

func scoreGrade(score float64) string {
	grade := ""
	switch {
	case score >= 95:
		grade = "EXCELLENT"
	case score >= 90:
		grade = "STRONG"
	case score >= 80:
		grade = "GOOD"
	case score >= 70:
		grade = "MODERATE"
	default:
		grade = "WEAK"
	}
	return fmt.Sprintf("%.2f%% (%s)", score, grade)
}

func assessmentExplanation(s Summary) string {
	switch {
	case s.Fail > 0:
		return red("One or more findings indicate a control failure or a high-confidence security condition requiring investigation/remediation before the host is considered clean.")
	case s.Warn > 0 && s.Unknown > 0:
		return yellow("No confirmed FAIL findings were recorded, but warnings and incomplete evidence remain. Validate the affected controls and collect missing evidence before treating the posture as fully verified.")
	case s.Warn > 0:
		return yellow("No confirmed FAIL findings were recorded, but one or more controls require contextual validation or hardening.")
	case s.Unknown > 0:
		return cyan("No confirmed FAIL/WARN findings were recorded, but some controls could not be verified. The score therefore represents incomplete evidence rather than full assurance.")
	default:
		return green("All completed applicable checks passed. Continue maintaining a trusted baseline and repeat the assessment after firmware or boot-chain changes.")
	}
}

func printActionQueue() {
	items := []Finding{}
	for _, f := range currentReport.Findings {
		if f.Status == PASS || f.Status == NA || !selectedID(f.ID) {
			continue
		}
		items = append(items, f)
	}
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := actionRank(items[i]), actionRank(items[j])
		if ri != rj {
			return ri < rj
		}
		if impactLevel(items[i].Severity) != impactLevel(items[j].Severity) {
			return impactRank(impactLevel(items[i].Severity)) < impactRank(impactLevel(items[j].Severity))
		}
		return items[i].ID < items[j].ID
	})

	limit := len(items)
	if limit > 12 && cfg.Verbose < 2 {
		limit = 12
	}
	for i := 0; i < limit; i++ {
		f := items[i]
		action := strings.TrimSpace(f.Remediation)
		if action == "" || strings.EqualFold(action, "none") {
			action = "collect additional evidence and review the finding manually"
		}
		fmt.Printf("  %2d. %s %-11s %-8s %s\n", i+1, statusColor(f.Status), f.ID, impactColor(impactLevel(f.Severity)), f.Title)
		fmt.Printf("      Evidence : %s\n", oneLine(f.Evidence, 1000))
		fmt.Printf("      Remediate: %s\n", oneLine(action, 1200))
	}
	if len(items) > limit {
		fmt.Printf("      %s\n", dim(fmt.Sprintf("... %d additional review items omitted at verbosity %d; use --verbose 2 or 3 for the full queue.", len(items)-limit, cfg.Verbose)))
	}
}

func actionRank(f Finding) int {
	switch f.Status {
	case FAIL:
		return 0
	case WARN:
		return 1
	case UNKNOWN:
		return 2
	default:
		return 9
	}
}

func impactRank(impact string) int {
	switch impact {
	case "HIGH":
		return 0
	case "MEDIUM":
		return 1
	case "LOW":
		return 2
	default:
		return 3
	}
}

func writeReports(r *Report, dir string) error {
	if e := os.MkdirAll(dir, 0750); e != nil {
		return e
	}
	stamp := time.Now().UTC().Format("20060102_150405")
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	jsonPath := filepath.Join(dir, "report_"+stamp+".json")
	if e = os.WriteFile(jsonPath, b, 0640); e != nil {
		return e
	}
	var sb strings.Builder
	sb.WriteString("sl0ppy-UEFIScan v" + version + "\n")
	fmt.Fprintf(&sb, "Host=%s OS=%s Arch=%s Root=%t Verbose=%d Forensics=%d/5\n\n", r.Hostname, r.OS, r.Arch, r.Root, r.Verbose, r.ForensicsLevel)
	for _, f := range r.Findings {
		fmt.Fprintf(&sb, "[%s] %s | %s | %s\n  Impact: %s\n  Severity: %s\n  Confidence: %s\n  Evidence: %s\n  EvidenceHash: %s\n  Action: %s\n  Source: %s\n\n", f.Status, f.ID, f.Category, f.Title, impactLevel(f.Severity), f.Severity, f.Confidence, f.Evidence, f.EvidenceHash, f.Remediation, f.Source)
	}
	sb.WriteString("IMPACT & REMEDIATION OVERVIEW\n================================\n")
	if r.FirmwareImage != nil {
		sb.WriteString("\nFIRMWARE IMAGE / FV PARSE\n==========================\n")
		fmt.Fprintf(&sb, "Source=%s\nPath=%s\nSize=%d\nSHA512=%s\nFirmwareVolumes=%d\nParser=%s\n", r.FirmwareImage.Source, r.FirmwareImage.Path, r.FirmwareImage.Size, r.FirmwareImage.SHA512, r.FirmwareImage.FirmwareVolumes, r.FirmwareImage.Parser)
		for _, v := range r.FirmwareVolumes {
			fmt.Fprintf(&sb, "FV@0x%x len=%d GUID=%s files=%d PEI=%d DXE=%d SMM/MM=%d sections=%d checksum=%t\n", v.Offset, v.Length, v.FilesystemGUID, v.Files, v.PEIFiles, v.DXEFiles, v.SMMFiles, v.SectionCount, v.HeaderChecksumValid)
		}
	}

	for _, impact := range []string{"HIGH", "MEDIUM", "LOW", "INFO", "N/A"} {
		fmt.Fprintf(&sb, "[%s]\n", impact)
		for _, f := range r.Findings {
			if (f.Status == NA && impact == "N/A") || (f.Status != NA && impactLevel(f.Severity) == impact) {
				fmt.Fprintf(&sb, "%s %s | %s | remediation=%s\n", f.Status, f.ID, f.Title, oneLine(f.Remediation, 1400))
			}
		}
	}
	sb.WriteString("\nSUMMARY\n")
	fmt.Fprintf(&sb, "PASS=%d WARN=%d FAIL=%d UNKNOWN=%d N/A=%d SCORE=%.2f\n%s\n", r.Summary.Pass, r.Summary.Warn, r.Summary.Fail, r.Summary.Unknown, r.Summary.NA, r.Summary.Score, r.Summary.Assessment)
	if err := os.WriteFile(filepath.Join(dir, "summary_"+stamp+".txt"), []byte(sb.String()), 0640); err != nil {
		return err
	}
	manifest := map[string]interface{}{
		"schema": r.Schema, "scanner": r.Scanner, "version": r.Version, "timestamp": r.Timestamp,
		"hostname": r.Hostname, "summary": r.Summary, "finding_count": len(r.Findings), "match_count": len(r.Matches),
		"firmware_volume_count": len(r.FirmwareVolumes), "firmware_image": r.FirmwareImage,
		"malware_scan": r.MalwareScan, "spyware_scan": r.SpywareScan,
		"verbose": r.Verbose, "forensics_level": r.ForensicsLevel, "log_directory": r.LogDirectory,
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest_"+stamp+".json"), mb, 0640)
}

func statusColor(s Status) string {
	switch s {
	case FAIL:
		return red(string(s))
	case WARN:
		return yellow(string(s))
	case PASS:
		return green(string(s))
	case UNKNOWN:
		return cyan(string(s))
	case NA:
		return dim(string(s))
	default:
		return dim(string(s))
	}
}
func red(s string) string {
	if cfg.NoColor {
		return s
	}
	return "\033[1;31m" + s + "\033[0m"
}
func yellow(s string) string {
	if cfg.NoColor {
		return s
	}
	return "\033[1;33m" + s + "\033[0m"
}
func green(s string) string {
	if cfg.NoColor {
		return s
	}
	return "\033[1;32m" + s + "\033[0m"
}
func cyan(s string) string {
	if cfg.NoColor {
		return s
	}
	return "\033[1;36m" + s + "\033[0m"
}
func dim(s string) string {
	if cfg.NoColor {
		return s
	}
	return "\033[2m" + s + "\033[0m"
}
func magenta(s string) string {
	if cfg.NoColor {
		return s
	}
	return "\033[1;35m" + s + "\033[0m"
}
func severityColor(s string) string {
	switch normalizeSeverity(s) {
	case "critical", "high":
		return red(strings.ToUpper(s))
	case "medium":
		return yellow(strings.ToUpper(s))
	case "low":
		return cyan(strings.ToUpper(s))
	default:
		return dim(strings.ToUpper(s))
	}
}
func impactColor(s string) string {
	switch strings.ToUpper(s) {
	case "HIGH":
		return red("HIGH IMPACT")
	case "MEDIUM":
		return yellow("MEDIUM IMPACT")
	case "LOW":
		return cyan("LOW IMPACT")
	case "INFO":
		return dim("INFO")
	case "N/A":
		return dim("NOT_APPLICABLE")
	default:
		return dim(s)
	}
}
func severityLabel(s string) string { return severityColor(s) }
func logLabel() string {
	if cfg.LogDir == "" {
		return dim("disabled")
	}
	return green(cfg.LogDir)
}
func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "notice":
		return "info"
	default:
		return "info"
	}
}
func impactLevel(severity string) string {
	switch normalizeSeverity(severity) {
	case "critical", "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "INFO"
	}
}
func statusRank(s Status) int {
	switch s {
	case FAIL:
		return 0
	case WARN:
		return 1
	case UNKNOWN:
		return 2
	case PASS:
		return 3
	default:
		return 4
	}
}
func forensicLevelForCheck(name string) int {
	m := map[string]int{
		"dependencies": 1, "platform": 1, "secureboot": 1, "secureboot-policy": 1, "sbat": 1, "tpm": 1, "tpm-pcr7": 1, "bootchain": 1, "boot-security": 1, "security-controls": 1, "evidence": 1, "virtualization": 1,
		"measuredboot": 2, "tpm-eventlog": 2, "nvram": 2, "efi-var-integrity": 2, "bootentries": 2, "modules": 2, "module-signatures": 2, "processes": 2, "kernel-posture": 2, "kernel-lockdown": 2, "kernel-taint": 2, "mounts": 2, "efi-mount": 2, "updates": 2,
		"firmware-sources": 3, "firmware-update-path": 3, "fwupd-security": 3, "platform-management": 3, "verity": 3, "kernel-integrity": 3, "persistence": 3, "initramfs": 3, "efi-attributes": 3, "ima": 3, "kernel-config": 3, "kernel-cmdline": 3, "kexec": 3, "iommu": 3, "acpi-integrity": 3, "fs-integrity": 3, "efi-content": 3, "debug-surfaces": 3,
		"forensic-yara": 4, "firmware-forensics": 4, "spilock": 4, "cve-indicators": 4, "baseline": 4, "vuln-knowledge": 4,
		"deep-forensics":    5,
		"firmware-capsules": 4, "secureboot-keys": 4, "tpm-deep": 4, "smm-security": 4,
		"dxe-integrity": 4, "nvram-forensics": 4, "hardware-rot": 4, "uefi-shell": 4,
		"pci-option-rom": 4, "anti-rollback": 4, "side-channels": 3, "microcode": 3, "capsule-results": 4,
		"virtualization-escape":  4,
		"firmware-volume-parser": 4,
		"malware-scan":           1, "spyware-scan": 1, "threat-intel-2026": 1, "spyware-intel-2026": 1,
	}
	return m[name]
}
func forensicLevelName(level int) string {
	switch level {
	case 1:
		return "triage"
	case 2:
		return "extended"
	case 3:
		return "deep"
	case 4:
		return "advanced"
	case 5:
		return "full"
	default:
		return "custom"
	}
}
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func initLog() error {
	if strings.TrimSpace(cfg.LogDir) == "" {
		return nil
	}
	if err := os.MkdirAll(cfg.LogDir, 0750); err != nil {
		return err
	}
	name := filepath.Join(cfg.LogDir, "sl0ppy-UEFIScan_"+time.Now().UTC().Format("20060102_150405")+".log")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	logFile = f
	logf(1, "log initialized path=%s", name)
	return nil
}
func closeLog() {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_ = logFile.Sync()
		_ = logFile.Close()
		logFile = nil
	}
}
func logf(level int, format string, args ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile == nil {
		return
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	fmt.Fprintf(logFile, "%s [L%d] %s\n", stamp, level, fmt.Sprintf(format, args...))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…[truncated]"
}
func oneLine(s string, n int) string { return truncate(strings.Join(strings.Fields(s), " "), n) }
func printable(s string) string {
	b := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			return r
		}
		return '·'
	}, s)
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func safeID(s string) string {
	re := regexp.MustCompile(`[^A-Za-z0-9]+`)
	return truncate(re.ReplaceAllString(s, "_"), 80)
}
func extractToken(s, p string) string {
	for _, x := range strings.Fields(s) {
		if strings.HasPrefix(x, p) {
			return x
		}
	}
	return ""
}
func runtimeKernel() string {
	out, e := run("uname", "-r")
	if e != nil {
		return "unknown"
	}
	return strings.TrimSpace(out)
}
func findConfig(data, key string) string {
	for _, ln := range strings.Split(data, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), key) {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}
func normalizeEvidence(s string) string { return strings.Join(strings.Fields(s), " ") }

// Keep these imports/function references intentional: they make the binary's hashing
// and versioned report format explicit and leave room for future cryptographic baseline
// extensions without changing the report schema.
var _ = sha256.New
var _ = bufio.NewReader
var _ = strconv.Itoa

// ============================================================================
// FUSED LEGACY FORENSIC / FIRMWARE EVIDENCE LAYER
// ============================================================================
// This layer preserves the useful forensic concepts from sl0ppy-UEFIScan v1.1
// while keeping the v5 reporting model authoritative. It is intentionally
// read-only: no firmware writes, NVRAM writes, reflashing, or remediation are
// performed by this scanner.

const (
	YaraRulesDir      = "/tmp/sl0ppy_yara_rules_2025"
	RuleUpdateTimeout = 60 * time.Second
)

type UEFIFirmwareRegion struct {
	Name     string
	Start    uint64
	End      uint64
	Expected string
	TPMBound bool
	Critical bool
}

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

type FirmwareCheck struct {
	Region        string `json:"region"`
	Version       string `json:"version,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	Model         string `json:"model,omitempty"`
	Hash          string `json:"hash,omitempty"`
	ExpectedHash  string `json:"expected_hash,omitempty"`
	Algorithm     string `json:"algorithm,omitempty"`
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

type YARAMatch struct {
	FilePath string `json:"file"`
	String   string `json:"string"`
	Offset   string `json:"offset"`
	Data     string `json:"data"`
}

type NVRAMVariable struct {
	Name     string
	Expected string
	Critical bool
	Pattern  string
}

type NVRAMCheckLegacy struct {
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

// These are intentionally conservative defensive signatures. Generic byte
// sequences are never treated as proof of compromise; matches are surfaced for
// manual/vendor validation.
var enhancedYaraRules = map[string]string{
	"UEFI_Firmware_Tampering": `
rule UEFI_Firmware_Tampering {
 meta:
  description = "Detects suspicious firmware modification indicators"
  severity = "CRITICAL"
 strings:
  $dxe_anomaly = {48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 10}
 condition:
  any of them
}`,
	"UEFI_Hydrophobia": `
rule UEFI_Hydrophobia {
 meta:
  description = "Defensive indicator set for Hydrophobia-related Secure Boot research"
  severity = "CRITICAL"
  category = "Evasion"
 strings:
  $hydro_nvram = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ??}
  $hydro_smm = {48 C7 C0 00 00 00 00 0F 22 C0}
 condition:
  any of them
}`,
	"UEFI_SecureBoot_Bypass": `
rule UEFI_SecureBoot_Bypass {
 meta:
  description = "Detects suspicious Secure Boot bypass-related patterns"
  severity = "CRITICAL"
  category = "Evasion"
 strings:
  $nvram_tamper = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E}
  $pe_loader = {48 8B 45 D8 48 8D 15 ?? ?? ?? ?? 48 8B 00 48 89 45 E0}
  $msft_cert_abuse = "Microsoft Corporation UEFI CA 2011" wide ascii
 condition:
  any of them
}`,
	"UEFI_SMM_Hook_Generic": `
rule UEFI_SMM_Hook_Generic {
 meta:
  description = "Detects generic suspicious SMM-hook-like code patterns"
  severity = "CRITICAL"
  category = "Rootkit"
 strings:
  $smm_prologue_1 = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30}
  $smm_prologue_2 = {55 48 89 E5 48 83 EC 40 48 89 7D D8}
  $smm_sw_smi = {0F 01 5D ?? ?? ?? ?? ??}
 condition:
  any of them
}`,
	"UEFI_SPI_Flash_Manipulation": `
rule UEFI_SPI_Flash_Manipulation {
 meta:
  description = "Detects generic SPI-flash manipulation indicators"
  severity = "CRITICAL"
  category = "Persistence"
 strings:
  $spi_erase = {06 80 00 00 00 00}
  $spi_write = {02 80 00 00 00 00}
 condition:
  any of them
}`,
	"UEFI_Suspicious_Calls": `
rule UEFI_Suspicious_Calls {
 meta:
  description = "Detects suspicious UEFI runtime-service call patterns"
  severity = "HIGH"
 strings:
  $get_bs = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 18 48 85 C0 74 ??}
  $fv_access = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 20}
 condition:
  any of them
}`,
	"UEFI_AntiDebug_AntiVM": `
rule UEFI_AntiDebug_AntiVM {
 meta:
  description = "Detects anti-debug or anti-VM indicators"
  severity = "HIGH"
  category = "Evasion"
 strings:
  $anti_vm_1 = "VMware" nocase
  $anti_vm_2 = "VBox" nocase
  $anti_pt = {0F 01 D9}
 condition:
  any of them
}`,
	"UEFI_Backdoor_Keylogger": `
rule UEFI_Backdoor_Keylogger {
 meta:
  description = "Detects generic UEFI backdoor/keylogging indicators"
  severity = "CRITICAL"
 strings:
  $net_comms = "EFI_SIMPLE_NETWORK_PROTOCOL" wide ascii
  $hidden_cmd = "Backdoor" nocase
 condition:
  any of them
}`,
	"LoJax_2025": `
rule UEFI_LoJax_2025 {
 meta:
  description = "Defensive LoJax UEFI rootkit indicator set"
  severity = "CRITICAL"
  category = "Rootkit"
  version = "3.0"
 strings:
  $lojax_smm_hook = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30 48 8B 05 ?? ?? ?? ??}
  $lojax_persistence = {48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E}
 condition:
  any of them
}`,
	"MoonBounce_2025": `
rule UEFI_MoonBounce_2025 {
 meta:
  description = "Defensive MoonBounce UEFI implant indicator set"
  severity = "CRITICAL"
  category = "Bootkit"
  version = "4.1"
 strings:
  $mb_spi_flash = {55 48 89 E5 48 83 EC 40 48 89 7D D8 48 89 75 D0}
  $mb_pe_loader = {48 8B 45 D8 48 8D 15 ?? ?? ?? ?? 48 8B 00}
 condition:
  any of them
}`,
	"BlackLotus_UEFI_Bootkit": `
rule UEFI_BlackLotus {
 meta:
  description = "Defensive BlackLotus UEFI bootkit indicator set"
  severity = "CRITICAL"
  category = "Bootkit"
  version = "2.0"
 strings:
  $bl_secure_boot_bypass = {48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1E}
  $bl_persistence = {48 8B 45 E0 48 85 C0 74 1A 48 8B 40 18}
 condition:
  any of them
}`,
	"UEFI_AntiDebug": `
rule UEFI_AntiDebug {
 meta:
  description = "Defensive anti-debug indicator set"
  severity = "HIGH"
  category = "Evasion"
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
  description = "Defensive generic UEFI persistence indicators"
  severity = "HIGH"
  category = "Persistence"
 strings:
  $uefi_persistence = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 40 18}
  $smm_hook = {48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30}
 condition:
  any of them
}`,
	"UEFI_Malware_Generic_2025": `
rule UEFI_Malware_Generic_2025 {
 meta:
  description = "Defensive generic UEFI malware pattern set"
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
  description = "Defensive suspicious UEFI pattern set"
  severity = "HIGH"
  category = "Malware"
 strings:
  $suspicious_call = {E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 05 ?? ?? ?? ??}
  $backdoor_pattern = "Backdoor" nocase
 condition:
  any of them
}`,
	"UEFI_MosaicRegressor_Indicators": `
rule UEFI_MosaicRegressor_Indicators {
 meta:
  description = "Research indicators associated with MosaicRegressor-style UEFI persistence"
  severity = "HIGH"
  category = "Persistence"
 strings:
  $a = "MosaicRegressor" nocase
  $b = "NVRAM" nocase
  $c = "EFI_DRIVER" ascii
 condition:
  2 of them
}`,
	"UEFI_FinFisher_Indicators": `
rule UEFI_FinFisher_Indicators {
 meta:
  description = "Research indicators associated with FinFisher/FinSpy boot persistence"
  severity = "HIGH"
  category = "Persistence"
 strings:
  $a = "FinFisher" nocase
  $b = "FinSpy" nocase
  $c = "bootkit" nocase
 condition:
  2 of them
}`,
	"UEFI_TrickBoot_Indicators": `
rule UEFI_TrickBoot_Indicators {
 meta:
  description = "Research indicators associated with TrickBoot firmware tampering"
  severity = "HIGH"
  category = "Bootkit"
 strings:
  $a = "TrickBoot" nocase
  $b = "flashrom" nocase
  $c = "SPI" nocase
 condition:
  2 of them
}`,
	"UEFI_BlackLotus_Indicators": `
rule UEFI_BlackLotus_Indicators {
 meta:
  description = "Research indicators associated with BlackLotus boot-chain abuse"
  severity = "HIGH"
  category = "Bootkit"
 strings:
  $a = "BlackLotus" nocase
  $b = "\\EFI\\Microsoft\\Boot" nocase wide ascii
 condition:
  any of them
}`,
}

var embeddedSpywareYaraRules = []string{
	`rule UEFI_Spyware_Collection_Indicators {
 meta:
  description = "Defensive UEFI surveillance/collection behavior indicators"
  severity = "HIGH"
  category = "Spyware"
 strings:
  $a = "keylog" nocase
  $b = "keystroke" nocase
  $c = "keyboard hook" nocase
  $d = "screenshot" nocase
  $e = "clipboard" nocase
  $f = "microphone" nocase
  $g = "webcam" nocase
  $h = "credential" nocase
 condition:
  2 of them
}`,
	`rule UEFI_Spyware_Exfil_Indicators {
 meta:
  description = "Defensive UEFI network/exfiltration indicators"
  severity = "HIGH"
  category = "Spyware"
 strings:
  $a = "http://" nocase
  $b = "https://" nocase
  $c = "user-agent" nocase
  $d = "post /" nocase
  $e = "EFI_HTTP_PROTOCOL" nocase
  $f = "EFI_TCP4_PROTOCOL" nocase
  $g = "EFI_UDP4_PROTOCOL" nocase
  $h = "exfil" nocase
 condition:
  2 of them
}`,
	`rule UEFI_Spyware_Persistence_Indicators {
 meta:
  description = "Defensive UEFI runtime-variable/persistence indicators"
  severity = "MEDIUM"
  category = "Spyware"
 strings:
  $a = "GetVariable" nocase
  $b = "SetVariable" nocase
  $c = "Runtime Services" nocase
  $d = "BootOrder" nocase
  $e = "BootNext" nocase
  $f = "Driver####" nocase
 condition:
  2 of them
}`,
	`rule UEFI_Spyware_CommandAndControl {
 meta:
  description = "Defensive C2/beaconing indicators in firmware artifacts"
  severity = "HIGH"
  category = "Spyware"
 strings:
  $a = "beacon" nocase
  $b = "command and control" nocase
  $c = "C2" ascii
  $d = "socket" nocase
  $e = "upload" nocase
 condition:
  2 of them
}`,
}

var githubYaraRules2025 = []struct {
	URL, Filename, Description, Maintainer, LastUpdated string
}{
	{"https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_LoJax.yar", "APT_LoJax.yar", "LoJax indicators", "Yara-Rules Community", "2023-10-15"},
	{"https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/UEFI_MoonBounce.yar", "UEFI_MoonBounce.yar", "MoonBounce indicators", "Yara-Rules Community", "2023-11-22"},
	{"https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_lojax.yar", "apt_lojax.yar", "Alternative LoJax indicators", "Neo23x0", "2024-05-01"},
	{"https://raw.githubusercontent.com/InQuest/awesome-yara/master/rules/UEFI_BlackLotus.yar", "UEFI_BlackLotus.yar", "BlackLotus indicators", "InQuest", "2023-06-01"},
}

var uefiVulnerabilities2025 = []VulnerabilityCheck{
	{Name: "AMD Return Address Predictor Vulnerability", CVE: "CVE-2023-20569", Severity: "CRITICAL", Fix: "Update vendor firmware and validate SMM components.", Affected: []string{"UEFI SMM", "System Management Mode"}, Description: "Applicability requires exact platform/firmware mapping; this scanner does not infer CVE exposure from generic SMM strings.", DisclosureDate: "2023", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2023-20569", Exploitability: "Requires vendor/package correlation"},
	{Name: "TianoCore Buffer Overflow", CVE: "CVE-2023-31705", Severity: "CRITICAL", Fix: "Apply applicable vendor/TianoCore firmware updates.", Affected: []string{"TianoCore EDK II", "UEFI Boot Manager"}, Description: "Applicability requires exact firmware component/version mapping.", DisclosureDate: "2023", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2023-31705", Exploitability: "Requires component correlation"},
	{Name: "UEFI Secure Boot Bypass", CVE: "CVE-2023-33742", Severity: "CRITICAL", Fix: "Apply applicable firmware updates and validate Secure Boot configuration.", Affected: []string{"UEFI Secure Boot"}, Description: "A disabled Secure Boot state is not proof of this CVE; vulnerability applicability requires exact firmware identification.", DisclosureDate: "2023", Reference: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-33742", Exploitability: "Requires vendor correlation"},
	{Name: "InsydeH2O SMI Handler Vulnerability", CVE: "CVE-2023-42756", Severity: "HIGH", Fix: "Check the OEM advisory and update firmware if affected.", Affected: []string{"InsydeH2O UEFI", "SMI handlers"}, Description: "Applicability requires exact OEM firmware/component mapping.", DisclosureDate: "2023", Reference: "https://www.insyde.com/security-advisories/", Exploitability: "Requires OEM correlation"},
	{Name: "AMD SMM Callout Vulnerability", CVE: "CVE-2024-0179", Severity: "HIGH", Fix: "Apply the OEM firmware/PI update identified by AMD for the affected platform.", Affected: []string{"AMD UEFI SMM"}, Description: "Applicability requires exact AMD/OEM firmware component and version correlation; generic SMM indicators are insufficient.", DisclosureDate: "2024", Reference: "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7027.html", Exploitability: "Requires OEM correlation"},
	{Name: "AMD PSP Firmware Input Validation", CVE: "CVE-2024-21925", Severity: "HIGH", Fix: "Apply the OEM firmware/PI update identified by AMD for the affected platform.", Affected: []string{"AMD PSP", "AmdPspP2CmboxV2"}, Description: "Applicability requires exact platform firmware correlation.", DisclosureDate: "2024", Reference: "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7027.html", Exploitability: "Requires OEM correlation"},
	{Name: "AMD SMM Supervisor Vulnerability", CVE: "CVE-2023-20596", Severity: "HIGH", Fix: "Apply the OEM PI firmware update and verify SMEP/UMIP posture as appropriate.", Affected: []string{"AMD SMM Supervisor"}, Description: "Applicability requires exact AMD/OEM firmware correlation.", DisclosureDate: "2023", Reference: "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7011.html", Exploitability: "Requires OEM correlation"},
}

func updateDefensiveYARARules() ([]string, error) {
	if err := os.RemoveAll(YaraRulesDir); err != nil {
		return nil, fmt.Errorf("clean rules directory: %w", err)
	}
	if err := os.MkdirAll(YaraRulesDir, 0750); err != nil {
		return nil, fmt.Errorf("create rules directory: %w", err)
	}
	client := &http.Client{Timeout: RuleUpdateTimeout}
	var sources []string
	// Resolve by repository tree instead of hard-coding paths that may disappear.
	api := "https://api.github.com/repos/Yara-Rules/rules/git/trees/master?recursive=1"
	paths, err := githubTree(client, api)
	if err != nil {
		// Built-in rules remain usable; updater failure is not fatal to the scan.
		return writeBuiltInRules(sources, fmt.Errorf("Yara-Rules tree lookup failed: %w", err))
	}
	wanted := []string{"APT_LoJax.yar", "UEFI_MoonBounce.yar", "MosaicRegressor.yar", "FinFisher.yar", "TrickBoot.yar", "BlackLotus.yar"}
	for _, name := range wanted {
		path := findTreeFile(paths, name)
		if path == "" {
			// This is intentionally informational: the current upstream tree may not publish that filename.
			continue
		}
		url := "https://raw.githubusercontent.com/Yara-Rules/rules/master/" + path
		data, err := downloadRule(client, url)
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(YaraRulesDir, filepath.Base(path)), data, 0640); err == nil {
			sources = append(sources, "Yara-Rules:"+path)
		}
	}
	return writeBuiltInRules(sources, nil)
}

func githubTree(client *http.Client, api string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, api, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sl0ppy-UEFIScan/9.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub tree query returned HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(&doc); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(doc.Tree))
	for _, x := range doc.Tree {
		if x.Type == "blob" {
			paths = append(paths, x.Path)
		}
	}
	return paths, nil
}

func findTreeFile(paths []string, wanted string) string {
	for _, p := range paths {
		if strings.EqualFold(filepath.Base(p), wanted) {
			return p
		}
	}
	return ""
}

func downloadRule(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sl0ppy-UEFIScan/9.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil || len(b) == 0 {
		return nil, errors.New("empty or unreadable rule")
	}
	return b, nil
}

func writeBuiltInRules(sources []string, priorErr error) ([]string, error) {
	var b strings.Builder
	for _, rule := range enhancedYaraRules {
		b.WriteString("\n")
		b.WriteString(rule)
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(YaraRulesDir, "built_in_rules.yar"), []byte(b.String()), 0640); err != nil {
		return sources, fmt.Errorf("write built-in rules: %w", err)
	}
	sources = append(sources, "Built-in:enhanced rules")
	return sources, priorErr
}
func loadLegacyYARARules() []MalwareSignature {
	var rules []MalwareSignature
	for name, rule := range enhancedYaraRules {
		sev := "HIGH"
		if strings.Contains(rule, `severity = "CRITICAL"`) {
			sev = "CRITICAL"
		}
		cat := "Malware"
		for _, c := range []string{"Rootkit", "Bootkit", "Evasion", "Persistence"} {
			if strings.Contains(rule, `category = "`+c+`"`) || strings.Contains(rule, c) {
				cat = c
				break
			}
		}
		rules = append(rules, MalwareSignature{Name: name, Pattern: rule, Severity: sev, Source: "Built-in", Category: cat, ConfirmationReq: 2, RuleFile: "built_in_rules.yar", Version: "5.3", LastUpdated: time.Now().UTC().Format(time.RFC3339)})
	}
	return rules
}

func checkForensicYARA(r *Report) {
	if !cfg.LegacyForensic {
		return
	}
	if cfg.YaraDir == "" && cfg.UpdateYARA {
		cfg.YaraDir = YaraRulesDir
	}
	if cfg.YaraDir == "" {
		// Always materialize the conservative built-in rule set at forensic level 4+.
		// External rules remain optional; built-ins are defensive indicators only.
		if _, err := os.Stat(YaraRulesDir); err != nil {
			if mkErr := os.MkdirAll(YaraRulesDir, 0750); mkErr == nil {
				_, _ = writeBuiltInRules(nil, nil)
			}
		}
		if _, err := os.Stat(YaraRulesDir); err == nil {
			scanYARA(r, YaraRulesDir)
			add(r, "YARA-FORENSIC-000", "forensic-yara", "Defensive YARA rule source", PASS, "info", "high", "built-in conservative firmware rule set materialized automatically; external trusted rules may be supplied with -yara or refreshed with -update-yara", "maintain trusted external rule provenance and refresh the rule set periodically", "built-in rules")
			return
		}
		add(r, "YARA-FORENSIC-000", "forensic-yara", "Defensive YARA rule source", UNKNOWN, "medium", "medium", "could not materialize the built-in rule set", "verify writable temporary rule storage and rerun the forensic profile", "configuration")
		return
	}
	if _, e := os.Stat(cfg.YaraDir); e != nil {
		add(r, "YARA-FORENSIC-000", "forensic-yara", "Defensive YARA rule source", UNKNOWN, "medium", "high", e.Error(), "provide a readable YARA rule directory", cfg.YaraDir)
		return
	}
	scanYARA(r, cfg.YaraDir)
}
func parseLegacyYARAFile(path, content string) []MalwareSignature {
	var out []MalwareSignature
	re := regexp.MustCompile(`(?is)rule\s+([A-Za-z0-9_]+)\s*\{(.*?)\n\}`)
	for _, m := range re.FindAllStringSubmatch(content, -1) {
		if len(m) < 3 {
			continue
		}
		name, body := m[1], m[2]
		sev := "MEDIUM"
		if x := regexp.MustCompile(`(?i)severity\s*=\s*"([^"]+)"`).FindStringSubmatch(body); len(x) > 1 {
			sev = strings.ToUpper(x[1])
		}
		cat := "Unknown"
		if x := regexp.MustCompile(`(?i)category\s*=\s*"([^"]+)"`).FindStringSubmatch(body); len(x) > 1 {
			cat = x[1]
		}
		out = append(out, MalwareSignature{Name: name, Pattern: "rule " + name + " {" + body + "}", Severity: sev, Source: "Downloaded:" + filepath.Base(path), Category: cat, RuleFile: path, Version: "external"})
	}
	return out
}

func scanLegacyRuleHeuristics(path string, data []byte, rule string) []YARAMatch {
	var out []YARAMatch
	lower := strings.ToLower(string(data))
	for _, k := range []string{"backdoor", "lojax", "moonbounce", "blacklotus", "mosaicregressor", "finfisher", "finspy", "trickboot", "hydrophobia", "efi_simple_network_protocol", "bootkit", "smm callout"} {
		if strings.Contains(strings.ToLower(rule), k) {
			if i := strings.Index(lower, k); i >= 0 {
				out = append(out, YARAMatch{FilePath: path, String: k, Offset: fmt.Sprintf("0x%x", i), Data: hex.EncodeToString(data[max(0, i):min(len(data), i+len(k))])})
			}
		}
	}
	for _, hm := range regexp.MustCompile(`\{([0-9A-Fa-f?\s]+)\}`).FindAllStringSubmatch(rule, -1) {
		parts := strings.Fields(hm[1])
		var raw []byte
		for _, p := range parts {
			if strings.Contains(p, "?") || len(p) != 2 {
				continue
			}
			b, err := hex.DecodeString(p)
			if err == nil {
				raw = append(raw, b...)
			}
			if len(raw) >= 4 {
				break
			}
		}
		if len(raw) >= 4 {
			if i := indexBytes(data, raw); i >= 0 {
				out = append(out, YARAMatch{FilePath: path, String: "hexseq", Offset: fmt.Sprintf("0x%x", i), Data: hex.EncodeToString(raw)})
			}
		}
	}
	return out
}

func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func parseHexOffset(s string) int64 {
	s = strings.TrimPrefix(s, "0x")
	n, _ := strconv.ParseInt(s, 16, 64)
	return n
}

func checkFirmwareForensics(r *Report) {
	if !cfg.LegacyForensic {
		return
	}
	// Identity and hardware evidence is collected without pretending that a
	// synthetic hash is a firmware-image measurement.
	vendor, _ := readText("/sys/class/dmi/id/bios_vendor", 256)
	versionText, _ := readText("/sys/class/dmi/id/bios_version", 256)
	model, _ := readText("/sys/class/dmi/id/product_name", 512)
	secure := false
	if b, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil && len(b) > 4 {
		secure = b[4] == 1
	}
	tpm := exists("/dev/tpmrm0") || exists("/dev/tpm0")
	ima := exists("/sys/kernel/security/ima/ascii_runtime_measurements")
	identity := fmt.Sprintf("vendor=%s; version=%s; model=%s", strings.TrimSpace(vendor), strings.TrimSpace(versionText), strings.TrimSpace(model))
	identityStatus := PASS
	identitySeverity := "info"
	identityConfidence := "high"
	if strings.TrimSpace(vendor) == "" || strings.TrimSpace(versionText) == "" || strings.TrimSpace(model) == "" {
		identityStatus = UNKNOWN
		identitySeverity = "medium"
		identityConfidence = "medium"
	}
	add(r, "FW-FORENSIC-001", "firmware-forensics", "Firmware forensic identity", identityStatus, identitySeverity, identityConfidence, identity, "populate and verify complete firmware identity from DMI/sysfs or vendor tooling; compare it against an OEM-trusted baseline", "DMI sysfs")
	add(r, "FW-FORENSIC-002", "firmware-forensics", "Firmware trust binding evidence", func() Status {
		if secure && tpm && ima {
			return PASS
		}
		return UNKNOWN
	}(), "high", "medium", fmt.Sprintf("SecureBoot=%t TPM=%t IMA=%t; this is evidence availability, not proof of firmware authenticity", secure, tpm, ima), "combine vendor firmware validation with TPM PCR/IMA attestation where supported", "UEFI + TPM + IMA")

	roots := []string{"/boot/efi/EFI", "/boot/efi"}
	count := 0
	for _, root := range roots {
		if !exists(root) {
			continue
		}
		_ = filepath.Walk(root, func(p string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || info.Size() > cfg.MaxFile {
				return nil
			}
			if h, err := hashFile(p); err == nil {
				count++
				r.Matches = append(r.Matches, SignatureMatch{Rule: "SHA512-ARTIFACT", File: p, Offset: 0, Evidence: h})
			}
			return nil
		})
	}
	if count > 0 {
		add(r, "FW-FORENSIC-003", "firmware-forensics", "EFI artifact forensic hashes", PASS, "medium", "high", fmt.Sprintf("SHA-512 measurements collected for %d EFI artifacts", count), "compare hashes with signed OEM/package baselines", "filesystem hash")
	} else {
		add(r, "FW-FORENSIC-003", "firmware-forensics", "EFI artifact forensic hashes", UNKNOWN, "medium", "medium", "no readable EFI artifacts available", "verify ESP mount and permissions", "filesystem")
	}

	if cfg.UseFlashrom {
		collectFlashromFirmwareHash(r)
	} else {
		add(r, "FW-FLASH-000", "firmware-forensics", "Physical SPI firmware image hash", NA, "high", "high", "flashrom physical firmware read disabled by default", "rerun with -flashrom on supported hardware for a read-only flash image acquisition", "configuration")
	}
}

func collectFlashromFirmwareHash(r *Report) {
	if _, err := exec.LookPath("flashrom"); err != nil {
		add(r, "FW-FLASH-001", "firmware-forensics", "Physical SPI firmware image hash", UNKNOWN, "high", "high", "flashrom is not installed", "install a trusted flashrom package and rerun with -flashrom", "PATH")
		return
	}
	f, err := os.CreateTemp("", "sl0ppy-uefi-flash-*.bin")
	if err != nil {
		add(r, "FW-FLASH-001", "firmware-forensics", "Physical SPI firmware image hash", UNKNOWN, "high", "medium", err.Error(), "verify temporary-file permissions", "filesystem")
		return
	}
	path := f.Name()
	f.Close()
	if cfg.Malware || cfg.Spyware {
		runtimeFirmwareImage = path
	} else {
		defer os.Remove(path)
	}
	out, err := run("flashrom", "-p", "internal", "-r", path)
	if err != nil {
		add(r, "FW-FLASH-001", "firmware-forensics", "Physical SPI firmware image hash", UNKNOWN, "high", "medium", truncate(out, 1600), "use supported vendor/flashrom read-only acquisition; no write operation was requested", "flashrom -p internal -r")
		return
	}
	h, err := hashFile(path)
	if err != nil {
		add(r, "FW-FLASH-001", "firmware-forensics", "Physical SPI firmware image hash", UNKNOWN, "high", "medium", err.Error(), "preserve and hash the acquired image with a trusted tool", "flashrom image")
		return
	}
	st, _ := os.Stat(path)
	sz := int64(0)
	if st != nil {
		sz = st.Size()
	}
	add(r, "FW-FLASH-001", "firmware-forensics", "Physical SPI firmware image hash", PASS, "high", "high", fmt.Sprintf("read-only flash image acquired: %d bytes sha512=%s; %s", sz, h, truncate(out, 700)), "compare the image hash against a trusted OEM firmware image; hashing alone does not establish provenance", "flashrom read-only acquisition")
	analyzeFirmwareImage(r, path, "flashrom read-only acquisition")
}

// Firmware-volume parsing is intentionally read-only. It follows the UEFI PI
// model: firmware volumes contain 8-byte-aligned FFS files, and FFS files contain
// 4-byte-aligned sections. The parser records structure and hashes without
// executing or modifying any firmware payload.

const (
	fvHeaderSignatureOffset     = 40
	fvHeaderMinimumSize         = 56
	ffsHeaderSize               = 24
	ffsHeader2Size              = 32
	ffsFileTypeRaw              = 0x01
	ffsFileTypeFreeform         = 0x02
	ffsFileTypeSecurityCore     = 0x03
	ffsFileTypePEICore          = 0x04
	ffsFileTypeDXECore          = 0x05
	ffsFileTypePEIM             = 0x06
	ffsFileTypeDXEDriver        = 0x07
	ffsFileTypeDXECombined      = 0x08
	ffsFileTypeApplication      = 0x09
	ffsFileTypeMM               = 0x0A
	ffsFileTypeFirmwareVolume   = 0x0B
	ffsFileTypeCombinedMMDXE    = 0x0C
	ffsFileTypeMMCore           = 0x0D
	ffsFileTypeMMStandalone     = 0x0E
	ffsFileTypeMMCoreStandalone = 0x0F
	ffsFileTypePad              = 0xF0
)

func align8u(v uint64) uint64 { return (v + 7) &^ 7 }
func align4u(v uint64) uint64 { return (v + 3) &^ 3 }

func firmwareFFSTypeName(t uint8) string {
	switch t {
	case ffsFileTypeRaw:
		return "RAW"
	case ffsFileTypeFreeform:
		return "FREEFORM"
	case ffsFileTypeSecurityCore:
		return "SECURITY_CORE"
	case ffsFileTypePEICore:
		return "PEI_CORE"
	case ffsFileTypeDXECore:
		return "DXE_CORE"
	case ffsFileTypePEIM:
		return "PEIM"
	case ffsFileTypeDXEDriver:
		return "DXE_DRIVER"
	case ffsFileTypeDXECombined:
		return "DXE_COMBINED_DRIVER"
	case ffsFileTypeApplication:
		return "APPLICATION"
	case ffsFileTypeMM:
		return "MM"
	case ffsFileTypeFirmwareVolume:
		return "FIRMWARE_VOLUME_IMAGE"
	case ffsFileTypeCombinedMMDXE:
		return "COMBINED_MM_DXE"
	case ffsFileTypeMMCore:
		return "MM_CORE"
	case ffsFileTypeMMStandalone:
		return "MM_STANDALONE"
	case ffsFileTypeMMCoreStandalone:
		return "MM_CORE_STANDALONE"
	case ffsFileTypePad:
		return "PAD"
	default:
		return fmt.Sprintf("TYPE_0x%02x", t)
	}
}

func firmwareExecutionClass(t uint8) string {
	switch t {
	case ffsFileTypePEICore, ffsFileTypePEIM:
		return "PEI"
	case ffsFileTypeDXECore, ffsFileTypeDXEDriver, ffsFileTypeDXECombined:
		return "DXE"
	case ffsFileTypeMM, ffsFileTypeCombinedMMDXE, ffsFileTypeMMCore, ffsFileTypeMMStandalone, ffsFileTypeMMCoreStandalone:
		return "SMM/MM"
	case ffsFileTypeRaw:
		return "RAW"
	default:
		return "OTHER"
	}
}

func firmwareSectionTypeName(t uint8) string {
	switch t {
	case 0x01:
		return "COMPRESSION"
	case 0x02:
		return "GUID_DEFINED"
	case 0x10:
		return "PE32"
	case 0x11:
		return "PIC"
	case 0x12:
		return "TE"
	case 0x13:
		return "DXE_DEPEX"
	case 0x14:
		return "VERSION"
	case 0x15:
		return "UI"
	case 0x16:
		return "COMPAT16"
	case 0x17:
		return "FV_IMAGE"
	case 0x18:
		return "FREEFORM_SUBTYPE_GUID"
	case 0x19:
		return "RAW"
	case 0x1B:
		return "MM_DEPEX"
	default:
		return fmt.Sprintf("TYPE_0x%02x", t)
	}
}

func decodeUTF16String(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	vals := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i : i+2])
		if v == 0 {
			break
		}
		vals = append(vals, v)
	}
	if len(vals) == 0 {
		return ""
	}
	return printable(string(utf16.Decode(vals)))
}

func validGUIDBytes(b []byte) bool {
	if len(b) < 16 {
		return false
	}
	all0, allF := true, true
	for _, x := range b[:16] {
		if x != 0 {
			all0 = false
		}
		if x != 0xff {
			allF = false
		}
	}
	return !all0 && !allF
}

func checksum16Valid(data []byte) bool {
	if len(data) == 0 || len(data)%2 != 0 {
		return false
	}
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.LittleEndian.Uint16(data[i : i+2]))
	}
	return uint16(sum) == 0
}

func parseFirmwareSections(data []byte, base uint64, maxSections int) ([]FirmwareSectionReport, string) {
	var out []FirmwareSectionReport
	var uiName string
	off := 0
	for off+4 <= len(data) && len(out) < maxSections {
		sz24 := uint64(data[off]) | uint64(data[off+1])<<8 | uint64(data[off+2])<<16
		t := data[off+3]
		if sz24 == 0 || sz24 == 0xFFFFFF && off+8 > len(data) {
			break
		}
		header := uint64(4)
		size := sz24
		if sz24 == 0xFFFFFF {
			size = uint64(binary.LittleEndian.Uint32(data[off+4 : off+8]))
			header = 8
		}
		if size < header || size > uint64(len(data)-off) {
			break
		}
		payload := data[off+int(header) : off+int(size)]
		s := FirmwareSectionReport{Offset: base + uint64(off), Size: size, HeaderSize: header, PayloadOffset: base + uint64(off) + header, Type: t, TypeName: firmwareSectionTypeName(t), SHA512: hashBytes(payload)}
		if t == 0x10 {
			s.PECOFF = isPEImage(payload)
		} else if t == 0x12 {
			s.PECOFF = len(payload) >= 2 && payload[0] == 'V' && payload[1] == 'Z'
		}
		if t == 0x15 {
			s.Text = truncate(decodeUTF16String(payload), 512)
			if s.Text != "" {
				uiName = s.Text
			}
		} else if t == 0x14 && len(payload) > 2 {
			s.Text = truncate(decodeUTF16String(payload[2:]), 512)
		} else if t == 0x02 && len(payload) >= 16 && validGUIDBytes(payload[:16]) {
			s.GUID = parseGUIDLE(payload[:16])
		}
		out = append(out, s)
		next := align4u(uint64(off) + size)
		if next <= uint64(off) {
			break
		}
		off = int(next)
	}
	return out, uiName
}

func parseUEFIFirmwareVolumes(data []byte, maxFiles, maxSections int) ([]FirmwareVolumeReport, []string) {
	if len(data) < fvHeaderMinimumSize {
		return nil, []string{"firmware image shorter than minimum FV header size"}
	}
	var volumes []FirmwareVolumeReport
	var notes []string
	search := 0
	for search < len(data) {
		i := bytes.Index(data[search:], []byte("_FVH"))
		if i < 0 {
			break
		}
		sigPos := search + i
		if sigPos < fvHeaderSignatureOffset {
			search = sigPos + 4
			continue
		}
		off := sigPos - fvHeaderSignatureOffset
		if off+fvHeaderMinimumSize > len(data) {
			break
		}
		fvLen := binary.LittleEndian.Uint64(data[off+32 : off+40])
		headerLen := binary.LittleEndian.Uint16(data[off+48 : off+50])
		revision := data[off+55]
		attrs := binary.LittleEndian.Uint32(data[off+44 : off+48])
		if fvLen < uint64(fvHeaderMinimumSize) || uint64(off)+fvLen > uint64(len(data)) || headerLen < fvHeaderMinimumSize || uint64(headerLen) > fvLen || (headerLen&1) != 0 || (revision != 1 && revision != 2) || !validGUIDBytes(data[off+16:off+32]) {
			search = sigPos + 4
			continue
		}
		end := uint64(off) + fvLen
		hdr := data[off : off+int(headerLen)]
		vol := FirmwareVolumeReport{
			Offset:              uint64(off),
			Length:              fvLen,
			HeaderLength:        headerLen,
			FilesystemGUID:      parseGUIDLE(hdr[16:32]),
			Revision:            revision,
			Attributes:          attrs,
			HeaderChecksumValid: checksum16Valid(hdr),
			FileAreaAligned:     ((uint64(off) + uint64(headerLen)) % 8) == 0,
			SectionTypes:        map[string]int{},
			FFSTypes:            map[string]int{},
		}
		if !vol.HeaderChecksumValid {
			notes = append(notes, fmt.Sprintf("FV at 0x%x has an invalid header checksum", off))
		}
		fileOff := align8u(uint64(off) + uint64(headerLen))
		filesSeen := 0
		for fileOff+ffsHeaderSize <= end && filesSeen < maxFiles {
			// Skip erased/padding bytes.
			allFF := true
			for j := uint64(0); j < ffsHeaderSize; j++ {
				if data[fileOff+j] != 0xff {
					allFF = false
					break
				}
			}
			if allFF {
				fileOff += 8
				continue
			}
			fo := int(fileOff)
			typeByte := data[fo+18]
			attrsByte := data[fo+19]
			size24 := uint64(data[fo+20]) | uint64(data[fo+21])<<8 | uint64(data[fo+22])<<16
			state := data[fo+23]
			headerSize := uint64(ffsHeaderSize)
			size := size24
			largeFile := (attrsByte & 0x01) != 0
			if largeFile {
				if fileOff+ffsHeader2Size > end {
					break
				}
				size = binary.LittleEndian.Uint64(data[fo+24 : fo+32])
				headerSize = ffsHeader2Size
			} else if size24 == 0xFFFFFF {
				// Some tooling emits the extended marker without setting the large-file bit.
				if fileOff+ffsHeader2Size > end {
					break
				}
				size = binary.LittleEndian.Uint64(data[fo+24 : fo+32])
				headerSize = ffsHeader2Size
			}
			if size < headerSize || size > end-fileOff {
				notes = append(notes, fmt.Sprintf("invalid FFS size at 0x%x type=0x%02x size=%d", fileOff, typeByte, size))
				break
			}
			fileBytes := data[fo : fo+int(size)]
			nameGUID := parseGUIDLE(fileBytes[:16])
			file := FirmwareFileReport{
				Offset:         fileOff,
				Size:           size,
				HeaderSize:     headerSize,
				NameGUID:       nameGUID,
				Type:           typeByte,
				TypeName:       firmwareFFSTypeName(typeByte),
				ExecutionClass: firmwareExecutionClass(typeByte),
				Attributes:     attrsByte,
				State:          state,
				HeaderChecksum: ffsHeaderChecksumValid(fileBytes, int(headerSize)),
				DataChecksum:   ffsDataChecksumValid(fileBytes, int(headerSize)),
				SHA512:         hashBytes(fileBytes),
			}
			sections, uiName := parseFirmwareSections(fileBytes[int(headerSize):], fileOff+headerSize, maxSections)
			file.Sections = sections
			file.Name = uiName
			vol.FilesDetail = append(vol.FilesDetail, file)
			vol.Files++
			vol.FFSTypes[file.TypeName]++
			for _, sec := range sections {
				vol.SectionCount++
				vol.SectionTypes[sec.TypeName]++
			}
			switch file.ExecutionClass {
			case "PEI":
				vol.PEIFiles++
			case "DXE":
				vol.DXEFiles++
			case "SMM/MM":
				vol.SMMFiles++
			case "RAW":
				vol.RawFiles++
			}
			if len(file.Name) > 0 {
				low := strings.ToLower(file.Name)
				if strings.Contains(low, "rootkit") || strings.Contains(low, "bootkit") || strings.Contains(low, "backdoor") || strings.Contains(low, "hook") {
					notes = append(notes, fmt.Sprintf("suspicious UI string in FV file 0x%x: %s", fileOff, truncate(file.Name, 180)))
				}
			}
			if !file.HeaderChecksum {
				notes = append(notes, fmt.Sprintf("FFS header checksum failed at 0x%x (%s)", fileOff, file.TypeName))
			}
			fileOff = align8u(fileOff + size)
			filesSeen++
		}
		volumes = append(volumes, vol)
		if fvLen == 0 {
			break
		}
		search = int(end)
	}
	// Sort and reject overlapping candidate volumes so a random _FVH inside a
	// valid FV does not become a second independent volume in the report.
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].Offset < volumes[j].Offset })
	filtered := make([]FirmwareVolumeReport, 0, len(volumes))
	var lastEnd uint64
	for _, v := range volumes {
		if len(filtered) > 0 && v.Offset < lastEnd {
			notes = append(notes, fmt.Sprintf("overlapping FV candidate at 0x%x ignored", v.Offset))
			continue
		}
		filtered = append(filtered, v)
		lastEnd = v.Offset + v.Length
	}
	return filtered, notes
}

func ffsHeaderChecksumValid(data []byte, headerSize int) bool {
	if headerSize < ffsHeaderSize || headerSize > len(data) {
		return false
	}
	// UEFI PI defines the header checksum as an 8-bit checksum. When evaluating
	// it, the File checksum byte and State byte are treated as zero and the
	// complete header must sum to zero modulo 256 when Header is included.
	if len(data) < 24 {
		return false
	}
	state := data[23]
	if state&0x02 == 0 { // EFI_FILE_HEADER_VALID is not set; header checksum is not authoritative yet.
		return true
	}
	copyHeader := append([]byte(nil), data[:headerSize]...)
	copyHeader[17] = 0 // IntegrityCheck.File
	copyHeader[23] = 0 // State
	var sum uint32
	for _, b := range copyHeader {
		sum += uint32(b)
	}
	return byte(sum) == 0
}

func ffsDataChecksumValid(data []byte, headerSize int) bool {
	if headerSize < ffsHeaderSize || headerSize > len(data) || len(data) < 24 {
		return false
	}
	attrs := data[19]
	state := data[23]
	fileChecksum := data[17]
	if state&0x04 == 0 { // EFI_FILE_DATA_VALID not set.
		return true
	}
	if attrs&0x40 == 0 {
		return fileChecksum == 0xAA
	}
	var sum uint32 = uint32(fileChecksum)
	for _, b := range data[headerSize:] {
		sum += uint32(b)
	}
	return byte(sum) == 0
}

func readFirmwareImage(path string) ([]byte, int64, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, "", err
	}
	if st.IsDir() {
		return nil, 0, "", fmt.Errorf("firmware image path is a directory")
	}
	if st.Size() <= 0 {
		return nil, 0, "", fmt.Errorf("firmware image is empty")
	}
	if cfg.MaxFirmwareImage > 0 && st.Size() > cfg.MaxFirmwareImage {
		return nil, 0, "", fmt.Errorf("firmware image is %d bytes, exceeds --max-firmware-image=%d", st.Size(), cfg.MaxFirmwareImage)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, cfg.MaxFirmwareImage+1))
	if err != nil {
		return nil, 0, "", err
	}
	if int64(len(b)) > cfg.MaxFirmwareImage {
		return nil, 0, "", fmt.Errorf("firmware image exceeds configured read limit")
	}
	return b, int64(len(b)), hashBytes(b), nil
}

func analyzeFirmwareImage(r *Report, path, source string) {
	data, size, sha, err := readFirmwareImage(path)
	if err != nil {
		add(r, "FVP-001", "firmware-volume-parser", "UEFI firmware volume acquisition", UNKNOWN, "high", "high", fmt.Sprintf("%s: %v", source, err), "provide a readable raw SPI/firmware image or rerun with supported read-only acquisition", source)
		return
	}
	volumes, notes := parseUEFIFirmwareVolumes(data, 10000, 256)
	r.FirmwareImage = &FirmwareImageEvidence{Source: source, Path: path, Size: size, SHA512: sha, FirmwareVolumes: len(volumes), Parser: "sl0ppy-UEFIScan UEFI PI FV/FFS/section parser v1"}
	r.FirmwareVolumes = append(r.FirmwareVolumes[:0], volumes...)
	add(r, "FVP-001", "firmware-volume-parser", "UEFI firmware image acquisition", PASS, "high", "high", fmt.Sprintf("source=%s size=%d bytes sha512=%s firmware_volumes=%d", source, size, sha, len(volumes)), "preserve the image and hash as forensic evidence; compare against a trusted OEM firmware image", source)
	if len(volumes) == 0 {
		add(r, "FVP-002", "firmware-volume-parser", "UEFI firmware volume discovery", UNKNOWN, "high", "high", "no structurally valid _FVH firmware volume was discovered in the image", "verify that the input is a complete raw SPI/firmware image rather than a vendor capsule or extracted partial region", "UEFI PI FV parser")
		return
	}
	fCount, pei, dxe, smm, raw, sections := 0, 0, 0, 0, 0, 0
	for _, v := range volumes {
		fCount += v.Files
		pei += v.PEIFiles
		dxe += v.DXEFiles
		smm += v.SMMFiles
		raw += v.RawFiles
		sections += v.SectionCount
	}
	add(r, "FVP-002", "firmware-volume-parser", "UEFI firmware volume discovery", PASS, "high", "high", fmt.Sprintf("volumes=%d; total_FFS=%d; PEI=%d; DXE=%d; SMM/MM=%d; RAW=%d; sections=%d", len(volumes), fCount, pei, dxe, smm, raw, sections), "preserve the parsed FV inventory and compare file GUIDs, hashes and UI strings with a trusted OEM firmware baseline", "UEFI PI firmware-volume parser")

	invalidFV, invalidFFS, invalidDataChecksums, suspiciousNames, peImages := 0, 0, 0, 0, 0
	detailLines := make([]string, 0, min(len(volumes), 32))
	for _, v := range volumes {
		if !v.HeaderChecksumValid {
			invalidFV++
		}
		invalidInV := 0
		invalidDataInV := 0
		for _, f := range v.FilesDetail {
			if !f.HeaderChecksum {
				invalidFFS++
				invalidInV++
			}
			if !f.DataChecksum {
				invalidDataInV++
				invalidDataChecksums++
			}
			if f.Name != "" {
				low := strings.ToLower(f.Name)
				if strings.Contains(low, "rootkit") || strings.Contains(low, "bootkit") || strings.Contains(low, "backdoor") || strings.Contains(low, "hook") {
					suspiciousNames++
				}
			}
			for _, sec := range f.Sections {
				if sec.PECOFF {
					peImages++
				}
			}
		}
		detailLines = append(detailLines, fmt.Sprintf("FV@0x%x len=%d guid=%s files=%d PEI=%d DXE=%d SMM/MM=%d sections=%d invalid_FFS=%d invalid_data_checksum=%d", v.Offset, v.Length, v.FilesystemGUID, v.Files, v.PEIFiles, v.DXEFiles, v.SMMFiles, v.SectionCount, invalidInV, invalidDataInV))
	}
	state := PASS
	if invalidFV > 0 || invalidFFS > 0 || suspiciousNames > 0 {
		state = WARN
	}
	evidence := fmt.Sprintf("invalid_FV_checksums=%d; invalid_FFS_headers=%d; invalid_FFS_data_checksums=%d; suspicious_UI_names=%d; PE/TE_sections=%d; %s", invalidFV, invalidFFS, invalidDataChecksums, suspiciousNames, peImages, truncate(strings.Join(detailLines, " | "), 4200))
	if len(notes) > 0 {
		evidence += "; parser_notes=" + truncate(strings.Join(notes, " | "), 2600)
	}
	add(r, "FVP-003", "firmware-volume-parser", "FV/FFS structural integrity", state, "high", "high", evidence, "validate checksum anomalies and unexpected FFS contents against the exact OEM firmware build; do not classify a parser anomaly as compromise without trusted-image comparison", "UEFI PI FV/FFS parser")
	add(r, "FVP-004", "firmware-volume-parser", "Firmware execution-region inventory", PASS, "high", "high", fmt.Sprintf("PEI files=%d; DXE files=%d; SMM/MM files=%d; RAW files=%d; PE/TE sections=%d", pei, dxe, smm, raw, peImages), "review unexpected PEI/DXE/SMM modules and compare file GUIDs/hashes with OEM firmware packages", "UEFI PI FV/FFS parser")
	if suspiciousNames > 0 {
		add(r, "FVP-005", "firmware-volume-parser", "Suspicious firmware UI-name indicators", WARN, "high", "medium", fmt.Sprintf("%d firmware files contained names/strings matching rootkit/bootkit/backdoor/hook indicators", suspiciousNames), "extract and independently verify the flagged FFS files; compare hashes and signatures with the vendor firmware package", "FFS UI section heuristic")
	} else {
		add(r, "FVP-005", "firmware-volume-parser", "Suspicious firmware UI-name indicators", PASS, "medium", "medium", "no rootkit/bootkit/backdoor/hook UI-name indicators observed in parsed FFS files", "none; retain the inventory for baseline comparison", "FFS UI section heuristic")
	}
	for _, v := range volumes {
		for _, f := range v.FilesDetail {
			logf(4, "fv-file fv=0x%x file=0x%x type=%s class=%s guid=%s size=%d sha512=%s name=%s sections=%d", v.Offset, f.Offset, f.TypeName, f.ExecutionClass, f.NameGUID, f.Size, f.SHA512, oneLine(f.Name, 160), len(f.Sections))
			for _, sec := range f.Sections {
				logf(4, "fv-section file=0x%x off=0x%x type=%s size=%d pe=%t guid=%s sha512=%s text=%s", f.Offset, sec.Offset, sec.TypeName, sec.Size, sec.PECOFF, sec.GUID, sec.SHA512, oneLine(sec.Text, 160))
			}
		}
	}
}

func checkFirmwareVolumeParser(r *Report) {
	if strings.TrimSpace(cfg.FirmwareImage) != "" {
		if !exists(cfg.FirmwareImage) {
			add(r, "FVP-000", "firmware-volume-parser", "UEFI firmware image input", UNKNOWN, "high", "high", "--firmware-image path does not exist: "+cfg.FirmwareImage, "provide a readable raw SPI/firmware image", "configuration")
			return
		}
		analyzeFirmwareImage(r, cfg.FirmwareImage, "--firmware-image")
		return
	}
	if cfg.UseFlashrom {
		add(r, "FVP-000", "firmware-volume-parser", "UEFI firmware image parser execution", NA, "high", "high", "flashrom image parsing is executed within firmware-forensics after read-only acquisition to avoid duplicate physical flash reads", "none; parser is enabled automatically by --flashrom", "configuration")
		return
	}
	add(r, "FVP-000", "firmware-volume-parser", "UEFI firmware image input", NA, "high", "high", "no raw firmware image supplied and physical SPI acquisition disabled", "rerun with --firmware-image <raw.bin> or --flashrom on supported hardware", "configuration")
}

// -----------------------------------------------------------------------------
// Malware / spyware detection pipeline
// -----------------------------------------------------------------------------

func threatTargets(r *Report) []string {
	seen := map[string]bool{}
	var targets []string
	addTarget := func(p string) {
		if strings.TrimSpace(p) == "" || seen[p] {
			return
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if st.Size() <= 0 || (cfg.MaxFile > 0 && st.Size() > cfg.MaxFile && !strings.EqualFold(p, cfg.FirmwareImage)) {
				return
			}
			seen[p] = true
			targets = append(targets, p)
		}
	}
	if cfg.FirmwareImage != "" {
		addTarget(cfg.FirmwareImage)
	} else if runtimeFirmwareImage != "" {
		addTarget(runtimeFirmwareImage)
	} else if r.FirmwareImage != nil {
		addTarget(r.FirmwareImage.Path)
	}
	for _, p := range []string{"/boot/efi/EFI", "/boot/efi/EFI/BOOT", "/boot/efi/EFI/Microsoft", "/efi/EFI", "/efi", "/boot/efi"} {
		if exists(p) {
			targets = appendUniquePath(targets, seen, p)
		}
	}
	return targets
}

func appendUniquePath(items []string, seen map[string]bool, p string) []string {
	if seen[p] {
		return items
	}
	seen[p] = true
	return append(items, p)
}

// ThreatSignature describes a public, defensive hunting heuristic. It is deliberately
// broader than a family-name IOC and is never interpreted as proof of compromise.
type ThreatSignature struct {
	Family     string
	Technique  string
	Severity   string
	Confidence string
	Reference  string
	Keywords   []string
	MinHits    int
}

type threatArtifact struct {
	Location string
	Path     string
	Kind     string
	Data     []byte
	SHA512   string
}

func current2026MalwareSignatures() []ThreatSignature {
	return []ThreatSignature{
		{Family: "LoJax", Technique: "SPI/DXE persistence", Severity: "HIGH", Confidence: "medium", Reference: "ESET LoJax research", Keywords: []string{"lojax", "sednit", "rpcnetp"}, MinHits: 1},
		{Family: "MoonBounce", Technique: "CORE_DXE/boot-chain hook", Severity: "HIGH", Confidence: "medium", Reference: "Binarly UEFI bootkit research", Keywords: []string{"moonbounce", "core_dxe", "core.dxe"}, MinHits: 1},
		{Family: "CosmicStrand", Technique: "CSMCORE/DXE persistence", Severity: "HIGH", Confidence: "medium", Reference: "Binarly UEFI bootkit research", Keywords: []string{"cosmicstrand", "csmcore"}, MinHits: 1},
		{Family: "MosaicRegressor", Technique: "DXE + EFI application persistence", Severity: "HIGH", Confidence: "medium", Reference: "Binarly UEFI bootkit research", Keywords: []string{"mosaicregressor", "mosaic_regressor"}, MinHits: 1},
		{Family: "ESPecter", Technique: "ESP bootloader persistence / espionage", Severity: "HIGH", Confidence: "medium", Reference: "ESET ESPecter research", Keywords: []string{"especter", "bootmgfw.efi", "keylogging", "document stealing"}, MinHits: 1},
		{Family: "BlackLotus", Technique: "Secure Boot bypass / bootkit", Severity: "CRITICAL", Confidence: "medium", Reference: "ESET BlackLotus research", Keywords: []string{"blacklotus", "grubx64.efi", "secure boot bypass"}, MinHits: 1},
		{Family: "Bootkitty", Technique: "Linux UEFI bootkit / kernel integrity bypass", Severity: "HIGH", Confidence: "medium", Reference: "ESET Bootkitty research", Keywords: []string{"bootkitty", "bootkit.efi", "bcDropper", "bcDropper"}, MinHits: 1},
		{Family: "HybridPetya", Technique: "ESP bootkit / Secure Boot bypass", Severity: "CRITICAL", Confidence: "medium", Reference: "ESET HybridPetya research", Keywords: []string{"hybridpetya", "cloak.dat", "cve-2024-7344"}, MinHits: 1},
		{Family: "FinFisher/FinSpy", Technique: "ESP/boot persistence + espionage", Severity: "HIGH", Confidence: "medium", Reference: "ESET FinSpy/UEFI research", Keywords: []string{"finfisher", "finspy"}, MinHits: 1},
		{Family: "TrickBoot", Technique: "SPI firmware tampering", Severity: "HIGH", Confidence: "medium", Reference: "Eclypsium TrickBoot research", Keywords: []string{"trickboot", "spi flash", "flashrom"}, MinHits: 1},
		{Family: "MosaicRegressor", Technique: "EFI variable persistence", Severity: "HIGH", Confidence: "low", Reference: "public UEFI malware research", Keywords: []string{"efi_driver", "nvram", "efivars"}, MinHits: 2},
		{Family: "Secure Boot bypass - CVE-2024-7344", Technique: "vulnerable signed shim / bootloader", Severity: "CRITICAL", Confidence: "medium", Reference: "ESET CVE-2024-7344 research", Keywords: []string{"cve-2024-7344", "shim", "microsoft corporation uefi ca 2011"}, MinHits: 2},
		{Family: "Secure Boot bypass - vulnerable shim", Technique: "revoked/vulnerable third-party shim", Severity: "HIGH", Confidence: "low", Reference: "ESET 2026 forgotten-shims research", Keywords: []string{"shim", "shim 0.9", "shimx64.efi", "fallback.efi"}, MinHits: 1},
		{Family: "UEFI Shim <=0.9", Technique: "legacy signed shim exposure", Severity: "HIGH", Confidence: "medium", Reference: "ESET Research, 14 Jul 2026", Keywords: []string{"shim 0.9", "shim 0.8", "shim 0.7", "shim version 0.9", "version 0.9"}, MinHits: 1},
		{Family: "LogoFAIL / CVE-2023-40238", Technique: "UEFI image-parser exposure", Severity: "HIGH", Confidence: "low", Reference: "Binarly Bootkitty/LogoFAIL research", Keywords: []string{"logofail", "cve-2023-40238", "image parser", "image parsing"}, MinHits: 1},
		{Family: "BlackLotus / Baton Drop", Technique: "vulnerable boot-manager chain", Severity: "CRITICAL", Confidence: "medium", Reference: "ESET BlackLotus research", Keywords: []string{"cve-2022-21894", "bootmgfw.efi", "grubx64.efi", "moklist"}, MinHits: 2},
		{Family: "EfiGuard-style bootkit", Technique: "CR0 WP / CR4 CET manipulation", Severity: "HIGH", Confidence: "low", Reference: "Binarly 2025 UEFI bootkit hunting", Keywords: []string{"efiguard", "asmwritecr0", "asmdisablecet", "clear wp", "disable cet", "cr4"}, MinHits: 2},
		{Family: "Bootlicker / DmaBackdoorBoot-style", Technique: "pre-OS hook/shellcode execution", Severity: "HIGH", Confidence: "low", Reference: "Binarly 2025 UEFI bootkit hunting", Keywords: []string{"bootlicker", "dmabackdoorboot", "oslargtransfertokernel", "oslarchtransfertokernel", "shellcode", "keinsertqueueapc"}, MinHits: 2},
		{Family: "umap/SandboxBootkit-style", Technique: "bootloader hook + relocation/API resolution", Severity: "HIGH", Confidence: "low", Reference: "Binarly 2025 UEFI bootkit hunting", Keywords: []string{"umap", "sandboxbootkit", "bootkit.efi", "resolve api", "image_base_relocation", "image_export_directory"}, MinHits: 2},
		{Family: "PeiBackdoor-style implant", Technique: "PEI relocation/backdoor behavior", Severity: "HIGH", Confidence: "low", Reference: "Binarly 2025 UEFI bootkit hunting", Keywords: []string{"peibackdoor", "pei backdoor", "image_base_relocation", "relocation"}, MinHits: 2},
		{Family: "Vixen/EfiGuard-derived behavior", Technique: "PatchGuard/DSE bypass behavior", Severity: "HIGH", Confidence: "low", Reference: "Binarly 2025 UEFI bootkit hunting", Keywords: []string{"vixen.efi", "patchguard", "driver signature enforcement", "dse", "asmdisablecet"}, MinHits: 2},
		{Family: "Boot Services transfer-hook behavior", Technique: "ExitBootServices / kernel-transfer hook", Severity: "HIGH", Confidence: "low", Reference: "Binarly 2025 UEFI bootkit hunting", Keywords: []string{"exitbootservices", "oslarchtransfertokernel", "setvirtualaddressmap", "createevent", "event_group_virtual_address_change"}, MinHits: 2},
		{Family: "Kernel image-resolution behavior", Technique: "kernel API / relocation resolution", Severity: "MEDIUM", Confidence: "low", Reference: "Binarly 2025 UEFI bootkit hunting", Keywords: []string{"blimgloadpeimageex", "resolve api", "iat", "image_export_directory", "image_base_relocation"}, MinHits: 3},
		{Family: "Generic UEFI hook-chain bootkit", Technique: "Boot Services / ReadyToBoot hooks", Severity: "HIGH", Confidence: "low", Reference: "Binarly public UEFI bootkit hunting methodology", Keywords: []string{"createeventex", "ready_to_boot", "handleprotocol", "bootservices", "locateprotocol", "installprotocolinterface"}, MinHits: 3},
		{Family: "Firmware kernel-injection behavior", Technique: "CR0/WP + PE relocation/API resolution", Severity: "HIGH", Confidence: "low", Reference: "Binarly public UEFI bootkit behavior research", Keywords: []string{"cr0", "write protect", "image_base_relocation", "image_export_directory", "resolve api", "iat"}, MinHits: 3},
		{Family: "UEFI implant persistence", Technique: "EFI variable/runtime-service persistence", Severity: "HIGH", Confidence: "low", Reference: "public UEFI persistence research", Keywords: []string{"getvariable", "setvariable", "runtime services", "driver####", "moklist", "moknew"}, MinHits: 2},
		{Family: "Firmware network-capable implant", Technique: "UEFI networking + persistence", Severity: "HIGH", Confidence: "low", Reference: "public UEFI malware behavior research", Keywords: []string{"efi_http_protocol", "efi_tcp4_protocol", "efi_udp4_protocol", "getvariable", "setvariable"}, MinHits: 3},
	}
}

func current2026SpywareSignatures() []ThreatSignature {
	return []ThreatSignature{
		{Family: "ESPecter-style espionage", Technique: "keylogging + screenshot/document collection", Severity: "HIGH", Confidence: "medium", Reference: "ESET ESPecter research", Keywords: []string{"especter", "keylogging", "screenshot", "document stealing"}, MinHits: 1},
		{Family: "FinSpy-style firmware espionage", Technique: "boot persistence + surveillance", Severity: "HIGH", Confidence: "medium", Reference: "ESET FinSpy/UEFI research", Keywords: []string{"finspy", "finfisher", "keylog", "screenshot"}, MinHits: 1},
		{Family: "Credential collection", Technique: "credential/token capture", Severity: "HIGH", Confidence: "medium", Reference: "public surveillance-malware behavior", Keywords: []string{"credential", "password", "browser cookie", "session token", "private key"}, MinHits: 2},
		{Family: "Input capture", Technique: "keylogging / keyboard hooks", Severity: "HIGH", Confidence: "medium", Reference: "public surveillance-malware behavior", Keywords: []string{"keylog", "keystroke", "keyboard hook", "getasynckeystate", "setwindowshookex"}, MinHits: 2},
		{Family: "Screen capture", Technique: "screen/screenshot collection", Severity: "HIGH", Confidence: "medium", Reference: "public surveillance-malware behavior", Keywords: []string{"screenshot", "screen capture", "bitblt", "printscreen", "gop"}, MinHits: 2},
		{Family: "Clipboard collection", Technique: "clipboard capture", Severity: "MEDIUM", Confidence: "low", Reference: "public surveillance-malware behavior", Keywords: []string{"clipboard", "getclipboarddata", "cf_text"}, MinHits: 2},
		{Family: "Audio/video surveillance", Technique: "microphone/webcam access", Severity: "HIGH", Confidence: "low", Reference: "public surveillance-malware behavior", Keywords: []string{"microphone", "audio capture", "webcam", "camera capture"}, MinHits: 2},
	}
}

func threatBehaviorSignatures(mode string) []ThreatSignature {
	if mode == "MALWARE" {
		return current2026MalwareSignatures()
	}
	return current2026SpywareSignatures()
}

func malwareIndicatorKeywords() []string {
	return []string{
		"lojax", "moonbounce", "blacklotus", "mosaicregressor", "trickboot", "finfisher", "finspy",
		"cosmicstrand", "especter", "vector-edk", "uefi rootkit", "bootkit", "firmware rootkit",
		"smm rootkit", "dxe rootkit", "spi implant", "firmware implant",
	}
}

func spywareCollectionKeywords() []string {
	return []string{
		"keylog", "keylogger", "keystroke", "keyboard hook", "keyboard capture", "screenshot", "screen capture",
		"clipboard", "webcam", "camera capture", "microphone", "audio capture", "credential", "password",
		"browser cookie", "browser credential", "session token", "private key", "ssh key", "secret capture",
	}
}

func spywareExfilKeywords() []string {
	return []string{
		"http://", "https://", "user-agent", "post /", "dns", "tcp4", "tcp6", "udp4", "udp6",
		"simple network protocol", "efi_http_protocol", "efi_tcp4_protocol", "efi_udp4_protocol", "socket",
		"exfil", "upload", "beacon", "c2", "command and control",
	}
}

func persistenceKeywords() []string {
	return []string{"getvariable", "setvariable", "runtime services", "bootorder", "bootnext", "driver####", "sysprep####", "startup", "shell.efi"}
}

func containsAnyFold(s string, keys []string) (string, bool) {
	low := strings.ToLower(s)
	for _, k := range keys {
		if strings.Contains(low, strings.ToLower(k)) {
			return k, true
		}
	}
	return "", false
}

func countKeywordHits(stringsFound []string, keywords []string) map[string]int {
	counts := make(map[string]int)
	for _, text := range stringsFound {
		low := strings.ToLower(text)
		for _, kw := range keywords {
			if strings.Contains(low, strings.ToLower(kw)) {
				counts[kw]++
			}
		}
	}
	return counts
}

func joinKeys(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func extractPrintableStrings(data []byte, minLen, maxStrings int) []string {
	out := make([]string, 0, min(maxStrings, 256))
	flush := func(buf []byte) {
		if len(buf) >= minLen && len(out) < maxStrings {
			out = append(out, printable(string(buf)))
		}
	}
	cur := make([]byte, 0, 64)
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			cur = append(cur, b)
		} else {
			flush(cur)
			cur = cur[:0]
		}
	}
	flush(cur)
	// Also inspect UTF-16LE ASCII-ish strings because UEFI UI/metadata frequently uses UTF-16.
	cur = cur[:0]
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] >= 0x20 && data[i] <= 0x7e && data[i+1] == 0 {
			cur = append(cur, data[i])
		} else {
			flush(cur)
			cur = cur[:0]
		}
	}
	flush(cur)
	return out
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var e float64
	ln := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / ln
		e -= p * (math.Log(p) / math.Log(2))
	}
	return e
}

func addThreatHit(r *Report, report *ThreatScanReport, mode, kind, severity, confidence, location string, offset int64, indicator, context, method string) {
	addThreatHitEx(r, report, mode, kind, "", "", severity, confidence, location, offset, indicator, context, method, "")
}

func addThreatHitEx(r *Report, report *ThreatScanReport, mode, kind, family, technique, severity, confidence, location string, offset int64, indicator, context, method, reference string) {
	if report == nil {
		return
	}
	if report.seen == nil {
		report.seen = make(map[string]struct{})
	}
	keyLocation := location
	if strings.EqualFold(kind, "YARA") && offset >= 0 {
		keyLocation = "OFFSET"
	}
	key := fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s", strings.ToUpper(mode), strings.ToUpper(kind), keyLocation, offset, strings.ToLower(indicator), technique, method)
	if _, exists := report.seen[key]; exists {
		return
	}
	report.seen[key] = struct{}{}
	sev := strings.ToUpper(severity)
	conf := strings.ToLower(confidence)
	report.Hits = append(report.Hits, ThreatHit{Mode: mode, Kind: kind, Family: family, Technique: technique, Severity: sev, Confidence: conf, Location: location, Offset: offset, Indicator: indicator, Context: truncate(context, 1400), Method: method, Reference: reference})
	report.Indicators++
	if conf == "high" {
		report.HighConfidence++
	}
	if strings.EqualFold(kind, "YARA") {
		report.YARAMatches++
	} else if strings.Contains(strings.ToLower(kind), "struct") || strings.Contains(strings.ToLower(kind), "module") || strings.Contains(strings.ToLower(kind), "anomaly") || strings.Contains(strings.ToLower(kind), "entropy") {
		report.StructuralHits++
	} else {
		report.StringHits++
	}
	if report.FamilyHits == nil {
		report.FamilyHits = map[string]int{}
	}
	if report.TechniqueHits == nil {
		report.TechniqueHits = map[string]int{}
	}
	if family != "" {
		report.FamilyHits[family]++
	}
	if technique != "" {
		report.TechniqueHits[technique]++
	}
	add(r, fmt.Sprintf("%s-HIT-%03d", mode, report.Indicators), strings.ToLower(mode)+"-scan", indicator, WARN, sev, conf, fmt.Sprintf("location=%s | %s", location, truncate(context, 1600)), threatRemediation(family, technique), method+" | "+reference)
}

func scanPEForThreats(r *Report, report *ThreatScanReport, mode, location string, payload []byte) {
	if len(payload) < 64 {
		return
	}
	pf, err := pe.NewFile(bytes.NewReader(payload))
	if err != nil {
		return
	}
	defer pf.Close()
	// Executable + writable PE sections are a strong anomaly indicator in firmware images.
	const imageScnMemExecute = 0x20000000
	const imageScnMemWrite = 0x80000000
	for _, sec := range pf.Sections {
		if sec.Characteristics&imageScnMemExecute != 0 && sec.Characteristics&imageScnMemWrite != 0 {
			addThreatHit(r, report, mode, "PE-structure", "HIGH", "medium", location, -1,
				"writable+executable PE section", fmt.Sprintf("section=%s characteristics=0x%x", strings.TrimSpace(sec.Name), sec.Characteristics), "debug/pe section analysis")
		}
		lowName := strings.ToLower(strings.TrimSpace(sec.Name))
		if containsAny := []string{"upx", "packed", "encrypt", "crypt", "loader", "stage", "payload", "shellcode", "stub"}; strings.TrimSpace(lowName) != "" {
			for _, marker := range containsAny {
				if strings.Contains(lowName, marker) {
					addThreatHit(r, report, mode, "PE-structure", "MEDIUM", "low", location, -1, "suspicious PE section name", fmt.Sprintf("section=%s marker=%s", sec.Name, marker), "debug/pe section analysis")
					break
				}
			}
		}
	}
	// Presence of an Authenticode certificate table is evidence of a signing blob,
	// not proof that the certificate is trusted. Full verification is delegated to sbverify/pesign when available.
	var certSize uint32
	var certRVA uint32
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes > 4 {
			certRVA = oh.DataDirectory[4].VirtualAddress
			certSize = oh.DataDirectory[4].Size
		}
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes > 4 {
			certRVA = oh.DataDirectory[4].VirtualAddress
			certSize = oh.DataDirectory[4].Size
		}
	}
	if certRVA == 0 || certSize == 0 {
		// Firmware DXE binaries are not universally Authenticode-signed; treat as context only.
		addThreatHit(r, report, mode, "PE-signature", "LOW", "low", location, -1, "no PE certificate table", "absence of an embedded PE certificate is not proof of maliciousness", "debug/pe optional-header analysis")
	}
}

func analyzeThreatBytes(r *Report, report *ThreatScanReport, mode, location string, data []byte) {
	if len(data) == 0 {
		return
	}
	stringsFound := extractPrintableStrings(data, 5, 25000)

	// 2025/2026 public bootkit hunting concept: combine family-specific IOCs
	// with execution-region, hook, persistence, network and Secure Boot-bypass behavior.
	for _, sig := range threatBehaviorSignatures(mode) {
		counts := countKeywordHits(stringsFound, sig.Keywords)
		unique := len(counts)
		if unique < sig.MinHits {
			continue
		}
		indicator := sig.Family
		ctx := fmt.Sprintf("family=%s technique=%s keywords=[%s] unique_matches=%d", sig.Family, sig.Technique, joinKeys(counts), unique)
		addThreatHitEx(r, report, mode, "family-signature", sig.Family, sig.Technique, sig.Severity, sig.Confidence, location, -1, indicator, ctx, "2026 public UEFI threat hunting heuristics", sig.Reference)
	}

	// Malware-specific generic execution/persistence indicators.
	if mode == "MALWARE" {
		behavior := map[string][]string{
			"firmware-write": {"spi flash", "flashrom", "erase", "write enable", "program flash"},
			"runtime-hook":   {"getvariable", "setvariable", "getruntime", "setruntime", "runtime services", "locateprotocol", "installprotocolinterface"},
			"boot-hook":      {"loadimage", "startimage", "bootorder", "bootnext", "bootmgfw.efi", "grubx64.efi", "shimx64.efi"},
			"memory-hook":    {"hook", "trampoline", "inline patch", "patchkernel", "disable signature", "disable kernel"},
		}
		for technique, kws := range behavior {
			counts := countKeywordHits(stringsFound, kws)
			if len(counts) >= 2 {
				addThreatHitEx(r, report, mode, "behavior-correlation", "Generic UEFI bootkit", technique, "HIGH", "low", location, -1,
					"multi-indicator bootkit behavior", fmt.Sprintf("technique=%s keywords=[%s]", technique, joinKeys(counts)),
					"2026 public UEFI behavior hunting", "Binarly 2025 UEFI bootkit hunting methodology")
			}
		}
	}

	// Spyware hunting is deliberately correlation-oriented: collection alone is not spyware.
	if mode == "SPYWARE" {
		collection := []string{"keylog", "keylogger", "keystroke", "keyboard hook", "screenshot", "screen capture", "clipboard", "credential", "password", "browser cookie", "session token", "private key", "microphone", "webcam"}
		network := []string{"efi_http_protocol", "efi_tcp4_protocol", "efi_udp4_protocol", "efi_dns4_protocol", "simple network protocol", "socket", "connect", "send", "http://", "https://", "beacon", "c2", "exfil", "upload"}
		persist := []string{"getvariable", "setvariable", "runtime services", "bootorder", "bootnext", "loadimage", "startimage", "driver####", "sysprep####"}
		c := countKeywordHits(stringsFound, collection)
		n := countKeywordHits(stringsFound, network)
		p := countKeywordHits(stringsFound, persist)
		if len(c) >= 2 && len(n) >= 1 {
			addThreatHitEx(r, report, mode, "behavior-correlation", "UEFI surveillance", "collection + network exfiltration", "HIGH", "medium", location, -1,
				"surveillance collection + network", fmt.Sprintf("collection=[%s] network=[%s]", joinKeys(c), joinKeys(n)), "2026 public surveillance behavior hunting", "ESET ESPecter/FinSpy public research")
		}
		if len(c) >= 2 && len(p) >= 1 {
			addThreatHitEx(r, report, mode, "behavior-correlation", "UEFI surveillance", "collection + persistence", "HIGH", "low", location, -1,
				"surveillance collection + persistence", fmt.Sprintf("collection=[%s] persistence=[%s]", joinKeys(c), joinKeys(p)), "2026 public surveillance behavior hunting", "ESET ESPecter/FinSpy public research")
		}
		if len(n) >= 2 && len(p) >= 1 {
			addThreatHitEx(r, report, mode, "behavior-correlation", "UEFI surveillance", "network + persistence", "MEDIUM", "low", location, -1,
				"network + persistence", fmt.Sprintf("network=[%s] persistence=[%s]", joinKeys(n), joinKeys(p)), "2026 public surveillance behavior hunting", "public UEFI network/persistence analysis")
		}
	}

	// Public behavior-hunting technique: look for low-level primitives used by some
	// bootkits, but require contextual corroboration because these instructions can
	// also occur legitimately in firmware.
	if mode == "MALWARE" {
		cr0Access := bytes.Contains(data, []byte{0x0f, 0x20, 0xc0}) || bytes.Contains(data, []byte{0x0f, 0x22, 0xc0})
		wrmsr := bytes.Contains(data, []byte{0x0f, 0x30})
		if cr0Access && wrmsr {
			addThreatHitEx(r, report, mode, "binary-behavior", "Firmware code-modification primitive", "CR0/MSR manipulation capability", "MEDIUM", "low", location, -1, "CR0 + WRMSR low-level primitive combination", "raw byte heuristic; legitimate low-level firmware can use these instructions", "x86 opcode heuristic", "public UEFI bootkit behavior research")
		}
	}

	// Structural analysis is common to both modes.
	prefix := payloadPrefix(data, 2*1024*1024)
	if isPEImage(prefix) {
		scanPEForThreats(r, report, mode, location, prefix)
	}
	ent := shannonEntropy(payloadPrefix(data, min(len(data), 4*1024*1024)))
	if ent >= 7.85 && len(data) >= 4096 {
		addThreatHitEx(r, report, mode, "structural-entropy", "Generic", "packed/encrypted-content", "MEDIUM", "low", location, -1,
			"high-entropy executable/raw content", fmt.Sprintf("entropy=%.3f bytes=%d; compressed/encrypted firmware content can also be legitimate", ent, len(data)),
			"Shannon entropy heuristic", "public firmware triage methodology")
	}
}

func payloadPrefix(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

func threatRuleRating(rule, mode string) (string, string) {
	low := strings.ToLower(rule)
	for _, x := range []string{"blacklotus", "hybridpetya", "bootkitty", "lojax", "moonbounce", "cosmicstrand", "especter", "finspy", "finfisher"} {
		if strings.Contains(low, x) {
			if strings.Contains(low, "blacklotus") || strings.Contains(low, "hybridpetya") {
				return "CRITICAL", "medium"
			}
			return "HIGH", "medium"
		}
	}
	if strings.Contains(low, "shim") || strings.Contains(low, "cve_2024_7344") {
		return "HIGH", "low"
	}
	if strings.Contains(low, "spyware") || mode == "SPYWARE" {
		return "HIGH", "low"
	}
	return "MEDIUM", "low"
}

func classifyThreatRuleName(rule, mode string) (family, technique, reference string) {
	low := strings.ToLower(rule)
	cases := []struct{ needle, family, technique, ref string }{
		{"lojax", "LoJax", "SPI/DXE persistence", "public ESET/Binarly UEFI research"},
		{"moonbounce", "MoonBounce", "CORE_DXE persistence", "public UEFI bootkit research"},
		{"cosmicstrand", "CosmicStrand", "CSMCORE/DXE persistence", "public UEFI bootkit research"},
		{"mosaic", "MosaicRegressor", "DXE/EFI persistence", "public UEFI bootkit research"},
		{"especter", "ESPecter", "ESP bootkit + espionage", "ESET ESPecter research"},
		{"blacklotus", "BlackLotus", "Secure Boot bypass / bootkit", "ESET BlackLotus research"},
		{"bootkitty", "Bootkitty", "Linux UEFI bootkit", "ESET Bootkitty research"},
		{"hybridpetya", "HybridPetya", "ESP bootkit / Secure Boot bypass", "ESET HybridPetya research"},
		{"finspy", "FinSpy", "boot persistence / espionage", "ESET FinSpy research"},
		{"trickboot", "TrickBoot", "SPI firmware tampering", "Eclypsium TrickBoot research"},
		{"shim", "UEFI shim", "Secure Boot bypass exposure", "ESET 2026 forgotten-shims research"},
		{"logofail", "LogoFAIL / CVE-2023-40238", "UEFI image-parser exposure", "Binarly public LogoFAIL research"},
		{"hookchain", "Generic UEFI hook-chain bootkit", "Boot Services / ReadyToBoot hook chain", "Binarly public UEFI bootkit hunting methodology"},
		{"persistence", "UEFI implant persistence", "EFI variable/runtime-service persistence", "public UEFI persistence research"},
	}
	for _, c := range cases {
		if strings.Contains(low, c.needle) {
			return c.family, c.technique, c.ref
		}
	}
	if mode == "SPYWARE" {
		return "UEFI surveillance", "spyware behavior", "public surveillance-malware research"
	}
	return "Generic UEFI threat", "static indicator", "public UEFI threat hunting"
}

func scanYARABuffer(r *Report, report *ThreatScanReport, mode, ruleFile, label string, absoluteOffset int64, data []byte) {
	if _, err := exec.LookPath("yara"); err != nil || len(data) == 0 {
		return
	}
	f, err := os.CreateTemp("", "sl0ppy-uefi-yara-*.bin")
	if err != nil {
		return
	}
	path := f.Name()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return
	}
	_ = f.Close()
	defer os.Remove(path)
	out, _ := run("yara", "-s", ruleFile, path)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "warning:") {
			continue
		}
		if strings.Contains(line, ": $") || strings.Contains(line, " $") {
			m := parseYARAMatchLine(line, ruleFile)
			m.File = label
			if m.Offset >= 0 && absoluteOffset >= 0 {
				m.Offset += absoluteOffset
			}
			r.Matches = append(r.Matches, m)
			family, technique, ref := classifyThreatRuleName(m.Rule, mode)
			sev, conf := threatRuleRating(m.Rule, mode)
			addThreatHitEx(r, report, mode, "YARA", family, technique, sev, conf, m.File, m.Offset, m.Rule, oneLine(line, 1000), "yara -s (extracted firmware module)", ref)
		}
	}
}

func scanYARAFile(r *Report, report *ThreatScanReport, mode, ruleFile, target string) {
	if _, err := exec.LookPath("yara"); err != nil {
		return
	}
	out, _ := run("yara", "-s", "-r", ruleFile, target)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "warning:") {
			continue
		}
		if strings.Contains(line, ": $") || strings.Contains(line, " $") {
			m := parseYARAMatchLine(line, ruleFile)
			r.Matches = append(r.Matches, m)
			family, technique, ref := classifyThreatRuleName(m.Rule, mode)
			sev, conf := threatRuleRating(m.Rule, mode)
			addThreatHitEx(r, report, mode, "YARA", family, technique, sev, conf, m.File, m.Offset, m.Rule, oneLine(line, 1000), "yara -s", ref)
		}
	}
}

func embedded2026YARARules() (string, string) {
	malware := `
rule UEFI_Bootkitty_2026_Indicators {
 meta:
  description = "Public defensive indicators for the Bootkitty Linux UEFI bootkit"
  severity = "HIGH"
  reference = "ESET public Bootkitty research"
 strings:
  $a = "bootkitty" nocase
  $b = "bootkit.efi" nocase
  $c = "BCDropper" nocase
  $d = "disable kernel signature" nocase
 condition:
  1 of them
}
rule UEFI_HybridPetya_2026_Indicators {
 meta:
  description = "Public defensive indicators for HybridPetya UEFI bootkit behavior"
  severity = "CRITICAL"
  reference = "ESET public HybridPetya research"
 strings:
  $a = "HybridPetya" nocase
  $b = "cloak.dat" nocase
  $c = "CVE-2024-7344" nocase
 condition:
  1 of them
}
rule UEFI_CVE_2024_7344_Shim_Exposure {
 meta:
  description = "Potential Secure Boot bypass exposure through affected signed UEFI shim/bootloader artifacts"
  severity = "CRITICAL"
  reference = "ESET CVE-2024-7344 research"
 strings:
  $a = "shim" nocase
  $b = "shimx64.efi" nocase
  $c = "Microsoft Corporation UEFI CA 2011" nocase wide ascii
  $d = "CVE-2024-7344" nocase
 condition:
  2 of them
}
rule UEFI_Vulnerable_Shim_2026_Indicators {
 meta:
  description = "Potential old/vulnerable UEFI shim artifact associated with 2026 Secure Boot revocation research"
  severity = "HIGH"
  reference = "ESET July 2026 forgotten-shims research"
 strings:
  $a = "shimx64.efi" nocase
  $b = "shim 0.9" nocase
  $c = "version 0.9" nocase
  $d = "fallback.efi" nocase
 condition:
  1 of them
}
rule UEFI_ESPecter_2026_Hunting {
 meta:
  description = "Defensive hunting indicators for ESPecter-style ESP persistence and surveillance"
  severity = "HIGH"
  reference = "ESET ESPecter public research"
 strings:
  $a = "especter" nocase
  $b = "bootmgfw.efi" nocase
  $c = "keylogging" nocase
  $d = "screenshot" nocase
  $e = "document stealing" nocase
 condition:
  2 of them
}
rule UEFI_Bootkit_HookChain_2026 {
 meta:
  description = "Generic public defensive UEFI bootkit behavior: Boot Services / ReadyToBoot hooks"
  severity = "HIGH"
  reference = "Binarly public UEFI bootkit hunting methodology"
 strings:
  $a = "CreateEventEx" nocase
  $b = "ReadyToBoot" nocase
  $c = "HandleProtocol" nocase
  $d = "LocateProtocol" nocase
  $e = "InstallProtocolInterface" nocase
 condition:
  3 of them
}
rule UEFI_Bootkit_CodeBehavior_2026 {
 meta:
  description = "Public behavior-oriented UEFI bootkit hunting: CR0/CR4 and boot transfer hooks"
  severity = "HIGH"
  reference = "Binarly 2025 UEFI bootkit hunting methodology"
 strings:
  $a = "ExitBootServices" nocase
  $b = "OslArchTransferToKernel" nocase
  $c = "SetVirtualAddressMap" nocase
  $d = "AsmWriteCr0" nocase
  $e = "AsmDisableCet" nocase
  $f = "BlImgLoadPEImageEx" nocase
 condition:
  2 of them
}
rule UEFI_Bootkit_Relocation_API_2026 {
 meta:
  description = "Public behavior-oriented bootkit hunting: relocation and API resolution"
  severity = "MEDIUM"
  reference = "Binarly 2025 UEFI bootkit hunting methodology"
 strings:
  $a = "IMAGE_BASE_RELOCATION" nocase
  $b = "IMAGE_EXPORT_DIRECTORY" nocase
  $c = "ResolveApi" nocase
  $d = "resolve api" nocase
  $e = "IAT" ascii
 condition:
  3 of them
}
rule UEFI_Bootkit_Persistence_2026 {
 meta:
  description = "Generic public defensive UEFI persistence behavior"
  severity = "HIGH"
  reference = "public UEFI persistence research"
 strings:
  $a = "GetVariable" nocase
  $b = "SetVariable" nocase
  $c = "Runtime Services" nocase
  $d = "Driver####" nocase
  $e = "MokList" nocase
 condition:
  2 of them
}
rule UEFI_LogoFAIL_2026 {
 meta:
  description = "Public defensive indicator for LogoFAIL/CVE-2023-40238 exposure context"
  severity = "HIGH"
  reference = "Binarly public Bootkitty/LogoFAIL research"
 strings:
  $a = "LogoFAIL" nocase
  $b = "CVE-2023-40238" nocase
  $c = "image parser" nocase
 condition:
  1 of them
}
`
	spyware := `
rule UEFI_Spyware_Keylogging_2026 {
 meta:
  description = "Public defensive EFI spyware hunting: keylogging/input capture"
  severity = "HIGH"
 strings:
  $a = "keylog" nocase
  $b = "keylogger" nocase
  $c = "keystroke" nocase
  $d = "GetAsyncKeyState" nocase
  $e = "SetWindowsHookEx" nocase
 condition:
  2 of them
}
rule UEFI_Spyware_ScreenCapture_2026 {
 meta:
  description = "Public defensive EFI spyware hunting: screen capture"
  severity = "HIGH"
 strings:
  $a = "screenshot" nocase
  $b = "screen capture" nocase
  $c = "BitBlt" nocase
  $d = "PrintScreen" nocase
 condition:
  2 of them
}
rule UEFI_Spyware_Credential_2026 {
 meta:
  description = "Public defensive surveillance hunting: credential/session collection"
  severity = "HIGH"
 strings:
  $a = "credential" nocase
  $b = "password" nocase
  $c = "browser cookie" nocase
  $d = "session token" nocase
  $e = "private key" nocase
 condition:
  2 of them
}
rule UEFI_Spyware_UEFINetwork_2026 {
 meta:
  description = "Public defensive surveillance hunting: EFI network + collection/exfiltration"
  severity = "HIGH"
 strings:
  $a = "EFI_HTTP_PROTOCOL" nocase
  $b = "EFI_TCP4_PROTOCOL" nocase
  $c = "EFI_UDP4_PROTOCOL" nocase
  $d = "EFI_DNS4_PROTOCOL" nocase
  $e = "exfil" nocase
  $f = "beacon" nocase
  $g = "command and control" nocase
 condition:
  2 of them
}
`
	return malware, spyware
}

func prepareThreatRules() (string, string, error) {
	if err := os.MkdirAll(YaraRulesDir, 0750); err != nil {
		return "", "", err
	}
	var malware strings.Builder
	currentMalware, currentSpyware := embedded2026YARARules()
	malware.WriteString(currentMalware)
	malware.WriteString("\n")
	for name, rule := range enhancedYaraRules {
		if strings.Contains(strings.ToLower(name), "spy") {
			continue
		}
		malware.WriteString(rule)
		malware.WriteString("\n")
	}
	malPath := filepath.Join(YaraRulesDir, "sl0ppy_malware_v10.4.yar")
	spyPath := filepath.Join(YaraRulesDir, "sl0ppy_spyware_v10.4.yar")
	if err := os.WriteFile(malPath, []byte(malware.String()), 0640); err != nil {
		return "", "", err
	}
	var spy strings.Builder
	spy.WriteString(currentSpyware)
	spy.WriteString("\n")
	for _, rule := range embeddedSpywareYaraRules {
		spy.WriteString(rule)
		spy.WriteString("\n")
	}
	if err := os.WriteFile(spyPath, []byte(spy.String()), 0640); err != nil {
		return "", "", err
	}
	return malPath, spyPath, nil
}

func scanEFIFileTree(r *Report, report *ThreatScanReport, mode string) {
	for _, root := range []string{"/boot/efi/EFI", "/efi/EFI"} {
		if !exists(root) {
			continue
		}
		_ = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || info.Size() <= 0 || (cfg.MaxFile > 0 && info.Size() > cfg.MaxFile) {
				return nil
			}
			low := strings.ToLower(path)
			if !(strings.HasSuffix(low, ".efi") || strings.HasSuffix(low, ".efi.signed") || strings.Contains(filepath.Base(low), "shell")) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			report.Artifacts++
			analyzeThreatBytes(r, report, mode, path, data)
			return nil
		})
	}
}

func scanEFIVariablesForThreats(r *Report, report *ThreatScanReport, mode string) {
	root := "/sys/firmware/efi/efivars"
	if !exists(root) {
		return
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		st, err := e.Info()
		if err != nil || st.IsDir() || st.Size() <= 0 || st.Size() > cfg.MaxFile {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		report.Artifacts++
		payload := b
		if len(payload) > 4 {
			payload = payload[4:]
		}
		analyzeThreatBytes(r, report, mode, "efivar:"+e.Name(), payload)
	}
}

func scanParsedFirmwareModules(r *Report, report *ThreatScanReport, mode string) {
	if r.FirmwareImage == nil || r.FirmwareImage.Path == "" || !exists(r.FirmwareImage.Path) {
		return
	}
	data, _, _, err := readFirmwareImage(r.FirmwareImage.Path)
	if err != nil {
		return
	}
	for _, v := range r.FirmwareVolumes {
		for _, f := range v.FilesDetail {
			if f.Size < f.HeaderSize || f.Offset+f.Size > uint64(len(data)) {
				continue
			}
			start := f.Offset + f.HeaderSize
			end := f.Offset + f.Size
			if start >= end || end > uint64(len(data)) {
				continue
			}
			payload := data[start:end]
			report.Artifacts++
			analyzeThreatBytes(r, report, mode, fmt.Sprintf("FV@0x%x/FFS@0x%x/%s/%s", v.Offset, f.Offset, f.TypeName, f.NameGUID), payload)
			for _, sec := range f.Sections {
				if sec.Size < 4 || sec.Offset < f.Offset || sec.Offset+sec.Size > uint64(len(data)) {
					continue
				}
				so := sec.Offset
				se := sec.Offset + sec.Size
				if so >= se {
					continue
				}
				sectionData := data[so:se]
				if sec.TypeName == "PE32" || sec.TypeName == "TE" || sec.PECOFF {
					analyzeThreatBytes(r, report, mode, fmt.Sprintf("FV@0x%x/FFS@0x%x/SECTION@0x%x/%s", v.Offset, f.Offset, sec.Offset, sec.TypeName), sectionData)
				}
			}
		}
	}
}

func runThreatScan(r *Report, mode string) *ThreatScanReport {
	profile := "2026-public-UEFI-bootkit-rootkit-hunt"
	if mode == "SPYWARE" {
		profile = "2026-public-UEFI-surveillance-hunt"
	}
	report := &ThreatScanReport{Enabled: true, Profile: profile, seen: map[string]struct{}{}, seenArtifacts: map[string]struct{}{}, FamilyHits: map[string]int{}, TechniqueHits: map[string]int{}}
	if err := ensureThreatFirmwareImage(r); err != nil {
		report.CoverageGaps = append(report.CoverageGaps, "firmware-image acquisition/parser unavailable: "+err.Error())
	}
	artifacts := collectThreatArtifacts(r)
	report.Targets = len(artifacts)
	report.UniqueArtifacts = len(artifacts)
	rawAvailable := false
	for _, a := range artifacts {
		if a.Kind == "RAW-FIRMWARE" {
			rawAvailable = true
		}
		key := mode + "|" + a.Location + "|" + a.SHA512
		if _, ok := report.seenArtifacts[key]; ok {
			continue
		}
		report.seenArtifacts[key] = struct{}{}
		report.Artifacts++
		analyzeThreatBytes(r, report, mode, a.Location, a.Data)
	}
	huntParsedFirmwareModules(r, report, mode)
	if malPath, spyPath, err := prepareThreatRules(); err == nil {
		if _, err := exec.LookPath("yara"); err == nil {
			rulePath := malPath
			if mode == "SPYWARE" {
				rulePath = spyPath
			}
			for _, a := range artifacts {
				if a.Path != "" {
					scanYARAFile(r, report, mode, rulePath, a.Path)
				}
			}
			if strings.TrimSpace(cfg.YaraDir) != "" {
				for _, ext := range []string{"*.yar", "*.yara"} {
					files, _ := filepath.Glob(filepath.Join(cfg.YaraDir, ext))
					for _, rf := range files {
						for _, a := range artifacts {
							if a.Path != "" {
								scanYARAFile(r, report, mode, rf, a.Path)
							}
						}
					}
				}
			}
		} else {
			report.CoverageGaps = append(report.CoverageGaps, "yara not installed; embedded static/behavioral hunting remained active")
		}
	} else {
		report.CoverageGaps = append(report.CoverageGaps, "embedded YARA rule preparation failed")
	}
	threatBaselineDifferential(r, report, mode)
	threatTrustAndBootChainHunt(r, report, mode)
	finalizeThreatScan(r, report, mode, rawAvailable)
	return report
}

func ensureThreatFirmwareImage(r *Report) error {
	if r.FirmwareImage != nil && len(r.FirmwareVolumes) > 0 {
		return nil
	}
	path := strings.TrimSpace(cfg.FirmwareImage)
	if path == "" && runtimeFirmwareImage != "" {
		path = runtimeFirmwareImage
	}
	if path == "" && cfg.UseFlashrom {
		if _, err := exec.LookPath("flashrom"); err != nil {
			return fmt.Errorf("flashrom is not installed")
		}
		f, err := os.CreateTemp("", "sl0ppy-threat-spi-*.bin")
		if err != nil {
			return err
		}
		path = f.Name()
		if err := f.Close(); err != nil {
			_ = os.Remove(path)
			return err
		}
		if out, err := run("flashrom", "-p", "internal", "-r", path); err != nil {
			_ = os.Remove(path)
			return fmt.Errorf("read-only flashrom acquisition failed: %s", truncate(out, 1200))
		}
		runtimeFirmwareImage = path
	}
	if path == "" {
		return nil
	}
	data, size, sha, err := readFirmwareImage(path)
	if err != nil {
		return err
	}
	volumes, _ := parseUEFIFirmwareVolumes(data, 10000, 256)
	r.FirmwareImage = &FirmwareImageEvidence{Source: "dedicated threat-hunt acquisition", Path: path, Size: size, SHA512: sha, FirmwareVolumes: len(volumes), Parser: "sl0ppy-UEFIScan UEFI PI FV/FFS/section parser"}
	r.FirmwareVolumes = append(r.FirmwareVolumes[:0], volumes...)
	return nil
}

func collectThreatArtifacts(r *Report) []threatArtifact {
	seen := map[string]bool{}
	var out []threatArtifact
	addFile := func(path, kind string, max int64) {
		if path == "" || seen[path] {
			return
		}
		st, err := os.Stat(path)
		if err != nil || st.IsDir() || st.Size() <= 0 || (max > 0 && st.Size() > max) {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		seen[path] = true
		out = append(out, threatArtifact{Location: path, Path: path, Kind: kind, Data: b, SHA512: hashBytes(b)})
	}
	if cfg.FirmwareImage != "" {
		addFile(cfg.FirmwareImage, "RAW-FIRMWARE", cfg.MaxFirmwareImage)
	} else if runtimeFirmwareImage != "" {
		addFile(runtimeFirmwareImage, "RAW-FIRMWARE", cfg.MaxFirmwareImage)
	} else if r.FirmwareImage != nil {
		addFile(r.FirmwareImage.Path, "RAW-FIRMWARE", cfg.MaxFirmwareImage)
	}
	for _, root := range []string{"/boot/efi/EFI", "/efi/EFI", "/boot/efi"} {
		if !exists(root) {
			continue
		}
		_ = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || info.Size() <= 0 || (cfg.MaxFile > 0 && info.Size() > cfg.MaxFile) {
				return nil
			}
			addFile(path, "ESP-FILE", cfg.MaxFile)
			return nil
		})
	}
	if exists("/sys/firmware/efi/efivars") {
		_ = filepath.Walk("/sys/firmware/efi/efivars", func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || info.Size() <= 4 || (cfg.MaxFile > 0 && info.Size() > cfg.MaxFile) {
				return nil
			}
			addFile(path, "EFI-VARIABLE", cfg.MaxFile)
			return nil
		})
	}
	return out
}

func huntNestedFirmwareVolumes(r *Report, report *ThreatScanReport, mode string, data []byte, parentLocation string, depth int, seen map[string]struct{}) {
	if depth > 2 || len(data) < fvHeaderMinimumSize {
		return
	}
	vols, _ := parseUEFIFirmwareVolumes(data, 2048, 128)
	for _, v := range vols {
		report.NestedFirmwareVolumes++
		for _, f := range v.FilesDetail {
			key := fmt.Sprintf("%d:0x%x:%s:%s", depth, f.Offset, f.NameGUID, f.SHA512)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if f.Offset+f.Size > uint64(len(data)) || f.HeaderSize > f.Size {
				continue
			}
			start := f.Offset + f.HeaderSize
			end := f.Offset + f.Size
			if start >= end || end > uint64(len(data)) {
				continue
			}
			loc := fmt.Sprintf("%s/FV@0x%x/FFS@0x%x[%s]", parentLocation, v.Offset, f.Offset, f.NameGUID)
			payload := data[start:end]
			analyzeThreatBytes(r, report, mode, loc, payload)
			for _, sec := range f.Sections {
				if sec.PayloadOffset < uint64(len(data)) && sec.Offset+sec.Size <= uint64(len(data)) && sec.PayloadOffset <= sec.Offset+sec.Size {
					sp := data[sec.PayloadOffset : sec.Offset+sec.Size]
					if sec.TypeName == "FV_IMAGE" && len(sp) >= fvHeaderMinimumSize {
						huntNestedFirmwareVolumes(r, report, mode, sp, loc+fmt.Sprintf("/FV_IMAGE@0x%x", sec.Offset), depth+1, seen)
					}
				}
			}
		}
	}
}

func verifyFirmwareModuleSignature(report *ThreatScanReport, location string, payload []byte) {
	if len(payload) < 64 || !isPEImage(payload) {
		return
	}
	if _, err := exec.LookPath("sbverify"); err != nil {
		report.SignatureUnknown++
		return
	}
	f, err := os.CreateTemp("", "sl0ppy-uefi-sig-*.efi")
	if err != nil {
		report.SignatureUnknown++
		return
	}
	path := f.Name()
	if _, err = f.Write(payload); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		report.SignatureUnknown++
		return
	}
	_ = f.Close()
	defer os.Remove(path)
	out, err := run("sbverify", "--list", path)
	low := strings.ToLower(out)
	if err == nil && (strings.Contains(low, "signature") || strings.Contains(low, "signer") || strings.Contains(low, "certificate")) {
		report.SignatureVerified++
		return
	}
	if strings.Contains(low, "no signature") || strings.Contains(low, "no signatures") || strings.Contains(low, "unsigned") {
		report.SignatureUnknown++
		return
	}
	if err != nil && strings.TrimSpace(out) != "" {
		report.SignatureInvalid++
		return
	}
	report.SignatureUnknown++
}

func huntParsedFirmwareModules(r *Report, report *ThreatScanReport, mode string) {
	if r.FirmwareImage == nil || r.FirmwareImage.Path == "" || len(r.FirmwareVolumes) == 0 || !exists(r.FirmwareImage.Path) {
		report.CoverageGaps = append(report.CoverageGaps, "no parsed raw firmware FV/FFS inventory; hidden DXE/SMM implants in SPI flash cannot be fully assessed")
		return
	}
	data, _, _, err := readFirmwareImage(r.FirmwareImage.Path)
	if err != nil {
		report.CoverageGaps = append(report.CoverageGaps, "raw firmware image unavailable to module hunter")
		return
	}
	seenNested := map[string]struct{}{}
	moduleLimit := 0
	var embeddedRulePath string
	if malPath, spyPath, err := prepareThreatRules(); err == nil {
		if mode == "MALWARE" {
			embeddedRulePath = malPath
		} else {
			embeddedRulePath = spyPath
		}
	}
	for _, v := range r.FirmwareVolumes {
		for _, f := range v.FilesDetail {
			if f.Size < f.HeaderSize || f.Offset+f.Size > uint64(len(data)) {
				continue
			}
			start, end := f.Offset+f.HeaderSize, f.Offset+f.Size
			if start >= end {
				continue
			}
			report.FirmwareModules++
			payload := data[start:end]
			moduleLimit++
			loc := fmt.Sprintf("firmware:FV@0x%x/FFS@0x%x[%s]", v.Offset, f.Offset, f.NameGUID)
			if moduleLimit <= 512 {
				verifyFirmwareModuleSignature(report, loc, payload)
				if embeddedRulePath != "" && (f.ExecutionClass == "DXE" || f.ExecutionClass == "SMM/MM" || f.ExecutionClass == "PEI") {
					scanYARABuffer(r, report, mode, embeddedRulePath, loc, int64(f.Offset+f.HeaderSize), payloadPrefix(payload, 16*1024*1024))
				}
			}
			stringsFound := extractPrintableStrings(payloadPrefix(payload, 4*1024*1024), 5, 14000)
			hooks := countKeywordHits(stringsFound, []string{"createeventex", "ready_to_boot", "event_group_ready_to_boot", "handleprotocol", "bootservices", "locateprotocol", "installprotocolinterface"})
			persist := countKeywordHits(stringsFound, persistenceKeywords())
			net := countKeywordHits(stringsFound, []string{"efi_http_protocol", "efi_tcp4_protocol", "efi_udp4_protocol", "efi_dns4_protocol", "simple network protocol", "http://", "https://", "beacon", "c2"})
			collect := countKeywordHits(stringsFound, append(spywareCollectionKeywords(), []string{"document stealing", "browser cookie"}...))
			secTypes := []string{}
			hasExec, hasEncap := false, false
			for _, sec := range f.Sections {
				secTypes = append(secTypes, sec.TypeName)
				if sec.PECOFF || sec.TypeName == "PE32" || sec.TypeName == "TE" {
					hasExec = true
				}
				if sec.TypeName == "COMPRESSION" || sec.TypeName == "GUID_DEFINED" || sec.TypeName == "FV_IMAGE" {
					hasEncap = true
				}
			}
			loc = fmt.Sprintf("firmware:FV@0x%x/FFS@0x%x/%s/%s", v.Offset, f.Offset, f.ExecutionClass, f.NameGUID)
			if mode == "MALWARE" {
				if hasExec && len(hooks) >= 3 && len(persist) >= 1 {
					addThreatHitEx(r, report, mode, "module-behavior", "Generic UEFI hook-chain bootkit", "Boot Services/ReadyToBoot hook + persistence", "HIGH", "medium", loc, int64(f.Offset), "boot-service hook chain", fmt.Sprintf("hooks=[%s] persistence=[%s] sections=%s", joinKeys(hooks), joinKeys(persist), strings.Join(uniqueStrings(secTypes), ",")), "FV/FFS module behavior analysis", "Binarly public UEFI bootkit-hunting methodology")
				}
				if f.ExecutionClass == "SMM/MM" && hasExec && (len(net) > 0 || len(persist) > 0) {
					report.ModuleAnomalies++
					addThreatHitEx(r, report, mode, "module-anomaly", "Potential SMM-resident implant", "SMM/MM executable module with network/persistence indicators", "HIGH", "low", loc, int64(f.Offset), "SMM/MM implant-like behavior", fmt.Sprintf("network=%s persistence=%s sections=%s", joinKeys(net), joinKeys(persist), strings.Join(uniqueStrings(secTypes), ",")), "FV/FFS execution-class analysis", "public SMM/UEFI implant hunting")
				}
				if hasExec && f.Name == "" && (len(hooks) >= 2 || len(persist) >= 2 || len(net) >= 2) {
					report.ModuleAnomalies++
					addThreatHitEx(r, report, mode, "module-anomaly", "Hidden executable firmware module", "executable module without UI metadata plus behavior indicators", "MEDIUM", "low", loc, int64(f.Offset), "hidden executable firmware module", fmt.Sprintf("class=%s hooks=%d persistence=%d network=%d", f.ExecutionClass, len(hooks), len(persist), len(net)), "FV/FFS structural + behavioral analysis", "public UEFI forensic methodology")
				}
				if hasEncap && (len(hooks) >= 2 || len(persist) >= 2 || len(net) >= 2) {
					addThreatHitEx(r, report, mode, "encapsulation-anomaly", "Encapsulated firmware payload", "compressed/GUID-defined/FV_IMAGE section with behavioral indicators", "MEDIUM", "low", loc, int64(f.Offset), "encapsulated firmware payload", fmt.Sprintf("sections=%s hooks=%d persistence=%d network=%d", strings.Join(uniqueStrings(secTypes), ","), len(hooks), len(persist), len(net)), "FV/FFS section analysis", "UEFI PI firmware-volume structure")
				}
			}
			if mode == "SPYWARE" && hasExec && len(collect) >= 2 && (len(net) >= 1 || len(persist) >= 1) {
				addThreatHitEx(r, report, mode, "module-behavior", "UEFI surveillance implant", "collection + firmware persistence/network behavior", "HIGH", "medium", loc, int64(f.Offset), "collection + persistence/network", fmt.Sprintf("collection=[%s] persistence=[%s] network=[%s]", joinKeys(collect), joinKeys(persist), joinKeys(net)), "FV/FFS module behavior analysis", "public UEFI surveillance research")
			}
		}
	}
	// Scan nested FV_IMAGE containers separately. This catches firmware modules that are hidden inside nested firmware volumes without duplicating the normal top-level parser check.
	for _, v := range r.FirmwareVolumes {
		for _, f := range v.FilesDetail {
			if f.Offset+f.Size > uint64(len(data)) || f.HeaderSize > f.Size {
				continue
			}
			for _, sec := range f.Sections {
				if sec.TypeName != "FV_IMAGE" || sec.PayloadOffset+1 > uint64(len(data)) || sec.Offset+sec.Size > uint64(len(data)) || sec.PayloadOffset > sec.Offset+sec.Size {
					continue
				}
				sp := data[sec.PayloadOffset : sec.Offset+sec.Size]
				huntNestedFirmwareVolumes(r, report, mode, sp, fmt.Sprintf("firmware:FV@0x%x/FFS@0x%x/FV_IMAGE", v.Offset, f.Offset), 1, seenNested)
			}
		}
	}
}

func threatBaselineDifferential(r *Report, report *ThreatScanReport, mode string) {
	if mode != "MALWARE" || cfg.Baseline == "" || len(r.FirmwareVolumes) == 0 {
		return
	}
	b, err := os.ReadFile(cfg.Baseline)
	if err != nil {
		return
	}
	var base Report
	if json.Unmarshal(b, &base) != nil || len(base.FirmwareVolumes) == 0 {
		report.CoverageGaps = append(report.CoverageGaps, "baseline has no firmware-volume/module inventory for differential hunting")
		return
	}
	baseMap := map[string]FirmwareFileReport{}
	for _, v := range base.FirmwareVolumes {
		for _, f := range v.FilesDetail {
			baseMap[strings.ToLower(f.NameGUID+"|"+f.TypeName+"|"+f.Name)] = f
		}
	}
	changed, added, highRisk := 0, 0, 0
	for _, v := range r.FirmwareVolumes {
		for _, f := range v.FilesDetail {
			k := strings.ToLower(f.NameGUID + "|" + f.TypeName + "|" + f.Name)
			old, ok := baseMap[k]
			if !ok {
				added++
				if f.ExecutionClass == "DXE" || f.ExecutionClass == "SMM/MM" {
					highRisk++
				}
				continue
			}
			if old.SHA512 != f.SHA512 {
				changed++
				if f.ExecutionClass == "DXE" || f.ExecutionClass == "SMM/MM" {
					highRisk++
				}
			}
		}
	}
	if changed == 0 && added == 0 {
		addThreatHitEx(r, report, mode, "baseline-differential", "Firmware differential integrity", "no module additions or FFS hash changes relative to trusted baseline", "INFO", "high", "firmware-image", -1, "baseline stable", "changed=0 added=0", "firmware differential comparison", "Binarly public differential firmware analysis methodology")
		return
	}
	sev, conf := "MEDIUM", "high"
	if highRisk > 0 {
		sev = "HIGH"
	}
	addThreatHitEx(r, report, mode, "baseline-differential", "Firmware differential anomaly", "FFS module added or modified relative to trusted baseline", sev, conf, "firmware-image", -1, "firmware module delta", fmt.Sprintf("changed=%d added=%d executable_dxe_or_smm_delta=%d", changed, added, highRisk), "firmware differential comparison", "Binarly public differential firmware analysis methodology")
}

func threatTrustAndBootChainHunt(r *Report, report *ThreatScanReport, mode string) {
	if mode != "MALWARE" {
		return
	}
	if out, err := run("mokutil", "--list-enrolled"); err == nil && strings.TrimSpace(out) != "" {
		addThreatHitEx(r, report, mode, "trust-context", "MOK trust-store surface", "enrolled Machine Owner Key material", "LOW", "high", "mokutil", -1, "MOK enrollment evidence", "MOK enrollment is legitimate on many Linux installations; unexpected keys should be compared with the trusted baseline", "mokutil --list-enrolled", "UEFI Secure Boot trust-chain context")
	}
	for _, p := range []string{"/boot/efi/EFI/Microsoft/Boot/system32", "/efi/EFI/Microsoft/Boot/system32"} {
		if exists(p) {
			addThreatHitEx(r, report, mode, "bootchain-anomaly", "BlackLotus-style ESP artifact surface", "unexpected Microsoft Boot system32 directory", "HIGH", "medium", p, -1, `EFI\Microsoft\Boot\system32`, "this directory should be validated against a trusted Windows ESP image", "ESP boot-chain structural analysis", "public BlackLotus forensic reporting")
		}
	}
}

func finalizeThreatScan(r *Report, report *ThreatScanReport, mode string, rawFirmwareAvailable bool) {
	if report.Targets == 0 {
		report.Coverage = "NONE"
		report.CoverageGaps = append(report.CoverageGaps, "no readable threat-hunting targets were available")
		return
	}
	if rawFirmwareAvailable {
		report.Coverage = "RAW_FIRMWARE + FV/FFS/MODULES + ESP + EFI_VARIABLES"
	} else {
		report.Coverage = "ESP + EFI_VARIABLES"
		report.CoverageGaps = append(report.CoverageGaps, "raw SPI/firmware image unavailable; hidden DXE/SMM implants in flash cannot be ruled out")
	}
	if len(report.Hits) == 0 {
		add(r, mode+"-SCAN-001", strings.ToLower(mode)+"-scan", strings.Title(strings.ToLower(mode))+" dedicated UEFI threat hunting", PASS, "high", "medium", fmt.Sprintf("profile=%s coverage=%s targets=%d artifacts=%d firmware_modules=%d yara=%d structural=%d behavior=%d", report.Profile, report.Coverage, report.Targets, report.Artifacts, report.FirmwareModules, report.YARAMatches, report.StructuralHits, report.StringHits), "none; preserve the collected evidence and compare future scans against a trusted baseline", mode+" dedicated public threat-hunting pipeline")
	} else {
		conf := "medium"
		if report.HighConfidence > 0 {
			conf = "high"
		}
		add(r, mode+"-SCAN-001", strings.ToLower(mode)+"-scan", strings.Title(strings.ToLower(mode))+" dedicated UEFI threat indicators", WARN, "high", conf, fmt.Sprintf("profile=%s coverage=%s targets=%d artifacts=%d firmware_modules=%d indicators=%d high_confidence=%d yara=%d structural=%d behavior=%d", report.Profile, report.Coverage, report.Targets, report.Artifacts, report.FirmwareModules, report.Indicators, report.HighConfidence, report.YARAMatches, report.StructuralHits, report.StringHits), "preserve the exact firmware/EFI artifacts and hashes; validate PE/TE signatures, Secure Boot revocation/trust state, FV/FFS module provenance and a trusted baseline before remediation", mode+" dedicated public threat-hunting pipeline")
	}
}

func check2026ThreatIntel(r *Report, mode string) {
	if mode == "MALWARE" {
		add(r, "THREAT-INTEL-2026", "malware-scan", "2026 public UEFI bootkit/rootkit hunt pack", PASS, "info", "high", "Family/behavior coverage: LoJax, MoonBounce, CosmicStrand, MosaicRegressor, ESPecter, BlackLotus, Bootkitty, HybridPetya, FinSpy/FinFisher, TrickBoot, EfiGuard-derived, Bootlicker/DmaBackdoorBoot-style, umap/SandboxBootkit-style and PeiBackdoor-style behaviors; exposure coverage includes 2026 vulnerable signed shims <=0.9, CVE-2024-7344, CVE-2022-21894, LogoFAIL/CVE-2023-40238 plus hook-chain, relocation/API-resolution, CR0/CR4, persistence and differential hunting", "none; metadata only", "public 2025-2026 UEFI threat research")
	} else {
		add(r, "SPYWARE-INTEL-2026", "spyware-scan", "2026 public UEFI surveillance hunt pack", PASS, "info", "high", "Behavior coverage: keylogging, screenshot, clipboard, credential/session theft, microphone/webcam, EFI networking, persistence and collection+network+persistence correlation", "none; metadata only", "public UEFI surveillance research")
	}
}

func threatRemediation(family, technique string) string {
	low := strings.ToLower(family + " " + technique)
	switch {
	case strings.Contains(low, "blacklotus"), strings.Contains(low, "shim"), strings.Contains(low, "secure boot bypass"), strings.Contains(low, "baton drop"):
		return "preserve the exact EFI artifact; verify version/hash and Authenticode signer; compare against trusted OEM/distribution artifacts and current dbx; apply vendor revocations/updates before remediation"
	case strings.Contains(low, "lojax"), strings.Contains(low, "moonbounce"), strings.Contains(low, "cosmicstrand"), strings.Contains(low, "mosaicregressor"), strings.Contains(low, "firmware differential"):
		return "preserve the complete SPI image; compare affected FV/FFS module hashes with a trusted OEM image; verify signatures where applicable and use an approved OEM firmware recovery/reflash process if unauthorized changes are confirmed"
	case strings.Contains(low, "smm"), strings.Contains(low, "mm"):
		return "preserve the raw firmware and exact SMM/MM module; compare with the vendor image and use OEM/vendor recovery or hardware-assisted reflash if unauthorized modification is confirmed"
	case strings.Contains(low, "spyware"), strings.Contains(low, "surveillance"):
		return "preserve the artifact and firmware image; correlate collection, persistence and network evidence; verify signatures/hashes against a trusted baseline before containment or reflash"
	case strings.Contains(low, "hook"):
		return "validate the module against a trusted firmware baseline and inspect the Boot Services/DXE hook context; generic hook strings alone do not prove compromise"
	default:
		return "preserve exact evidence, verify signatures and SHA-512 against a trusted OEM/baseline image, and investigate the module in context before remediation"
	}
}

func checkMalwareScan(r *Report)            { r.MalwareScan = runThreatScan(r, "MALWARE") }
func checkSpywareScan(r *Report)            { r.SpywareScan = runThreatScan(r, "SPYWARE") }
func check2026MalwareThreatIntel(r *Report) { check2026ThreatIntel(r, "MALWARE") }
func check2026SpywareThreatIntel(r *Report) { check2026ThreatIntel(r, "SPYWARE") }

func uniqueStrings(in []string) []string {
	m := map[string]struct{}{}
	for _, x := range in {
		if x != "" {
			m[x] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func checkDeepForensics(r *Report) {
	if !cfg.LegacyForensic {
		return
	}
	roots := []string{"/boot/efi/EFI", "/boot/efi"}
	seen := map[string]bool{}
	type artifact struct {
		path  string
		size  int64
		mode  string
		mtime string
		hash  string
	}
	var arts []artifact
	for _, root := range roots {
		if !exists(root) {
			continue
		}
		_ = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || seen[path] {
				return nil
			}
			if info.Size() > cfg.MaxFile {
				return nil
			}
			seen[path] = true
			h, e := hashFile(path)
			if e != nil {
				return nil
			}
			arts = append(arts, artifact{path: path, size: info.Size(), mode: info.Mode().String(), mtime: info.ModTime().UTC().Format(time.RFC3339), hash: h})
			return nil
		})
	}
	sort.Slice(arts, func(i, j int) bool { return arts[i].path < arts[j].path })
	if len(arts) == 0 {
		add(r, "DF-001", "deep-forensics", "Deep EFI artifact inventory", UNKNOWN, "high", "medium", "no readable EFI artifacts were available for level-5 inventory", "mount the ESP read-only and rerun the full forensic profile", "filesystem")
	} else {
		add(r, "DF-001", "deep-forensics", "Deep EFI artifact inventory", PASS, "high", "high", fmt.Sprintf("collected SHA-512, size, mode and mtime for %d EFI artifacts", len(arts)), "preserve the JSON report as the evidence manifest and compare artifact hashes against a trusted signed OEM/package baseline", "filesystem hash inventory")
		// Emit compact per-artifact log records without flooding stdout.
		for _, a := range arts {
			logf(4, "efi-artifact path=%s size=%d mode=%s mtime=%s sha512=%s", a.path, a.size, a.mode, a.mtime, a.hash)
		}
	}

	if _, err := exec.LookPath("sbverify"); err != nil {
		add(r, "DF-002", "deep-forensics", "EFI image signature verification", NA, "high", "high", "sbverify is not installed; signature verification was not attempted", "install sbsigntools and rerun for signature metadata where supported", "PATH")
	} else {
		checked, signed := 0, 0
		for _, a := range arts {
			if !looksLikeEFIArtifact(a.path) {
				continue
			}
			checked++
			out, err := run("sbverify", "--list", a.path)
			if err == nil && strings.TrimSpace(out) != "" {
				signed++
				logf(4, "efi-signature path=%s result=%s", a.path, oneLine(out, 1600))
			} else {
				logf(4, "efi-signature path=%s verification=%v output=%s", a.path, err, oneLine(out, 900))
			}
		}
		if checked == 0 {
			add(r, "DF-002", "deep-forensics", "EFI image signature verification", UNKNOWN, "high", "medium", "no PE/EFI candidates were identified for sbverify", "review EFI binaries manually or with vendor/package signature tooling", "sbverify")
		} else if signed == checked {
			add(r, "DF-002", "deep-forensics", "EFI image signature verification", PASS, "high", "medium", fmt.Sprintf("%d/%d candidate EFI binaries returned signature metadata", signed, checked), "validate signer trust against the platform Secure Boot db/dbx and OEM policy", "sbverify --list")
		} else {
			add(r, "DF-002", "deep-forensics", "EFI image signature verification", WARN, "high", "medium", fmt.Sprintf("%d/%d candidate EFI binaries returned signature metadata", signed, checked), "inspect unsigned or unverifiable EFI binaries and compare them with trusted package/OEM versions", "sbverify --list")
		}
	}

	if out, err := run("efibootmgr", "-v"); err == nil {
		add(r, "DF-003", "deep-forensics", "Deep boot-entry capture", PASS, "high", "high", truncate(out, 5000), "preserve and compare boot entries against the known-good baseline; investigate unexpected EFI paths or duplicate boot entries", "efibootmgr -v")
	} else {
		add(r, "DF-003", "deep-forensics", "Deep boot-entry capture", UNKNOWN, "high", "medium", truncate(out, 1500), "install efibootmgr or collect equivalent boot-entry evidence with vendor tooling", "efibootmgr -v")
	}
}

func looksLikeEFIArtifact(path string) bool {
	low := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(low, ".efi") || strings.Contains(low, "boot") || strings.Contains(low, "mm") || strings.Contains(low, "grub") || strings.Contains(low, "shim")
}

func findEFIVarPath(name string) string {
	matches, _ := filepath.Glob(filepath.Join("/sys/firmware/efi/efivars", name+"-*"))
	if len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[0]
}

func readEFIVar(name string) ([]byte, uint32, string, error) {
	path := findEFIVarPath(name)
	if path == "" {
		return nil, 0, "", os.ErrNotExist
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, path, err
	}
	if len(b) < 4 {
		return nil, 0, path, fmt.Errorf("EFI variable payload is shorter than 4-byte attributes header")
	}
	return b[4:], binary.LittleEndian.Uint32(b[:4]), path, nil
}

func efiAttrText(attr uint32) string {
	parts := []string{}
	const (
		nv       = 0x00000001
		bs       = 0x00000002
		runtimeA = 0x00000004
		hwerr    = 0x00000008
		auth     = 0x00000010
		timeAuth = 0x00000020
		appendW  = 0x00000040
		enhAuth  = 0x00000080
	)
	if attr&nv != 0 {
		parts = append(parts, "NV")
	}
	if attr&bs != 0 {
		parts = append(parts, "BS")
	}
	if attr&runtimeA != 0 {
		parts = append(parts, "RT")
	}
	if attr&hwerr != 0 {
		parts = append(parts, "HWERR")
	}
	if attr&auth != 0 {
		parts = append(parts, "AUTH")
	}
	if attr&timeAuth != 0 {
		parts = append(parts, "TIME_AUTH")
	}
	if attr&appendW != 0 {
		parts = append(parts, "APPEND")
	}
	if attr&enhAuth != 0 {
		parts = append(parts, "ENH_AUTH")
	}
	if len(parts) == 0 {
		return "NONE"
	}
	return strings.Join(parts, "|")
}

func checkSecureBootPolicy(r *Report) {
	if !exists("/sys/firmware/efi/efivars") {
		add(r, "SBP-001", "secureboot-policy", "UEFI Secure Boot policy variables", NA, "high", "high", "efivarfs is unavailable; Secure Boot policy variables cannot be inspected", "run the scanner from a UEFI boot with efivarfs available", "efivarfs")
		return
	}
	vars := []string{"PK", "KEK", "db", "dbx", "SetupMode", "AuditMode", "DeployedMode", "VendorKeys"}
	present := 0
	details := []string{}
	for _, name := range vars {
		data, attr, path, err := readEFIVar(name)
		if err != nil {
			details = append(details, name+":missing")
			continue
		}
		present++
		entry := fmt.Sprintf("%s:len=%d attr=0x%08x(%s)", name, len(data), attr, efiAttrText(attr))
		if name == "SetupMode" || name == "AuditMode" || name == "DeployedMode" || name == "VendorKeys" {
			if len(data) > 0 {
				entry += fmt.Sprintf(" value=%d", data[0])
			}
		}
		if path != "" {
			logf(4, "secureboot-variable name=%s path=%s %s", name, path, entry)
		}
		details = append(details, entry)
	}
	if present < 4 {
		add(r, "SBP-001", "secureboot-policy", "UEFI Secure Boot policy variables", UNKNOWN, "high", "medium", fmt.Sprintf("%d/%d policy variables readable; %s", present, len(vars), strings.Join(details, "; ")), "verify PK/KEK/db/dbx and Secure Boot policy state with firmware or vendor tooling", "efivarfs")
		return
	}

	setup, _, _, setupErr := readEFIVar("SetupMode")
	audit, _, _, auditErr := readEFIVar("AuditMode")
	deployed, _, _, deployedErr := readEFIVar("DeployedMode")
	vendorKeys, _, _, vkErr := readEFIVar("VendorKeys")
	status := PASS
	severity := "high"
	confidence := "high"
	issues := []string{}
	if setupErr == nil && len(setup) > 0 && setup[0] != 0 {
		status = WARN
		issues = append(issues, "SetupMode=1")
	}
	if auditErr == nil && len(audit) > 0 && audit[0] != 0 {
		status = WARN
		issues = append(issues, "AuditMode=1")
	}
	if deployedErr == nil && len(deployed) > 0 && deployed[0] == 0 {
		// DeployedMode is optional on some implementations, so only treat an explicitly readable 0 as informational context.
		issues = append(issues, "DeployedMode=0")
	}
	if vkErr == nil && len(vendorKeys) > 0 && vendorKeys[0] == 0 {
		status = WARN
		issues = append(issues, "VendorKeys=0")
	}
	for _, name := range []string{"PK", "KEK", "db", "dbx"} {
		data, attr, _, err := readEFIVar(name)
		if err != nil || len(data) == 0 {
			status = WARN
			issues = append(issues, name+" empty/missing")
			continue
		}
		if attr&0x20 == 0 { // EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
			status = WARN
			issues = append(issues, name+" lacks TIME_AUTH")
		}
	}
	if len(issues) > 0 {
		confidence = "medium"
	}
	if status == PASS {
		add(r, "SBP-001", "secureboot-policy", "UEFI Secure Boot policy variables", PASS, severity, confidence, strings.Join(details, "; "), "none", "UEFI Secure Boot variables")
	} else {
		add(r, "SBP-001", "secureboot-policy", "UEFI Secure Boot policy variables", status, severity, confidence, strings.Join(details, "; ")+"; policy observations: "+strings.Join(issues, ", "), "review Secure Boot policy in firmware; for enabled Secure Boot ensure PK/KEK/db/dbx are populated and authenticated according to platform policy", "UEFI Secure Boot variables")
	}

	// Hash the policy databases as evidence without attempting to interpret certificate trust chains.
	for _, name := range []string{"PK", "KEK", "db", "dbx"} {
		data, _, _, err := readEFIVar(name)
		if err != nil || len(data) == 0 {
			continue
		}
		add(r, "SBP-HASH-"+safeID(name), "secureboot-policy", name+" database evidence hash", PASS, "medium", "high", fmt.Sprintf("%s payload sha512=%s length=%d", name, hashBytes(data), len(data)), "compare the database hash against a trusted platform baseline before treating a change as malicious", "efivarfs")
	}
}

func checkEFIVariableIntegrity(r *Report) {
	root := "/sys/firmware/efi/efivars"
	if !exists(root) {
		add(r, "EFIVAR-001", "efi-var-integrity", "EFI variable inventory", NA, "medium", "high", "efivarfs is not mounted", "mount efivarfs read-only where appropriate for evidence collection", root)
		return
	}
	count := 0
	suspicious := []string{}
	varNameRE := regexp.MustCompile(`^([^ -]+)-[0-9a-fA-F-]{36}$`)
	entries, err := os.ReadDir(root)
	if err != nil {
		add(r, "EFIVAR-001", "efi-var-integrity", "EFI variable inventory", UNKNOWN, "medium", "high", err.Error(), "run with sufficient privileges to enumerate efivars", root)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		count++
		name := e.Name()
		if !varNameRE.MatchString(name) {
			suspicious = append(suspicious, name)
		}
		if count <= 200 {
			logf(4, "efivar path=%s", filepath.Join(root, name))
		}
	}
	if len(suspicious) > 0 {
		add(r, "EFIVAR-001", "efi-var-integrity", "EFI variable inventory", WARN, "medium", "medium", fmt.Sprintf("%d variables enumerated; %d names do not match the common NAME-GUID efivarfs form: %s", count, len(suspicious), truncate(strings.Join(suspicious, ", "), 1800)), "review unusual variable names against the platform vendor and installed boot components; irregular naming alone does not prove tampering", "efivarfs directory inventory")
	} else {
		add(r, "EFIVAR-001", "efi-var-integrity", "EFI variable inventory", PASS, "info", "high", fmt.Sprintf("%d EFI variables enumerated with expected efivarfs naming", count), "none", "efivarfs directory inventory")
	}

	mount, err := run("findmnt", "-rn", "-o", "TARGET,FSTYPE,OPTIONS", root)
	if err == nil && strings.TrimSpace(mount) != "" {
		add(r, "EFIVAR-002", "efi-var-integrity", "efivarfs mount policy", PASS, "low", "high", truncate(mount, 1400), "review efivarfs mount options against local policy; scanner does not attempt any writes", "findmnt")
	} else {
		add(r, "EFIVAR-002", "efi-var-integrity", "efivarfs mount policy", UNKNOWN, "low", "medium", "could not obtain efivarfs mount options", "inspect the efivarfs mount with findmnt", "findmnt")
	}
}

func checkBootSecurity(r *Report) {
	out, err := run("efibootmgr", "-v")
	if err != nil {
		add(r, "BOOTSEC-001", "boot-security", "Boot manager configuration", UNKNOWN, "high", "medium", truncate(out, 2600), "install efibootmgr or collect equivalent firmware boot-entry evidence", "efibootmgr -v")
		return
	}
	low := strings.ToLower(out)
	issues := []string{}
	if strings.Contains(low, "bootnext:") {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(strings.ToLower(line), "bootnext:") {
				issues = append(issues, strings.TrimSpace(line))
			}
		}
	}
	bootOrder := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "BootOrder:") {
			bootOrder = strings.TrimSpace(strings.TrimPrefix(line, "BootOrder:"))
		}
	}
	entries := 0
	network := []string{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Boot") && strings.Contains(line, "*") {
			entries++
			l := strings.ToLower(line)
			if strings.Contains(l, "pxe") || strings.Contains(l, "ipv4") || strings.Contains(l, "ipv6") || strings.Contains(l, "httpboot") {
				network = append(network, strings.TrimSpace(line))
			}
		}
	}
	status := PASS
	sev := "medium"
	conf := "high"
	if len(network) > 0 {
		status = WARN
		sev = "medium"
		conf = "high"
		issues = append(issues, "network-capable boot entry present")
	}
	if len(issues) > 0 && strings.Contains(strings.Join(issues, " "), "BootNext") {
		conf = "medium"
	}
	evidence := fmt.Sprintf("BootOrder=%s; entries=%d; BootNext_present=%t", bootOrder, entries, strings.Contains(low, "bootnext:"))
	if len(network) > 0 {
		evidence += "; network_entries=" + truncate(strings.Join(network, " | "), 1200)
	}
	if len(issues) > 0 {
		evidence += "; observations=" + truncate(strings.Join(issues, " | "), 1200)
	}
	add(r, "BOOTSEC-001", "boot-security", "Boot manager configuration", status, sev, conf, evidence, "review BootOrder/BootNext and remove unexpected network or temporary boot entries according to platform policy; preserve the raw efibootmgr output for investigation", "efibootmgr -v")

	if bootOrder == "" {
		add(r, "BOOTSEC-002", "boot-security", "BootOrder present", WARN, "medium", "high", "BootOrder was not reported by efibootmgr", "verify firmware boot-order configuration", "efibootmgr -v")
	} else {
		add(r, "BOOTSEC-002", "boot-security", "BootOrder present", PASS, "info", "high", bootOrder, "none", "efibootmgr -v")
	}
}

func checkFWUPDSecurity(r *Report) {
	if _, err := exec.LookPath("fwupdmgr"); err != nil {
		add(r, "FWUPD-000", "fwupd-security", "fwupd host security assessment", NA, "high", "high", "fwupdmgr is not installed; HSI/security attributes unavailable", "install fwupd where supported or use the OEM firmware security tooling", "PATH")
		return
	}
	out, err := run("fwupdmgr", "security")
	if err != nil {
		add(r, "FWUPD-001", "fwupd-security", "fwupd host security assessment", UNKNOWN, "high", "medium", truncate(out, 3500), "update fwupd metadata and rerun fwupdmgr security; investigate any reported HSI failures", "fwupdmgr security")
		return
	}
	low := strings.ToLower(out)
	status := PASS
	sev := "high"
	conf := "medium"
	if strings.Contains(low, "hsi: ") && strings.Contains(low, "hsI: 0") {
		status = WARN
	}
	if strings.Contains(low, "critical") || strings.Contains(low, "failed") || strings.Contains(low, "✘") || strings.Contains(low, "❌") {
		status = WARN
	}
	if strings.Contains(low, "hsI: ") {
		conf = "high"
	}
	add(r, "FWUPD-001", "fwupd-security", "fwupd host security assessment", status, sev, conf, truncate(out, 4500), "address each fwupdmgr security/HSI failure using the specific recommendation shown by fwupdmgr, then rescan", "fwupdmgr security")

	if dev, e := run("fwupdmgr", "get-devices"); e == nil {
		add(r, "FWUPD-002", "fwupd-security", "fwupd firmware device inventory", PASS, "medium", "high", truncate(dev, 3500), "none; preserve device/version information for firmware baseline correlation", "fwupdmgr get-devices")
	} else {
		add(r, "FWUPD-002", "fwupd-security", "fwupd firmware device inventory", UNKNOWN, "medium", "medium", truncate(dev, 1600), "collect firmware inventory with fwupdmgr or OEM tooling", "fwupdmgr get-devices")
	}
}

func checkIOMMU(r *Report) {
	cmdline, _ := readText("/proc/cmdline", 4096)
	iommuGroups := 0
	if entries, err := os.ReadDir("/sys/kernel/iommu_groups"); err == nil {
		iommuGroups = len(entries)
	}
	acpi := []string{}
	for _, t := range []string{"/sys/firmware/acpi/tables/DMAR", "/sys/firmware/acpi/tables/IVRS"} {
		if exists(t) {
			acpi = append(acpi, filepath.Base(t))
		}
	}
	enabledParam := regexp.MustCompile(`(?i)(intel_iommu=on|amd_iommu=on|iommu=on|iommu=force)`).MatchString(cmdline)
	status := PASS
	sev := "medium"
	if iommuGroups == 0 && !enabledParam && len(acpi) == 0 {
		status = UNKNOWN
	}
	if iommuGroups == 0 && enabledParam {
		status = WARN
	}
	add(r, "IOMMU-001", "iommu", "DMA/IOMMU protection evidence", status, sev, "high", fmt.Sprintf("iommu_groups=%d; ACPI=%s; cmdline_iommu_enabled=%t; cmdline=%s", iommuGroups, strings.Join(acpi, ","), enabledParam, truncate(cmdline, 1400)), "enable and validate platform DMA remapping/IOMMU protections according to the OEM security policy; verify PCIe devices are placed into expected IOMMU groups", "sysfs + ACPI + /proc/cmdline")
}

func checkKernelLockdown(r *Report) {
	p := "/sys/kernel/security/lockdown"
	data, err := readText(p, 512)
	if err != nil {
		add(r, "LOCK-001", "kernel-lockdown", "Kernel lockdown mode", UNKNOWN, "high", "medium", "kernel lockdown interface unavailable", "enable/configure kernel lockdown when supported and compatible with the host security policy", p)
		return
	}
	low := strings.ToLower(data)
	if strings.Contains(low, "[confidentiality]") || strings.Contains(low, "[integrity]") {
		add(r, "LOCK-001", "kernel-lockdown", "Kernel lockdown mode", PASS, "high", "high", strings.TrimSpace(data), "none", p)
	} else if strings.Contains(low, "none") || strings.TrimSpace(low) == "[none]" {
		add(r, "LOCK-001", "kernel-lockdown", "Kernel lockdown mode", WARN, "high", "high", strings.TrimSpace(data), "enable kernel lockdown when required by the platform policy, especially where Secure Boot is used", p)
	} else {
		add(r, "LOCK-001", "kernel-lockdown", "Kernel lockdown mode", UNKNOWN, "high", "medium", strings.TrimSpace(data), "verify kernel lockdown policy", p)
	}
}

func checkKernelTaint(r *Report) {
	b, err := readText("/proc/sys/kernel/tainted", 128)
	if err != nil {
		add(r, "TAINT-001", "kernel-taint", "Kernel taint state", UNKNOWN, "medium", "high", "kernel taint interface unavailable", "inspect kernel taint state using equivalent kernel tooling", "/proc/sys/kernel/tainted")
		return
	}
	v := strings.TrimSpace(b)
	if v == "0" {
		add(r, "TAINT-001", "kernel-taint", "Kernel taint state", PASS, "medium", "high", "tainted=0", "none", "/proc/sys/kernel/tainted")
	} else {
		add(r, "TAINT-001", "kernel-taint", "Kernel taint state", WARN, "medium", "high", "tainted="+v, "decode the kernel taint flags and investigate proprietary/out-of-tree modules, forced unloads, firmware errors, or other causes before treating the host as high-assurance", "/proc/sys/kernel/tainted")
	}
}

func checkKernelCommandLine(r *Report) {
	data, err := readText("/proc/cmdline", 8192)
	if err != nil {
		add(r, "CMD-001", "kernel-cmdline", "Kernel security command-line posture", UNKNOWN, "medium", "high", err.Error(), "collect /proc/cmdline from the running host", "/proc/cmdline")
		return
	}
	tokens := strings.Fields(data)
	bad := []string{}
	good := []string{}
	securityParams := []string{"module.sig_enforce=1", "slab_nomerge", "init_on_alloc=1", "init_on_free=1", "pti=on", "randomize_kstack_offset=on", "vsyscall=none", "iommu=force", "intel_iommu=on", "amd_iommu=on", "lockdown=integrity", "lockdown=confidentiality", "page_alloc.shuffle=1"}
	for _, p := range securityParams {
		found := false
		for _, t := range tokens {
			if t == p {
				found = true
				break
			}
		}
		if found {
			good = append(good, p)
		}
	}
	for _, t := range tokens {
		lt := strings.ToLower(t)
		if lt == "module.sig_enforce=0" || lt == "efi=debug" || lt == "iomem=relaxed" || lt == "slab_nomerge=0" {
			bad = append(bad, t)
		}
	}
	st := PASS
	if len(bad) > 0 {
		st = WARN
	}
	add(r, "CMD-001", "kernel-cmdline", "Kernel security command-line posture", st, "medium", "high", fmt.Sprintf("security_parameters_present=%s; sensitive_parameters=%s; full_cmdline=%s", strings.Join(good, ","), strings.Join(bad, ","), truncate(strings.TrimSpace(data), 2600)), "remove debug/relaxed parameters that are not explicitly required and align kernel boot parameters with the enterprise hardening baseline", "/proc/cmdline")
}

func checkKexecProtection(r *Report) {
	p := "/proc/sys/kernel/kexec_load_disabled"
	v, err := readText(p, 32)
	if err != nil {
		add(r, "KEXEC-001", "kexec", "Kernel kexec load protection", UNKNOWN, "medium", "medium", "kexec_load_disabled interface unavailable", "verify whether kexec is required; otherwise apply a documented kexec restriction policy", p)
		return
	}
	value := strings.TrimSpace(v)
	st := PASS
	if value == "0" {
		st = WARN
	} else if value != "1" {
		st = UNKNOWN
	}
	configEvidence := ""
	if data, e := readKernelConfigText(); e == nil {
		for _, k := range []string{"CONFIG_KEXEC=", "CONFIG_KEXEC_FILE="} {
			if line := findConfig(data, k); line != "" {
				configEvidence += line + "; "
			}
		}
	}
	add(r, "KEXEC-001", "kexec", "Kernel kexec load protection", st, "medium", "high", "kexec_load_disabled="+value+"; "+configEvidence, "restrict kexec loading when required by the platform policy; verify crash-dump tooling before changing this control", "sysctl + kernel config")
}

func checkTPMEventLog(r *Report) {
	paths := []string{"/sys/kernel/security/tpm0/binary_bios_measurements", "/sys/kernel/security/tpm0/ascii_bios_measurements"}
	found := []string{}
	for _, p := range paths {
		if exists(p) {
			st, _ := os.Stat(p)
			if st != nil {
				found = append(found, fmt.Sprintf("%s(size=%d)", p, st.Size()))
			}
		}
	}
	if len(found) == 0 {
		add(r, "TPMEV-001", "tpm-eventlog", "TPM firmware measurement event log", UNKNOWN, "high", "medium", "TPM BIOS measurement event-log interfaces not visible", "verify TPM event-log exposure and measured-boot support; collect vendor attestation evidence where available", "securityfs")
		return
	}
	add(r, "TPMEV-001", "tpm-eventlog", "TPM firmware measurement event log", PASS, "high", "high", strings.Join(found, "; "), "preserve PCR values and event-log data together when performing attestation or incident response", "securityfs")
	if _, err := exec.LookPath("tpm2_eventlog"); err == nil && exists(paths[0]) {
		out, e := run("tpm2_eventlog", paths[0])
		if e == nil {
			add(r, "TPMEV-002", "tpm-eventlog", "TPM event-log parse", PASS, "high", "high", truncate(out, 3500), "none", "tpm2_eventlog")
		} else {
			add(r, "TPMEV-002", "tpm-eventlog", "TPM event-log parse", UNKNOWN, "medium", "medium", truncate(out, 1500), "preserve the raw event log and review with TPM-aware tooling", "tpm2_eventlog")
		}
	} else {
		add(r, "TPMEV-002", "tpm-eventlog", "TPM event-log parse", NA, "medium", "high", "tpm2_eventlog is unavailable; raw event-log presence was checked", "install tpm2-tools for structured event-log parsing", "PATH")
	}
}

func checkACPIIntegrity(r *Report) {
	root := "/sys/firmware/acpi/tables"
	if !exists(root) {
		add(r, "ACPI-001", "acpi-integrity", "ACPI firmware table inventory", UNKNOWN, "medium", "medium", "ACPI table directory unavailable", "verify firmware ACPI table exposure", root)
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		add(r, "ACPI-001", "acpi-integrity", "ACPI firmware table inventory", UNKNOWN, "medium", "medium", err.Error(), "run with access to ACPI table sysfs interfaces", root)
		return
	}
	count := 0
	hashed := 0
	important := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		count++
		p := filepath.Join(root, e.Name())
		if h, err := hashFile(p); err == nil {
			hashed++
			logf(4, "acpi-table name=%s sha512=%s", e.Name(), h)
		}
		name := strings.ToUpper(e.Name())
		for _, want := range []string{"DMAR", "IVRS", "TPM2", "TCPA", "FPDT"} {
			if strings.Contains(name, want) {
				important = append(important, e.Name())
				break
			}
		}
	}
	st := PASS
	if count == 0 {
		st = UNKNOWN
	}
	add(r, "ACPI-001", "acpi-integrity", "ACPI firmware table inventory", st, "medium", "high", fmt.Sprintf("tables=%d hashed=%d important=%s", count, hashed, strings.Join(important, ",")), "compare ACPI table hashes against a trusted hardware baseline when investigating firmware changes; use DMAR/IVRS/TPM2 evidence to correlate DMA and measured-boot posture", "ACPI sysfs")
}

func checkFirmwareUpdatePath(r *Report) {
	entries, err := os.ReadDir("/sys/firmware/efi/esrt/entries")
	if err != nil {
		add(r, "ESRT-001", "firmware-update-path", "EFI System Resource Table", NA, "medium", "high", "ESRT entry directory unavailable; firmware may not expose ESRT through this kernel", "use fwupd or OEM tooling to inventory firmware update resources", "ESRT sysfs")
		return
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			count++
		}
	}
	if count == 0 {
		add(r, "ESRT-001", "firmware-update-path", "EFI System Resource Table", UNKNOWN, "medium", "medium", "ESRT directory exists but no entries were readable", "verify firmware capsule/update support with OEM tooling", "ESRT sysfs")
	} else {
		add(r, "ESRT-001", "firmware-update-path", "EFI System Resource Table", PASS, "medium", "high", fmt.Sprintf("%d ESRT firmware resource entries present", count), "preserve ESRT firmware IDs and versions as part of the trusted baseline", "ESRT sysfs")
	}
	if out, e := run("fwupdmgr", "get-history"); e == nil {
		add(r, "ESRT-002", "firmware-update-path", "Firmware update history", PASS, "low", "medium", truncate(out, 3500), "review firmware update history for unexpected downgrade/reflash activity", "fwupdmgr get-history")
	} else {
		add(r, "ESRT-002", "firmware-update-path", "Firmware update history", NA, "low", "high", "fwupdmgr history unavailable", "use OEM or distribution firmware-update logs if update provenance is required", "fwupdmgr get-history")
	}
}

func checkEFIMount(r *Report) {
	out, err := run("findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "/boot/efi")
	if err != nil {
		add(r, "ESP-001", "efi-mount", "EFI System Partition mount", UNKNOWN, "medium", "medium", truncate(out, 1800), "identify the mounted ESP and collect it read-only when performing firmware forensics", "findmnt")
		return
	}
	low := strings.ToLower(out)
	status := PASS
	if strings.Contains(low, " rw,") || strings.HasSuffix(low, " rw") {
		status = WARN
	}
	add(r, "ESP-001", "efi-mount", "EFI System Partition mount", status, "medium", "high", truncate(out, 2200), "review ESP mount policy; for forensic acquisition prefer a read-only mount when the system does not require runtime ESP writes", "findmnt /boot/efi")
}

func checkDebugSurfaces(r *Report) {
	items := []string{}
	checks := map[string]string{"debugfs": "/sys/kernel/debug", "tracefs": "/sys/kernel/tracing", "efi-vars": "/sys/firmware/efi/efivars"}
	for name, p := range checks {
		if exists(p) {
			items = append(items, name+"=present")
		} else {
			items = append(items, name+"=absent")
		}
	}
	if out, e := run("findmnt", "-rn", "-o", "TARGET,FSTYPE,OPTIONS", "/sys/kernel/debug"); e == nil && strings.TrimSpace(out) != "" {
		items = append(items, "debugfs-mount="+oneLine(out, 1000))
	}
	if out, e := run("findmnt", "-rn", "-o", "TARGET,FSTYPE,OPTIONS", "/sys/kernel/tracing"); e == nil && strings.TrimSpace(out) != "" {
		items = append(items, "tracefs-mount="+oneLine(out, 1000))
	}
	add(r, "DBG-001", "debug-surfaces", "Kernel debug surface inventory", PASS, "low", "high", strings.Join(items, "; "), "disable or restrict debug interfaces on production high-assurance systems where they are not required; presence alone does not prove compromise", "runtime filesystem inventory")
}

func readKernelConfigText() (string, error) {
	paths := []string{"/boot/config-" + runtimeKernel(), "/proc/config.gz"}
	for _, p := range paths {
		if strings.HasSuffix(p, ".gz") {
			if out, e := run("zcat", p); e == nil && strings.TrimSpace(out) != "" {
				return out, nil
			}
		} else if data, e := readText(p, 8*1024*1024); e == nil {
			return data, nil
		}
	}
	return "", os.ErrNotExist
}

func checkModuleSignatures(r *Report) {
	if !exists("/proc/modules") {
		add(r, "MODSIG-001", "module-signatures", "Loaded kernel module signature posture", UNKNOWN, "high", "medium", "/proc/modules unavailable", "collect loaded-module evidence with equivalent kernel tooling", "/proc/modules")
		return
	}
	data, err := readText("/proc/modules", 2*1024*1024)
	if err != nil {
		add(r, "MODSIG-001", "module-signatures", "Loaded kernel module signature posture", UNKNOWN, "high", "medium", err.Error(), "run with access to /proc/modules and modinfo", "procfs")
		return
	}
	mods := []string{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "" {
			mods = append(mods, fields[0])
		}
	}
	if len(mods) == 0 {
		add(r, "MODSIG-001", "module-signatures", "Loaded kernel module signature posture", PASS, "medium", "high", "no external modules reported as loaded", "none", "/proc/modules")
		return
	}
	unsigned := []string{}
	checked := 0
	for i, mod := range mods {
		if i >= 120 {
			break
		}
		out, e := run("modinfo", "-F", "signer", mod)
		checked++
		if e != nil || strings.TrimSpace(out) == "" {
			unsigned = append(unsigned, mod)
			continue
		}
		logf(4, "module-signer module=%s signer=%s", mod, oneLine(out, 500))
	}
	st := PASS
	if len(unsigned) > 0 {
		st = WARN
	}
	evidence := fmt.Sprintf("loaded_modules=%d; signer_checked=%d; no_signer_or_unreadable=%d", len(mods), checked, len(unsigned))
	if len(unsigned) > 0 {
		evidence += "; modules=" + truncate(strings.Join(unsigned, ", "), 1800)
	}
	add(r, "MODSIG-001", "module-signatures", "Loaded kernel module signature posture", st, "high", "medium", evidence, "investigate unsigned/unverifiable loaded modules; require module signatures where supported by policy and validate CONFIG_MODULE_SIG_FORCE before relying on this control", "procfs + modinfo")
}

func checkVerity(r *Report) {
	dmNames := []string{}
	if entries, err := os.ReadDir("/sys/block"); err == nil {
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "dm-") {
				continue
			}
			namePath := filepath.Join("/sys/block", e.Name(), "dm", "name")
			if name, e2 := readText(namePath, 256); e2 == nil {
				name := strings.TrimSpace(name)
				if strings.Contains(strings.ToLower(name), "verity") {
					dmNames = append(dmNames, e.Name()+":"+name)
				}
			}
		}
	}
	rootFS, _ := run("findmnt", "-n", "-o", "SOURCE,FSTYPE,OPTIONS", "/")
	low := strings.ToLower(rootFS)
	if len(dmNames) > 0 || strings.Contains(low, "verity") {
		add(r, "VERITY-001", "verity", "Root filesystem integrity / dm-verity evidence", PASS, "high", "high", fmt.Sprintf("dm-verity=%s; root=%s", strings.Join(dmNames, ","), truncate(rootFS, 1200)), "none", "sysfs + findmnt")
		return
	}
	add(r, "VERITY-001", "verity", "Root filesystem integrity / dm-verity evidence", NA, "medium", "high", fmt.Sprintf("no dm-verity mapping detected; root=%s", truncate(rootFS, 1200)), "use dm-verity or an equivalent immutable/integrity-backed root mechanism where required by the deployment model", "sysfs + findmnt")
}

func checkSBAT(r *Report) {
	paths, _ := filepath.Glob("/sys/firmware/efi/efivars/SbatLevelRT-*")
	if len(paths) == 0 {
		if _, err := exec.LookPath("mokutil"); err == nil {
			out, e := run("mokutil", "--sb-state")
			if e == nil && strings.Contains(strings.ToLower(out), "secureboot enabled") {
				add(r, "SBAT-001", "sbat", "SBAT revocation-state evidence", UNKNOWN, "medium", "medium", "Secure Boot is enabled but SbatLevelRT was not exposed through efivarfs", "inspect shim SBAT state and the platform dbx/MOK policy with vendor-supported tooling", "mokutil + efivarfs")
				return
			}
		}
		add(r, "SBAT-001", "sbat", "SBAT revocation-state evidence", NA, "medium", "high", "SbatLevelRT variable not present or not exposed; SBAT cannot be assessed directly", "review shim/systemd-boot SBAT support where applicable", "efivarfs")
		return
	}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil || len(b) < 4 {
			continue
		}
		payload := b[4:]
		text := printable(string(payload))
		add(r, "SBAT-001", "sbat", "SBAT revocation-state evidence", PASS, "medium", "high", fmt.Sprintf("%s sha512=%s data=%s", filepath.Base(p), hashBytes(payload), oneLine(text, 1600)), "compare SBAT state against current trusted boot-chain policy and the platform dbx revocation baseline", "efivarfs")
		return
	}
	add(r, "SBAT-001", "sbat", "SBAT revocation-state evidence", UNKNOWN, "medium", "medium", "SbatLevelRT variable was present but unreadable", "preserve the variable path and inspect shim/bootloader SBAT state with supported tooling", "efivarfs")
}

func checkPlatformManagement(r *Report) {
	intelME := exists("/sys/class/mei/mei0")
	psp := false
	if entries, err := os.ReadDir("/sys/bus/pci/devices"); err == nil {
		for _, e := range entries {
			vendor, _ := readText(filepath.Join("/sys/bus/pci/devices", e.Name(), "vendor"), 64)
			class, _ := readText(filepath.Join("/sys/bus/pci/devices", e.Name(), "class"), 64)
			if strings.EqualFold(strings.TrimSpace(vendor), "0x1022") && strings.HasPrefix(strings.TrimSpace(class), "0x1080") {
				psp = true
			}
		}
	}
	items := []string{fmt.Sprintf("intel_mei=%t", intelME), fmt.Sprintf("amd_psp_evidence=%t", psp)}
	st := PASS
	if !intelME && !psp {
		st = NA
	}
	add(r, "PME-001", "platform-management", "Platform management/security processor visibility", st, "medium", "medium", strings.Join(items, "; "), "correlate the platform management engine/security processor version with OEM firmware advisories; absence from Linux sysfs is not proof that the component is absent", "sysfs PCI/MEI inventory")
}

func checkTPMPCR7(r *Report) {
	if _, err := exec.LookPath("tpm2_pcrread"); err != nil {
		add(r, "TPM-PCR7-000", "tpm-pcr7", "TPM PCR 7 measurement evidence", NA, "high", "high", "tpm2_pcrread unavailable", "install tpm2-tools and rerun to capture PCR 7 evidence", "PATH")
		return
	}
	out, err := run("tpm2_pcrread", "sha256:7")
	if err != nil {
		add(r, "TPM-PCR7-001", "tpm-pcr7", "TPM PCR 7 measurement evidence", UNKNOWN, "high", "medium", truncate(out, 1800), "verify TPM access and collect PCR 7 using trusted attestation tooling", "tpm2_pcrread sha256:7")
		return
	}
	value := regexp.MustCompile(`0x[0-9A-Fa-f]{16,}`).FindString(out)
	if value == "" {
		add(r, "TPM-PCR7-001", "tpm-pcr7", "TPM PCR 7 measurement evidence", UNKNOWN, "high", "medium", truncate(out, 1800), "preserve raw PCR output and obtain a structured TPM attestation/event-log correlation", "tpm2_pcrread")
		return
	}
	add(r, "TPM-PCR7-001", "tpm-pcr7", "TPM PCR 7 measurement evidence", PASS, "high", "high", truncate(out, 1800), "correlate PCR 7 with the TPM event log and Secure Boot policy; PCR presence alone does not prove a known-good state", "TPM PCR 7")
}

// --- Extended firmware assurance checks (v9.0) ------------------------------

func listESPRoots() []string {
	candidates := []string{"/boot/efi", "/efi", "/boot"}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range candidates {
		st, err := os.Stat(p)
		if err != nil || !st.IsDir() || seen[p] || !exists(filepath.Join(p, "EFI")) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func parseGUIDLE(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	a := binary.LittleEndian.Uint32(b[0:4])
	bb := binary.LittleEndian.Uint16(b[4:6])
	c := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", a, bb, c, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func readUintFile(path string) (uint64, error) {
	s, err := readText(path, 128)
	if err != nil {
		return 0, err
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		return strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

func checkSecureBootKeys(r *Report) {
	if !exists("/sys/firmware/efi/efivars") {
		add(r, "SBKEY-000", "secureboot-keys", "Secure Boot trust database inspection", NA, "high", "high", "efivarfs unavailable", "run from UEFI with efivarfs available and inspect PK/KEK/db/dbx", "efivarfs")
		return
	}
	vars := []string{"PK", "KEK", "db", "dbx"}
	issues := []string{}
	details := []string{}
	for _, name := range vars {
		data, attr, path, err := readEFIVar(name)
		if err != nil || len(data) == 0 {
			issues = append(issues, name+" missing/empty")
			continue
		}
		lists := 0
		valid := true
		for off := 0; off+28 <= len(data); {
			listSize := int(binary.LittleEndian.Uint32(data[off+16 : off+20]))
			headerSize := int(binary.LittleEndian.Uint32(data[off+20 : off+24]))
			entrySize := int(binary.LittleEndian.Uint32(data[off+24 : off+28]))
			if listSize < 28 || entrySize <= 0 || headerSize > listSize-28 || off+listSize > len(data) {
				valid = false
				break
			}
			lists++
			off += listSize
		}
		if lists == 0 {
			valid = false
		}
		if !valid {
			issues = append(issues, name+" has no valid EFI_SIGNATURE_LIST structure")
		}
		details = append(details, fmt.Sprintf("%s len=%d lists=%d attr=%s sha512=%s path=%s", name, len(data), lists, efiAttrText(attr), hashBytes(data), filepath.Base(path)))
	}
	st := PASS
	if len(issues) > 0 {
		st = WARN
	}
	evidence := strings.Join(details, "; ")
	if len(issues) > 0 {
		evidence += "; observations=" + strings.Join(issues, ", ")
	}
	add(r, "SBKEY-001", "secureboot-keys", "Secure Boot signature database structure", st, "high", "high", evidence, "compare PK/KEK/db/dbx certificates and hashes with the OEM/platform trust baseline; restore missing/revoked trust data only through an authenticated vendor-supported path", "UEFI authenticated variables")

	if _, err := exec.LookPath("efi-readvar"); err == nil {
		for _, name := range vars {
			out, err := run("efi-readvar", "-v", name)
			if err == nil {
				add(r, "SBKEY-READVAR-"+safeID(name), "secureboot-keys", name+" certificate/signature inventory", PASS, "medium", "high", truncate(out, 3000), "compare certificate fingerprints/owners against a trusted OEM or distribution baseline", "efi-readvar")
			} else {
				add(r, "SBKEY-READVAR-"+safeID(name), "secureboot-keys", name+" certificate/signature inventory", UNKNOWN, "medium", "medium", truncate(out, 1200), "inspect the variable using trusted firmware/efitools tooling", "efi-readvar")
			}
		}
	} else {
		add(r, "SBKEY-002", "secureboot-keys", "Secure Boot certificate fingerprint inventory", NA, "medium", "high", "efi-readvar unavailable; structural validation and SHA-512 database evidence were collected", "install efitools/efi-readvar when certificate-level analysis is required", "PATH")
	}
}

func checkTPMDeepInspection(r *Report) {
	if !exists("/dev/tpmrm0") && !exists("/dev/tpm0") {
		add(r, "TPMDEEP-000", "tpm-deep", "TPM 2.0 deep inspection", NA, "high", "high", "no TPM device node present", "verify platform TPM configuration before requiring TPM-backed attestation", "/dev/tpm*")
		return
	}
	parts := []string{}
	status := PASS
	for _, cap := range []string{"properties-fixed", "properties-variable", "algorithms", "pcrs", "handles-persistent", "handles-nv-index"} {
		out, err := run("tpm2_getcap", cap)
		if err != nil {
			status = UNKNOWN
			parts = append(parts, cap+":ERROR:"+oneLine(out, 900))
			continue
		}
		parts = append(parts, cap+":"+oneLine(out, 1800))
	}
	if out, err := run("tpm2_getrandom", "16"); err == nil {
		parts = append(parts, "getrandom=PASS")
	} else {
		status = UNKNOWN
		parts = append(parts, "getrandom=ERROR:"+oneLine(out, 500))
	}
	if out, err := run("tpm2_pcrread", "sha1:0,7", "sha256:0,7"); err == nil {
		parts = append(parts, "pcrread="+oneLine(out, 2800))
	} else {
		status = UNKNOWN
		parts = append(parts, "pcrread=ERROR:"+oneLine(out, 900))
	}
	add(r, "TPMDEEP-001", "tpm-deep", "TPM 2.0 capability, PCR-bank and handle inspection", status, "high", "high", strings.Join(parts, " | "), "investigate failed TPM capability reads or unexpected persistent/NV handles; correlate PCR 7 with the BIOS event log before relying on the TPM as a trust anchor", "tpm2-tools")
	if out, err := run("tpm2_getcap", "handles-nv-index"); err == nil {
		seen := 0
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "0x") {
				continue
			}
			h := strings.Fields(line)[0]
			pub, e := run("tpm2_nvreadpublic", h)
			st := PASS
			if e != nil {
				st = UNKNOWN
			}
			add(r, "TPM-NV-"+safeID(h), "tpm-deep", "TPM NV index metadata", st, "medium", "medium", truncate(pub, 1800), "validate unexpected NV indexes against the device policy/vendor baseline", "tpm2_nvreadpublic")
			seen++
			if seen >= 24 {
				break
			}
		}
	}
	add(r, "TPMDEEP-002", "tpm-deep", "TPM remote attestation execution", NA, "high", "high", "scanner does not create or approve a remote attestation identity/quote autonomously", "perform a policy-approved TPM quote using a trusted AK and verifier when remote attestation is required", "attestation boundary")
}

func checkSMMExposure(r *Report) {
	cpu, _ := readText("/proc/cpuinfo", 64*1024)
	vendor, _ := readText("/sys/class/dmi/id/sys_vendor", 256)
	product, _ := readText("/sys/class/dmi/id/product_name", 256)
	items := []string{"vendor=" + strings.TrimSpace(vendor), "product=" + strings.TrimSpace(product)}
	intel := strings.Contains(strings.ToLower(cpu), "genuineintel")
	amd := strings.Contains(strings.ToLower(cpu), "authenticamd")
	if intel {
		items = append(items, "cpu=Intel")
	}
	if amd {
		items = append(items, "cpu=AMD")
	}
	status := UNKNOWN
	if out, err := run("fwupdmgr", "security"); err == nil {
		low := strings.ToLower(out)
		for _, line := range strings.Split(out, "\n") {
			ll := strings.ToLower(line)
			if strings.Contains(ll, "smm") || strings.Contains(ll, "callout") {
				items = append(items, oneLine(line, 1100))
			}
		}
		if strings.Contains(low, "smm") || strings.Contains(low, "callout") {
			status = PASS
			if strings.Contains(low, "failed") || strings.Contains(low, "not protected") || strings.Contains(low, "✘") {
				status = WARN
			}
		} else if !intel && !amd {
			status = NA
		}
	} else if !intel && !amd {
		status = NA
	}
	add(r, "SMM-001", "smm-security", "SMM security posture / exploit indicators", status, "high", "medium", strings.Join(items, "; "), "correlate exact OEM firmware/SMM component versions with current vendor advisories; do not infer a CVE from CPU family or an SMM-named driver alone", "fwupd HSI + DMI + CPU")
}

func isPEImage(data []byte) bool {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	off := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	return off >= 0x40 && off+4 <= len(data) && string(data[off:off+4]) == "PE\\x00\\x00"
}

func verifyEFISignature(path string) (string, bool, error) {
	if _, err := os.Stat(path); err != nil {
		return "", false, err
	}
	if _, err := exec.LookPath("sbverify"); err == nil {
		out, err := run("sbverify", "--list", path)
		if err == nil {
			low := strings.ToLower(out)
			return truncate(out, 1400), strings.Contains(low, "signature is valid") || strings.Contains(low, "signer") || strings.Contains(low, "signature 1"), nil
		}
		return truncate(out, 900), false, err
	}
	if _, err := exec.LookPath("pesign"); err == nil {
		out, err := run("pesign", "-S", "-i", path)
		if err == nil {
			low := strings.ToLower(out)
			return truncate(out, 1400), strings.Contains(low, "signed") || strings.Contains(low, "fingerprint"), nil
		}
		return truncate(out, 900), false, err
	}
	return "signature verifier unavailable", false, os.ErrNotExist
}

func checkDXEIntegrity(r *Report) {
	roots := listESPRoots()
	if len(roots) == 0 {
		add(r, "DXE-000", "dxe-integrity", "DXE/EFI driver integrity", NA, "high", "high", "no readable ESP root discovered", "mount the ESP read-only and rerun the forensic profile", "filesystem")
		return
	}
	checked := 0
	unsigned := []string{}
	suspicious := []string{}
	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || info.Size() <= 0 || info.Size() > cfg.MaxFile || !strings.HasSuffix(strings.ToLower(path), ".efi") {
				return nil
			}
			data, e := os.ReadFile(path)
			if e != nil || !isPEImage(data) {
				return nil
			}
			checked++
			out, signed, verr := verifyEFISignature(path)
			if verr == os.ErrNotExist {
				p := strings.ToLower(path)
				if strings.Contains(p, "/efi/boot/") || strings.Contains(p, "/efi/microsoft/boot/") {
					unsigned = append(unsigned, path)
				}
			} else if !signed {
				unsigned = append(unsigned, path)
			}
			base := strings.ToLower(filepath.Base(path))
			if strings.Contains(base, "bootkit") || strings.Contains(base, "rootkit") || strings.Contains(base, "smm") || strings.Contains(base, "dxe") {
				suspicious = append(suspicious, path)
			}
			logf(4, "efi-image path=%s sha512=%s verifier=%s", path, hashBytes(data), oneLine(out, 700))
			return nil
		})
	}
	st := PASS
	if len(unsigned) > 0 || len(suspicious) > 0 {
		st = WARN
	}
	conf := "high"
	if _, err := exec.LookPath("sbverify"); err != nil {
		if _, err2 := exec.LookPath("pesign"); err2 != nil {
			conf = "medium"
		}
	}
	evidence := fmt.Sprintf("PE/COFF EFI images checked=%d; unsigned_or_unverifiable=%d; suspicious_name_indicators=%d", checked, len(unsigned), len(suspicious))
	if len(unsigned) > 0 {
		evidence += "; unsigned=" + truncate(strings.Join(unsigned, ", "), 1800)
	}
	if len(suspicious) > 0 {
		evidence += "; suspicious_names=" + truncate(strings.Join(suspicious, ", "), 1200)
	}
	add(r, "DXE-001", "dxe-integrity", "DXE/EFI driver integrity indicators", st, "high", conf, evidence, "validate flagged EFI binaries against trusted signed OEM/distribution packages; replace unexpected unsigned or modified drivers through the supported boot/firmware update path", "ESP scan + PE/COFF + sbverify/pesign")
}

func checkNVRAMForensics(r *Report) {
	root := "/sys/firmware/efi/efivars"
	if !exists(root) {
		add(r, "NVRAM-F-000", "nvram-forensics", "Deep NVRAM persistence inspection", NA, "high", "high", "efivarfs unavailable", "run on a UEFI host with efivarfs mounted read-only", "efivarfs")
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		add(r, "NVRAM-F-001", "nvram-forensics", "Deep NVRAM persistence inspection", UNKNOWN, "high", "medium", err.Error(), "run with sufficient read privileges", "efivarfs")
		return
	}
	suspicious := []string{}
	pePayloads := []string{}
	for _, ent := range entries {
		b, err := os.ReadFile(filepath.Join(root, ent.Name()))
		if err != nil || len(b) < 4 {
			continue
		}
		name := strings.ToLower(strings.SplitN(ent.Name(), "-", 2)[0])
		payload := b[4:]
		if len(payload) >= 2 && payload[0] == 'M' && payload[1] == 'Z' {
			pePayloads = append(pePayloads, ent.Name())
		}
		preview := strings.ToLower(printable(string(payload[:min(len(payload), 4096)])))
		for _, pat := range []string{"shell", "startup", "bootkit", "rootkit", "backdoor", "payload", "persist", "dxe", "smm", "hook"} {
			if strings.Contains(name, pat) || strings.Contains(preview, pat) {
				suspicious = append(suspicious, ent.Name()+":"+pat)
				break
			}
		}
	}
	st := PASS
	sev := "medium"
	conf := "high"
	if len(suspicious) > 0 || len(pePayloads) > 0 {
		st = WARN
		sev = "high"
		conf = "medium"
	}
	evidence := fmt.Sprintf("variables=%d; suspicious_indicators=%d; PE_like_payloads=%d", len(entries), len(suspicious), len(pePayloads))
	if len(suspicious) > 0 {
		evidence += "; indicators=" + truncate(strings.Join(suspicious, ", "), 2000)
	}
	if len(pePayloads) > 0 {
		evidence += "; PE_like_payloads=" + truncate(strings.Join(pePayloads, ", "), 1200)
	}
	add(r, "NVRAM-F-001", "nvram-forensics", "Deep NVRAM persistence inspection", st, sev, conf, evidence, "inspect flagged variables with vendor/efitools tooling; compare variable hashes, attributes and authenticated-write state against a trusted baseline; never delete variables blindly", "efivarfs full inventory")
}

func checkHardwareRootOfTrust(r *Report) {
	cpu, _ := readText("/proc/cpuinfo", 64*1024)
	items := []string{"arch=" + runtime.GOARCH}
	intel := strings.Contains(strings.ToLower(cpu), "genuineintel")
	amd := strings.Contains(strings.ToLower(cpu), "authenticamd")
	if intel {
		items = append(items, "cpu=Intel")
	}
	if amd {
		items = append(items, "cpu=AMD")
	}
	status := UNKNOWN
	sev := "high"
	conf := "medium"
	if out, err := run("fwupdmgr", "security"); err == nil {
		low := strings.ToLower(out)
		for _, line := range strings.Split(out, "\n") {
			ll := strings.ToLower(line)
			if strings.Contains(ll, "bootguard") || strings.Contains(ll, "boot guard") || strings.Contains(ll, "platform secure boot") || strings.Contains(ll, "psb") || strings.Contains(ll, "trustzone") {
				items = append(items, oneLine(line, 1200))
			}
		}
		if strings.Contains(low, "bootguard") || strings.Contains(low, "boot guard") || strings.Contains(low, "platform secure boot") || strings.Contains(low, "psb") || strings.Contains(low, "trustzone") {
			status = PASS
			conf = "high"
			if strings.Contains(low, "failed") || strings.Contains(low, "not protected") || strings.Contains(low, "✘") {
				status = WARN
			}
		}
	}
	if status == UNKNOWN && runtime.GOARCH == "arm64" {
		status = NA
		sev = "medium"
		items = append(items, "generic Linux userspace cannot independently prove TrustZone state")
	}
	add(r, "ROT-001", "hardware-rot", "Hardware Root of Trust validation", status, sev, conf, strings.Join(items, "; "), "validate Intel Boot Guard, AMD Platform Secure Boot, or ARM secure-world/TrustZone state with OEM/SoC tooling; Linux visibility alone is insufficient for attestation", "fwupd HSI + CPU/architecture")
}

func checkUEFIShellAndEFIApps(r *Report) {
	roots := listESPRoots()
	if len(roots) == 0 {
		add(r, "EFIAPP-000", "uefi-shell", "UEFI Shell and EFI application inventory", NA, "high", "high", "no ESP root discovered", "mount the ESP read-only and rerun firmware forensics", "filesystem")
		return
	}
	shells := []string{}
	apps := []string{}
	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".efi") || info.Size() > cfg.MaxFile {
				return nil
			}
			base := strings.ToLower(filepath.Base(path))
			if base == "shell.efi" || strings.HasPrefix(base, "shell") || strings.Contains(base, "uefi-shell") {
				shells = append(shells, path)
			} else {
				apps = append(apps, path)
			}
			return nil
		})
	}
	st := PASS
	sev := "medium"
	if len(shells) > 0 {
		st = WARN
		sev = "high"
	}
	evidence := fmt.Sprintf("EFI applications=%d; shell_candidates=%d", len(apps), len(shells))
	if len(shells) > 0 {
		evidence += "; shells=" + truncate(strings.Join(shells, ", "), 1800)
	}
	add(r, "EFIAPP-001", "uefi-shell", "UEFI Shell and EFI application inventory", st, sev, "high", evidence, "remove/restrict unexpected UEFI Shell binaries and validate EFI executables against signed OEM/distribution packages and the Secure Boot trust chain", "ESP filesystem inventory")
}

func checkPCIOptionROMs(r *Report) {
	root := "/sys/bus/pci/devices"
	if !exists(root) {
		add(r, "PCIROM-000", "pci-option-rom", "PCI Option ROM inventory", NA, "medium", "high", "PCI sysfs inventory unavailable", "run on a Linux host exposing PCI sysfs", "sysfs")
		return
	}
	devices, _ := os.ReadDir(root)
	readable := 0
	entries := []string{}
	for _, d := range devices {
		p := filepath.Join(root, d.Name(), "rom")
		st, err := os.Stat(p)
		if err != nil || st.Size() <= 0 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil || len(b) == 0 {
			continue
		}
		readable++
		entries = append(entries, fmt.Sprintf("%s len=%d sha512=%s pe=%t", d.Name(), len(b), hashBytes(b), isPEImage(b)))
	}
	if readable == 0 {
		add(r, "PCIROM-001", "pci-option-rom", "PCI Option ROM inventory", NA, "medium", "high", fmt.Sprintf("no Option ROM data readable without enabling ROM access; devices=%d", len(devices)), "use vendor-supported offline PCI ROM acquisition when Option ROM integrity is in scope; scanner does not write to ROM sysfs enable controls", "PCI sysfs read-only")
		return
	}
	add(r, "PCIROM-001", "pci-option-rom", "PCI Option ROM inventory", PASS, "medium", "high", fmt.Sprintf("readable_option_roms=%d; %s", readable, truncate(strings.Join(entries, " | "), 4200)), "compare Option ROM hashes/signatures with the device OEM baseline and investigate unexpected changes", "PCI sysfs read-only")
}

func checkAntiRollback(r *Report) {
	root := "/sys/firmware/efi/esrt/entries"
	entries, err := os.ReadDir(root)
	if err != nil {
		add(r, "ROLLBACK-000", "anti-rollback", "Firmware anti-rollback state", NA, "high", "high", "ESRT entries unavailable", "use OEM firmware tooling to validate rollback protection and minimum supported firmware versions", "ESRT")
		return
	}
	violations := []string{}
	atMin := []string{}
	count := 0
	for _, e := range entries {
		base := filepath.Join(root, e.Name())
		cur, e1 := readUintFile(filepath.Join(base, "fw_version"))
		minv, e2 := readUintFile(filepath.Join(base, "lowest_supported_fw_version"))
		if e1 != nil || e2 != nil {
			continue
		}
		count++
		typ, _ := readText(filepath.Join(base, "fw_type"), 128)
		item := fmt.Sprintf("%s fw=%d lowest=%d type=%s", e.Name(), cur, minv, strings.TrimSpace(typ))
		if cur < minv {
			violations = append(violations, item)
		} else if cur == minv {
			atMin = append(atMin, item)
		}
	}
	st := PASS
	if len(violations) > 0 {
		st = FAIL
	} else if len(atMin) > 0 {
		st = WARN
	}
	sev := "high"
	evidence := fmt.Sprintf("entries_with_version_policy=%d; below_minimum=%d; at_minimum=%d", count, len(violations), len(atMin))
	if len(violations) > 0 {
		evidence += "; violations=" + strings.Join(violations, " | ")
	}
	if len(atMin) > 0 {
		evidence += "; at_minimum=" + strings.Join(atMin, " | ")
	}
	add(r, "ROLLBACK-001", "anti-rollback", "Firmware anti-rollback / minimum supported version", st, sev, "high", evidence, "update affected firmware to a vendor-supported version at or above the ESRT lowest-supported version; investigate any current<lowest state as a serious integrity issue", "UEFI ESRT")
}

func checkSideChannelMitigations(r *Report) {
	root := "/sys/devices/system/cpu/vulnerabilities"
	if !exists(root) {
		add(r, "SIDE-000", "side-channels", "CPU side-channel mitigation inventory", NA, "high", "high", "kernel vulnerability sysfs interface unavailable", "use a supported kernel exposing CPU vulnerability mitigation status", "sysfs")
		return
	}
	files := []string{"spectre_v1", "spectre_v2", "meltdown", "l1tf", "mds", "tsx_async_abort", "retbleed", "spec_rstack_overflow", "gather_data_sampling", "reg_file_data_sampling", "branch_history_injection", "mmio_stale_data", "spec_store_bypass", "srbds", "itlb_multihit", "rfds"}
	vuln := []string{}
	good := []string{}
	other := []string{}
	for _, n := range files {
		data, err := readText(filepath.Join(root, n), 2048)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(data)
		low := strings.ToLower(v)
		switch {
		case strings.HasPrefix(low, "vulnerable") && !strings.Contains(low, "mitigation"):
			vuln = append(vuln, n+"="+v)
		case strings.Contains(low, "mitigation:") || strings.Contains(low, "not affected"):
			good = append(good, n+"="+v)
		default:
			other = append(other, n+"="+v)
		}
	}
	st := PASS
	sev := "medium"
	if len(vuln) > 0 {
		st = WARN
		sev = "high"
	}
	evidence := fmt.Sprintf("mitigated_or_not_affected=%d; vulnerable=%d; other=%d", len(good), len(vuln), len(other))
	if len(vuln) > 0 {
		evidence += "; vulnerable=" + truncate(strings.Join(vuln, " | "), 2800)
	}
	if len(good) > 0 {
		evidence += "; mitigated=" + truncate(strings.Join(good, " | "), 2500)
	}
	if len(other) > 0 {
		evidence += "; other=" + truncate(strings.Join(other, " | "), 1800)
	}
	add(r, "SIDE-001", "side-channels", "CPU side-channel mitigation inventory", st, sev, "high", evidence, "apply current CPU microcode/kernel updates and resolve vulnerability files reporting an unmitigated vulnerable state; follow Linux CPU-vulnerability guidance for the relevant attack vector", "Linux CPU vulnerability sysfs")
}

func checkMicrocodePosture(r *Report) {
	paths := []string{"/sys/devices/system/cpu/microcode/version", "/sys/devices/system/cpu/cpu0/microcode/version", "/sys/devices/system/cpu/microcode/revision"}
	vals := []string{}
	for _, p := range paths {
		if s, err := readText(p, 512); err == nil && strings.TrimSpace(s) != "" {
			vals = append(vals, p+"="+strings.TrimSpace(s))
		}
	}
	if out, err := run("journalctl", "-k", "-b", "--no-pager", "-n", "200"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(strings.ToLower(line), "microcode") {
				vals = append(vals, "kernel="+oneLine(line, 1200))
			}
		}
	}
	if len(vals) == 0 {
		add(r, "MICROCODE-001", "microcode", "CPU microcode posture", UNKNOWN, "high", "medium", "microcode version/revision not exposed through inspected interfaces", "verify current CPU microcode through kernel logs and the OEM firmware update path", "sysfs + kernel log")
		return
	}
	add(r, "MICROCODE-001", "microcode", "CPU microcode posture", PASS, "high", "medium", strings.Join(vals, "; "), "correlate the observed microcode revision with the CPU vendor/OEM security advisory baseline; presence alone does not prove freshness", "microcode sysfs + kernel log")
}

func checkVirtualizationEscapeIndicators(r *Report) {
	dmi, _ := readText("/sys/class/dmi/id/product_name", 256)
	lowdmi := strings.ToLower(dmi)
	isVM := false
	for _, x := range []string{"kvm", "qemu", "vmware", "virtualbox", "xen", "bochs", "hyper-v", "microsoft corporation"} {
		if strings.Contains(lowdmi, x) {
			isVM = true
			break
		}
	}
	if !isVM {
		add(r, "VIRT-ESC-000", "virtualization-escape", "Virtualization escape exposure", NA, "high", "high", "host does not expose a common virtual-machine DMI identity; guest-to-host escape testing is not applicable from this host context", "run guest escape assessment from inside the affected virtual machine and correlate hypervisor/security advisories when virtualization is in scope", "DMI")
		return
	}
	items := []string{"dmi=" + strings.TrimSpace(dmi)}
	mods, _ := readText("/proc/modules", 2*1024*1024)
	for _, x := range []string{"kvm", "vhost", "vhost_net", "vhost_vsock", "vsock", "virtio", "virtiofs", "9p"} {
		if strings.Contains(strings.ToLower(mods), x) {
			items = append(items, "module="+x)
		}
	}
	vuln := []string{}
	vdir := "/sys/devices/system/cpu/vulnerabilities"
	for _, n := range []string{"vmscape", "branch_history_injection", "spectre_v2", "retbleed", "gather_data_sampling", "mmio_stale_data"} {
		if data, err := readText(filepath.Join(vdir, n), 1024); err == nil {
			v := strings.TrimSpace(data)
			if strings.HasPrefix(strings.ToLower(v), "vulnerable") && !strings.Contains(strings.ToLower(v), "mitigation") {
				vuln = append(vuln, n+"="+v)
			}
		}
	}
	logOut := ""
	if out, err := run("journalctl", "-k", "-b", "--no-pager", "-n", "300"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			ll := strings.ToLower(line)
			if strings.Contains(ll, "qemu") || strings.Contains(ll, "vmware") || strings.Contains(ll, "hyper-v") || strings.Contains(ll, "virtio") || strings.Contains(ll, "vsock") {
				logOut += oneLine(line, 700) + " | "
			}
		}
	}
	st := PASS
	sev := "medium"
	if len(vuln) > 0 {
		st = WARN
		sev = "high"
	}
	conf := "medium"
	evidence := strings.Join(items, "; ")
	if len(vuln) > 0 {
		evidence += "; vulnerable_cpu_controls=" + strings.Join(vuln, " | ")
	}
	if logOut != "" {
		evidence += "; hypervisor_log_indicators=" + truncate(logOut, 2200)
	}
	add(r, "VIRT-ESC-001", "virtualization-escape", "Virtualization escape exposure indicators", st, sev, conf, evidence, "keep the hypervisor and guest kernel/microcode current; resolve any guest-to-host vulnerability shown as unmitigated; investigate correlated hypervisor logs separately because generic virtio/vsock activity is not evidence of an escape", "DMI + kernel modules + CPU vulnerability sysfs + kernel log")
}

func checkCapsuleResults(r *Report) {
	root := "/sys/firmware/efi/efivars"
	if !exists(root) {
		add(r, "CAPS-RES-000", "capsule-results", "UEFI capsule processing result variables", NA, "medium", "high", "efivarfs unavailable", "run in UEFI mode with efivarfs to inspect capsule result variables", "efivarfs")
		return
	}
	matches := []string{}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if strings.Contains(name, "capsule") || strings.Contains(name, "lastattempt") {
			b, err := os.ReadFile(filepath.Join(root, e.Name()))
			if err == nil {
				payload := b
				if len(payload) > 4 {
					payload = b[4:]
				}
				matches = append(matches, fmt.Sprintf("%s len=%d sha512=%s", e.Name(), len(payload), hashBytes(payload[:min(len(payload), 4096)])))
			}
		}
	}
	if len(matches) == 0 {
		add(r, "CAPS-RES-001", "capsule-results", "UEFI capsule processing result variables", NA, "medium", "high", "no capsule-related result variables exposed", "use OEM/fwupd update history when capsule processing provenance is required", "efivarfs")
		return
	}
	add(r, "CAPS-RES-001", "capsule-results", "UEFI capsule processing result variables", PASS, "medium", "high", strings.Join(matches, "; "), "correlate capsule result variables and firmware-update history with authorized maintenance records", "efivarfs")
}

func checkFirmwareCapsules(r *Report) {
	roots := []string{"/boot/efi", "/efi", "/var/lib/fwupd", "/var/cache/fwupd"}
	candidates := []string{}
	for _, root := range roots {
		if !exists(root) {
			continue
		}
		_ = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || info.Size() <= 0 || info.Size() > cfg.MaxFile {
				return nil
			}
			low := strings.ToLower(path)
			if strings.HasSuffix(low, ".cap") || strings.HasSuffix(low, ".capsule") || strings.Contains(low, "capsule") {
				candidates = append(candidates, path)
			}
			return nil
		})
	}
	if len(candidates) == 0 {
		add(r, "CAP-001", "firmware-capsules", "UEFI firmware capsule inventory", NA, "high", "high", "no staged capsule artifacts found in inspected paths", "include vendor/fwupd capsule staging paths during offline firmware investigation when capsule history is relevant", "filesystem inventory")
		return
	}
	valid := 0
	invalid := []string{}
	details := []string{}
	const fmpGUID = "6dcbd5ed-e82d-4c44-bda1-7194199ad92a"
	for _, path := range candidates {
		b, err := os.ReadFile(path)
		if err != nil || len(b) < 28 {
			invalid = append(invalid, path+":short/unreadable")
			continue
		}
		guid := parseGUIDLE(b[:16])
		headerSize := binary.LittleEndian.Uint32(b[16:20])
		flags := binary.LittleEndian.Uint32(b[20:24])
		imageSize := binary.LittleEndian.Uint32(b[24:28])
		ok := headerSize >= 28 && uint64(headerSize) <= uint64(len(b)) && uint64(imageSize) == uint64(len(b))
		if guid == fmpGUID && ok && len(b) >= int(headerSize)+8 {
			body := b[headerSize:]
			if len(body) >= 8 {
				ver := binary.LittleEndian.Uint32(body[:4])
				drivers := binary.LittleEndian.Uint16(body[4:6])
				payloads := binary.LittleEndian.Uint16(body[6:8])
				if ver != 1 || drivers+payloads == 0 {
					ok = false
				}
			}
		}
		details = append(details, fmt.Sprintf("%s guid=%s header=%d image=%d flags=0x%08x sha512=%s", path, guid, headerSize, imageSize, flags, hashBytes(b)))
		if ok {
			valid++
		} else {
			invalid = append(invalid, path)
		}
	}
	st := PASS
	if len(invalid) > 0 {
		st = WARN
	}
	if len(invalid) == len(candidates) {
		st = FAIL
	}
	evidence := fmt.Sprintf("candidate_capsules=%d; structurally_valid=%d; invalid=%d; %s", len(candidates), valid, len(invalid), truncate(strings.Join(details, " | "), 4200))
	if len(invalid) > 0 {
		evidence += "; invalid=" + truncate(strings.Join(invalid, ", "), 1800)
	}
	add(r, "CAP-001", "firmware-capsules", "UEFI firmware capsule structural validation", st, "high", "high", evidence, "quarantine and validate malformed/unexpected capsules with vendor tooling; require authenticated FMP payloads and trusted firmware-update provenance before deployment; structure anomalies are indicators, not proof of a malicious capsule", "UEFI capsule header/FMP parser")
}

func checkVulnerabilityKnowledgeBase(r *Report) {
	items := make([]string, 0, len(uefiVulnerabilities2025))
	for _, v := range uefiVulnerabilities2025 {
		items = append(items, v.CVE+"="+v.Name)
	}
	add(r, "VULN-KB-001", "vulnerability-knowledge", "UEFI vulnerability knowledge base", NA, "info", "high", strings.Join(items, "; "), "correlate exact OEM firmware/component versions with current advisories before declaring a CVE applicable", "local knowledge base")
}
