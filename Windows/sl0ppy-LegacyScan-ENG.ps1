Write-Host "--- LEGACY & DRIVER INTEGRITY SCANNER ---" -ForegroundColor Cyan
Write-Host "Inspired by sl0ppy-UEFIScan for Legacy systems" -ForegroundColor Gray
Write-Host ""

# --- STEP 1: Check Boot Mode ---
$isUefi = $true
try {
    $null = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
} catch {
    $isUefi = $false
}

if (-not $isUefi) {
    Write-Host "[!] System is running in LEGACY BIOS mode." -ForegroundColor Yellow
} else {
    Write-Host "[V] System is running in UEFI mode." -ForegroundColor Green
}

# --- STEP 2: Scan BCD (Boot Configuration Data) ---
# The tool looks for 'testsigning' or 'nointegritychecks' which malware often enables
Write-Host "`n[1/4] Scanning BCD for insecure settings..." -ForegroundColor Yellow
$bcd = bcdedit /enum ALL | Out-String

$unsafeFlags = @("testsigning", "nointegritychecks", "disable-elam")
foreach ($flag in $unsafeFlags) {
    if ($bcd -match $flag) {
        Write-Host "  [X] DANGER: '$flag' found in BCD! This allows malware to load unsigned drivers." -ForegroundColor Red
    } else {
        Write-Host "  [V] '$flag' is not active." -ForegroundColor Green
    }
}

# --- STEP 3: Scan Driver Integrity (ddc.dll & monitor.sys) ---
Write-Host "`n[2/4] Checking critical display files..." -ForegroundColor Yellow
$filesToScan = @(
    "$env:SystemRoot\System32\ddc.dll",
    "$env:SystemRoot\System32\drivers\monitor.sys"
)

foreach ($file in $filesToScan) {
    if (Test-Path $file) {
        $sig = Get-AuthenticodeSignature -FilePath $file
        $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
        
        if ($sig.Status -eq "Valid") {
            Write-Host "  [V] OK: $(Split-Path $file -Leaf) is validly signed." -ForegroundColor Green
        } else {
            Write-Host "  [X] WARNING: $(Split-Path $file -Leaf) is NOT signed or has been modified!" -ForegroundColor Red
            Write-Host "      Hash: $hash" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [-] Info: $(Split-Path $file -Leaf) not found on this system." -ForegroundColor Gray
    }
}

# --- STEP 4: Scan Boot Sectors (Legacy MBR check) ---
if (-not $isUefi) {
    Write-Host "`n[3/4] Checking MBR status (Legacy)..." -ForegroundColor Yellow
    Write-Host "  [!] Note: PowerShell cannot read the physical MBR directly without extra tools." -ForegroundColor Gray
    Write-Host "  [!] Checking for unusual disk partitions..." -ForegroundColor Gray
    Get-Partition | Select-Object DiskNumber, PartitionNumber, Size, Type | Format-Table
}

# --- STEP 5: Scan Auto-Loading Drivers ---
Write-Host "`n[4/4] Scanning loaded drivers for certificate status..." -ForegroundColor Yellow
Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq "Running" } | Select-Object -First 10 | ForEach-Object {
    $path = $_.PathName
    if ($path -and (Test-Path $path)) {
        $s = Get-AuthenticodeSignature $path
        if ($s.Status -ne "Valid") {
            Write-Host "  [?] Unknown Driver: $($_.DisplayName) ($path)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n--- SCAN COMPLETE ---" -ForegroundColor Cyan
Write-Host "If you see red alerts: Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'" -ForegroundColor White
