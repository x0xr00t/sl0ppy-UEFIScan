Write-Host "--- LEGACY & DRIVER INTEGRITY SCANNER ---" -ForegroundColor Cyan
Write-Host "Geïnspireerd op sl0ppy-UEFIScan voor Legacy systemen" -ForegroundColor Gray
Write-Host ""

# --- STAP 1: Controleer Boot Modus ---
$isUefi = $true
try {
    $null = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
} catch {
    $isUefi = $false
}

if (-not $isUefi) {
    Write-Host "[!] Systeem draait in LEGACY BIOS modus." -ForegroundColor Yellow
} else {
    Write-Host "[V] Systeem draait in UEFI modus." -ForegroundColor Green
}

# --- STAP 2: Scan BCD (Boot Configuration Data) ---
# De tool zoekt naar 'testsigning' of 'nointegritychecks' die malware vaak aanzet
Write-Host "`n[1/4] Scant BCD op onveilige instellingen..." -ForegroundColor Yellow
$bcd = bcdedit /enum ALL | Out-String

$unsafeFlags = @("testsigning", "nointegritychecks", "disable-elam")
foreach ($flag in $unsafeFlags) {
    if ($bcd -match $flag) {
        Write-Host "  [X] GEVAAR: '$flag' gevonden in BCD! Dit staat malware toe drivers te laden." -ForegroundColor Red
    } else {
        Write-Host "  [V] '$flag' is niet actief." -ForegroundColor Green
    }
}

# --- STAP 3: Scan Driver Integriteit (ddc.dll & monitor.sys) ---
Write-Host "`n[2/4] Controleert kritieke display bestanden..." -ForegroundColor Yellow
$filesToScan = @(
    "$env:SystemRoot\System32\ddc.dll",
    "$env:SystemRoot\System32\drivers\monitor.sys"
)

foreach ($file in $filesToScan) {
    if (Test-Path $file) {
        $sig = Get-AuthenticodeSignature -FilePath $file
        $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
        
        if ($sig.Status -eq "Valid") {
            Write-Host "  [V] OK: $(Split-Path $file -Leaf) is geldig ondertekend." -ForegroundColor Green
        } else {
            Write-Host "  [X] WAARSCHUWING: $(Split-Path $file -Leaf) is NIET ondertekend of aangepast!" -ForegroundColor Red
            Write-Host "      Hash: $hash" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [-] Info: $(Split-Path $file -Leaf) niet gevonden op dit systeem." -ForegroundColor Gray
    }
}

# --- STAP 4: Scan Boot Sectoren (Legacy MBR check) ---
if (-not $isUefi) {
    Write-Host "`n[3/4] Controleert MBR status (Legacy)..." -ForegroundColor Yellow
    Write-Host "  [!] Let op: PowerShell kan de fysieke MBR niet direct 'lezen' zonder extra tools." -ForegroundColor Gray
    Write-Host "  [!] Controleert op vreemde schijfpartities..." -ForegroundColor Gray
    Get-Partition | Select-Object DiskNumber, PartitionNumber, Size, Type | Format-Table
}

# --- STAP 5: Scan Automatisch Ladende Drivers ---
Write-Host "`n[4/4] Scant geladen drivers op certificaat-status..." -ForegroundColor Yellow
Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq "Running" } | Select-Object -First 10 | ForEach-Object {
    $path = $_.PathName
    if ($path -and (Test-Path $path)) {
        $s = Get-AuthenticodeSignature $path
        if ($s.Status -ne "Valid") {
            Write-Host "  [?] Onbekende Driver: $($_.DisplayName) ($path)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n--- SCAN VOLTOOID ---" -ForegroundColor Cyan
Write-Host "Als je rode meldingen ziet: Run 'sfc /scannow' en 'DISM /Online /Cleanup-Image /RestoreHealth'" -ForegroundColor White
