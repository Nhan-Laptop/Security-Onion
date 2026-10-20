# ==============================================================================
# Script: endpoint_simulation.ps1
# Purpose: Simulate Suspicious Endpoint Behaviors (T1059.001, T1082, T1057)
# Target: Windows Endpoint with Elastic Agent + Sysmon
# Output: Triggers Sysmon Event ID 1 (Process Create), Event ID 3 (Network)
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [!] BAT DAU MO PHONG HANH VI ENDPOINT (SCENARIO 4)" -ForegroundColor Yellow
Write-Host " MITRE ATT&CK: T1059.001 (PowerShell), T1082 (Discovery)" -ForegroundColor Green
Write-Host " Thoi gian: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Benign Execution Marker (Dau vet nhan dien kiem thu)
Write-Host "`n[*] Buoc 1: Chay lenh voi Marker kiem thu dac biet..." -ForegroundColor Yellow
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SO-LAB-POWERSHELL-MARKER-2026'"

# 2. System Information Discovery (T1082) & Process Discovery (T1057)
Write-Host "[*] Buoc 2: Mo phong do quet thong tin he thong (Discovery)..." -ForegroundColor Yellow
cmd.exe /c "whoami && hostname && net user"
cmd.exe /c "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""

# 3. Encoded PowerShell Execution (T1059.001 - Ma hoa Base64 thuong gap trong malware)
Write-Host "[*] Buoc 3: Mo phong chay lenh PowerShell ma hoa Base64 (-EncodedCommand)..." -ForegroundColor Yellow
# Chuoi ro: "Write-Output 'SO-LAB-ENCODED-EXECUTION'"
$plainCommand = "Write-Output 'SO-LAB-ENCODED-EXECUTION'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($plainCommand)
$encodedCommand = [Convert]::ToBase64String($bytes)

Write-Host "    Payload Base64: $encodedCommand" -ForegroundColor DarkGray
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encodedCommand

# 4. Simulated Suspicious Outbound Connection (T1071.001 / Sysmon Event ID 3)
Write-Host "[*] Buoc 4: Mo phong ket noi HTTP tu tien trinh la..." -ForegroundColor Yellow
powershell.exe -NoProfile -Command "try { Invoke-WebRequest -Uri 'http://192.168.182.10:80/endpoint-test' -TimeoutSec 3 -UseBasicParsing } catch { Write-Host 'Connection logged.' }"

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " [V] HOAN TAT MO PHONG ENDPOINT!" -ForegroundColor Green
Write-Host " Bay gio hay vao Security Onion SOC -> Hunt de dieu tra:" -ForegroundColor Yellow
Write-Host " - Query 1: event.dataset:\"windows.sysmon_operational\" AND process.command_line:*SO-LAB-*" -ForegroundColor White
Write-Host " - Query 2: process.name:\"powershell.exe\" AND process.command_line:*-EncodedCommand*" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
