# Setup script for https://securityshells.com
# Requires Administrator permissions

$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$certPath = "$PSScriptRoot\cert.pem"

Write-Host "[*] Configuring hosts file..." -ForegroundColor Cyan
$hostsContent = Get-Content -Path $hostsFile -Raw -ErrorAction SilentlyContinue

$entriesToAdd = @(
    "127.0.0.1  securityshells.com",
    "127.0.0.1  www.securityshells.com"
)

$needsUpdate = $false
foreach ($entry in $entriesToAdd) {
    if ($hostsContent -notmatch [regex]::Escape($entry.Split()[1])) {
        $needsUpdate = $true
    }
}

if ($needsUpdate) {
    $newLines = "`r`n# SecurityShells Domain Mapping`r`n" + ($entriesToAdd -join "`r`n") + "`r`n"
    Add-Content -Path $hostsFile -Value $newLines -Encoding ascii
    Write-Host "[+] Added securityshells.com to hosts file." -ForegroundColor Green
} else {
    Write-Host "[i] securityshells.com already configured in hosts file." -ForegroundColor Yellow
}

Write-Host "[*] Flushing DNS..." -ForegroundColor Cyan
& ipconfig /flushdns | Out-Null
Write-Host "[+] DNS cache flushed." -ForegroundColor Green

if (Test-Path $certPath) {
    Write-Host "[*] Installing SSL certificate into Trusted Root Authority..." -ForegroundColor Cyan
    try {
        certutil -addstore -f "Root" $certPath | Out-Null
        Write-Host "[+] SSL Certificate installed into Windows Trusted Root store! Browsers will show secure padlock." -ForegroundColor Green
    } catch {
        Write-Host "[-] Warning: Could not install cert into Trusted Root: $_" -ForegroundColor Red
    }
}

Write-Host "`n[SUCCESS] https://securityshells.com is fully configured and ready!" -ForegroundColor Green
Start-Sleep -Seconds 2
