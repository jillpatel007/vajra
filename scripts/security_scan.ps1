# Vajra Daily Security Scan
# Run this every day before committing
# Industry standard: every finding gets a verdict

Write-Host "`n=== VAJRA SECURITY SCAN ===" -ForegroundColor Cyan
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n"

$failures = 0

# --- TOOL 1: Ruff (code quality) ---
Write-Host "[1/5] Ruff — code quality" -ForegroundColor Yellow
uv run ruff check vajra/
if ($LASTEXITCODE -ne 0) { $failures++ }

# --- TOOL 2: Bandit (security scan) ---
Write-Host "`n[2/5] Bandit — security scan" -ForegroundColor Yellow
uv run bandit -r vajra/ -ll -q
if ($LASTEXITCODE -ne 0) { $failures++ }

# --- TOOL 3: Detect-secrets ---
Write-Host "`n[3/5] Detect-secrets — secret scan" -ForegroundColor Yellow
$secrets = uv run detect-secrets scan vajra/ | ConvertFrom-Json
if ($secrets.results.PSObject.Properties.Count -gt 0) {
    Write-Host "SECRETS FOUND — investigate immediately" -ForegroundColor Red
    $failures++
} else {
    Write-Host "Clean — no secrets found" -ForegroundColor Green
}

# --- TOOL 4: pip-audit (supply chain) ---
Write-Host "`n[4/5] pip-audit — supply chain" -ForegroundColor Yellow
uv run pip-audit --ignore-vuln CVE-2026-4539
if ($LASTEXITCODE -ne 0) { $failures++ }

# --- TOOL 5: pytest ---
Write-Host "`n[5/5] pytest — security contracts" -ForegroundColor Yellow
uv run pytest tests/ -v --tb=short -q
if ($LASTEXITCODE -ne 0) { $failures++ }

# --- SUMMARY ---
Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Cyan
if ($failures -eq 0) {
    Write-Host "ALL CLEAN — safe to commit" -ForegroundColor Green
} else {
    Write-Host "$failures tool(s) failed - DO NOT commit until resolved" -ForegroundColor Red
}
