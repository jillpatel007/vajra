# Vajra

**Multi-cloud attack path intelligence platform.**

Vajra discovers attack paths across 7 cloud providers, mathematically proves the minimum set of fixes to eliminate them, and signs every report with cryptographic tamper evidence.

## Why Vajra

| Feature | Vajra | Wiz | Prowler | ScoutSuite |
|---------|-------|-----|---------|------------|
| Graph-based attack paths | Yes | Partial | No | No |
| Mathematical minimum cut proof | Yes | No | No | No |
| Self-verifying analysis | Yes | No | No | No |
| Signed reports (HMAC-SHA256) | Yes | No | No | No |
| 7 cloud providers | Yes | 3 | 3 | 4 |
| Cedar condition evaluation | Yes | No | No | No |
| Financial exposure model | Yes | No | No | No |
| Open source | Apache 2.0 | No | Yes | Yes |

## Install

```bash
pip install vajra
```

## Quick Start

```bash
# Scan AWS infrastructure
vajra scan --providers aws

# Scan multiple clouds
vajra scan --providers aws,azure,gcp

# Check a Terraform plan for new attack paths
vajra plan tfplan.json

# Run with demo data (no credentials needed)
vajra scan --demo
```

## Architecture

```
CloudQuery  -->  DuckDB  -->  VajraGraph  -->  Cedar      -->  APIM       -->  Signed Report
  (scan)        (store)      (rustworkx)     (conditions)    (scoring)       (HMAC-SHA256)
                                  |               |              |
                            attack paths    FP reduction    risk ranking
                            minimum cut     default-DENY    exploit probability
```

## Supported Providers

| Provider | Assets Discovered |
|----------|-------------------|
| AWS | IAM Roles, EC2, S3, Lambda, RDS, Secrets Manager |
| Azure | Service Principals, Key Vaults, Storage Accounts |
| GCP | Service Accounts, IAM Bindings, GCS Buckets |
| Alibaba | RAM Roles, OSS Buckets |
| Tencent | CAM Roles |
| Huawei | IAM Agencies |
| Kubernetes | Service Accounts, Cluster Roles |

## How It Works

1. **Discover** — CloudQuery scans your infrastructure into DuckDB
2. **Build** — Vajra constructs a directed attack graph (entry points to crown jewels)
3. **Evaluate** — Cedar engine evaluates IAM conditions, eliminating false positives
4. **Prove** — Stoer-Wagner minimum cut algorithm finds the mathematically smallest fix set
5. **Score** — APIM ranks paths by real-world exploit probability (CISA KEV, EPSS, Falco)
6. **Sign** — Every report is HMAC-SHA256 signed with proof certificate

## CI Pipeline

Every commit runs:

| Tool | Purpose |
|------|---------|
| ruff | Code quality + formatting |
| mypy | Type safety (strict mode) |
| bandit | Static security analysis |
| detect-secrets | Credential leak prevention |
| pytest | 226 tests including enterprise security suite |

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

All external input is validated against 6 injection families (XSS, SQL, Log4Shell, path traversal, template injection, null byte). Reports are cryptographically signed. The tool self-verifies its own integrity at startup.

## License

Apache 2.0 — see [LICENSE](LICENSE).
