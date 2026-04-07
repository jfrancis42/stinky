# analyze.py - Security Analysis Tool

Analyzes stinky.json captures and generates comprehensive security reports.

## Features

### Comprehensive Analysis
- **Post-Quantum Security Assessment** - Identifies quantum-vulnerable connections
- **Weak Crypto Detection** - Finds deprecated TLS versions, broken ciphers
- **Forward Secrecy Analysis** - Identifies connections without perfect forward secrecy
- **Risk Scoring** - Calculates overall security risk (0-100 scale)
- **Protocol Distribution** - Shows what protocols are being used
- **Connection Analysis** - Top talkers, server names, patterns
- **Actionable Recommendations** - Prioritized remediation steps

### Multiple Output Formats
- **Text** - Console-friendly format
- **Markdown** - GitHub-compatible documentation
- **HTML** - Web-viewable report with styling
- **JSON** - Machine-readable for automation

## Installation

No additional dependencies required - uses Python standard library.

```bash
cd ~/stinky
chmod +x analyze.py
```

## Usage

### Basic Usage

Analyze stinky.json (default):
```bash
./analyze.py
```

### Specify Input File

```bash
./analyze.py /path/to/captures.json
```

Or:
```bash
./analyze.py -f /path/to/captures.json
```

### Output Formats

#### Text Report (default)
```bash
./analyze.py stinky.json
```

#### Markdown Report
```bash
./analyze.py -F markdown -o report.md
```

#### HTML Report
```bash
./analyze.py -F html -o report.html
```

#### JSON Report
```bash
./analyze.py -F json -o report.json
```

### Time Filtering

Analyze only recent captures:
```bash
./analyze.py --since "2026-04-05T12:00:00"
```

Analyze captures before a time:
```bash
./analyze.py --before "2026-04-05T18:00:00"
```

Time range:
```bash
./analyze.py --since "2026-04-05T12:00:00" --before "2026-04-05T18:00:00"
```

### Output to File

```bash
./analyze.py -o security_report.txt
./analyze.py -F markdown -o report.md
./analyze.py -F html -o report.html
```

### Verbose Mode

```bash
./analyze.py -v stinky.json
```

Shows:
- Number of captures loaded
- Number after filtering
- Analysis progress
- Output file location

## Output Sections

### 1. Executive Summary
- Risk level (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL)
- Risk score (0-100, higher = more risk)
- Total captures
- Analysis time period
- Duration

### 2. Post-Quantum Security Status
- ✅ Post-Quantum Secure count & percentage
- 🔐 Hybrid (PQ+Classical) count & percentage
- ⚠️ Quantum-Vulnerable count & percentage
- ❓ Unknown count

### 3. Critical Findings
Sorted by severity (CRITICAL > HIGH > MEDIUM > LOW):
- **Category** - Type of issue
- **Count** - Number of affected connections
- **Description** - What the issue is
- **Impact** - Security implications
- **Examples** - Specific instances

### 4. TLS Version Distribution
- Shows all TLS/DTLS versions seen
- Flags deprecated versions (SSL 3.0, TLS 1.0, TLS 1.1)
- Counts and percentages

### 5. Top 10 Cipher Suites
- Most frequently used cipher suites
- Counts and percentages
- Helps identify weak crypto patterns

### 6. Protocol Distribution
- All protocols detected
- Counts and percentages
- Shows protocol diversity

### 7. Top Server Names (SNI)
- Top 10 most accessed servers
- Useful for understanding traffic patterns

### 8. Recommendations
Prioritized action items:
- **Priority** - CRITICAL/HIGH/MEDIUM/LOW
- **Category** - What area to address
- **Action** - What to do
- **Details** - Specific steps

## Risk Scoring

The risk score (0-100) is calculated based on:

**Post-Quantum Vulnerability (25 points):**
- Percentage of connections using quantum-vulnerable crypto

**Weak TLS Versions (25 points):**
- Percentage using SSL 3.0, TLS 1.0, or TLS 1.1

**Weak Cipher Suites (30 points):**
- Percentage using RC4, 3DES, MD5, or other broken ciphers

**No Forward Secrecy (20 points):**
- Percentage using RSA key exchange (no PFS)

**Risk Levels:**
- **CRITICAL:** 75-100 points - Immediate action required
- **HIGH:** 50-74 points - Urgent remediation needed
- **MEDIUM:** 25-49 points - Should be addressed soon
- **LOW:** 1-24 points - Minor issues to fix
- **MINIMAL:** 0 points - Good security posture

## Example Workflows

### 1. Daily Security Check

```bash
#!/bin/bash
# daily_check.sh

cd ~/stinky

# Generate report
./analyze.py -F markdown -o daily_report_$(date +%Y%m%d).md

# Check risk level
RISK=$(./analyze.py -F json | jq -r '.stats.risk_level')

if [ "$RISK" = "CRITICAL" ] || [ "$RISK" = "HIGH" ]; then
    echo "ALERT: Security risk is $RISK"
    # Send email, notification, etc.
fi
```

### 2. Weekly Summary

```bash
# Get last week's captures
WEEK_AGO=$(date -d '7 days ago' -Iseconds)

./analyze.py --since "$WEEK_AGO" -F html -o weekly_report.html
```

### 3. Compare Before/After Upgrade

```bash
# Before upgrade
./analyze.py old_captures.json -o before_upgrade.txt

# After upgrade
./analyze.py new_captures.json -o after_upgrade.txt

# Compare
diff before_upgrade.txt after_upgrade.txt
```

### 4. Automated Reporting

```bash
# Generate all format reports
./analyze.py stinky.json -o report.txt
./analyze.py stinky.json -F markdown -o report.md
./analyze.py stinky.json -F html -o report.html
./analyze.py stinky.json -F json -o report.json

# Upload to dashboard, send email, etc.
```

## Integration Examples

### With UPCE

```bash
# Monitor UPCE traffic and analyze
cd ~/stinky
sudo ./stinky.py &
SNIFFER_PID=$!

# Run UPCE operations
cd ~/back-end
./provision.sh

# Stop sniffer
sudo kill $SNIFFER_PID

# Analyze captured data
cd ~/stinky
./analyze.py -F html -o upce_crypto_report.html
```

### With CI/CD

```yaml
# .gitlab-ci.yml or similar
security_audit:
  script:
    - cd /path/to/stinky
    - ./analyze.py production_captures.json -F json -o report.json
    - RISK=$(jq -r '.stats.risk_level' report.json)
    - if [ "$RISK" = "CRITICAL" ]; then exit 1; fi
```

### With Monitoring Systems

```bash
# Export metrics to monitoring
./analyze.py -F json stinky.json | jq '{
  risk_score: .stats.risk_score,
  pq_vulnerable: .stats.pq_vulnerable,
  weak_tls: .stats.weak_tls_count,
  weak_ciphers: .stats.weak_cipher_count
}' | curl -X POST -d @- http://monitoring.example.com/api/metrics
```

## Understanding the Output

### Post-Quantum Status

**✅ Post-Quantum Secure**
- Uses quantum-resistant algorithms (Kyber, NTRU, Dilithium)
- Safe from quantum computer attacks
- Recommended for long-term security

**🔐 Hybrid (PQ+Classical)**
- Uses both post-quantum AND classical algorithms
- Transitional security approach
- Protected against both current and future threats
- Recommended during migration period

**⚠️ Quantum-Vulnerable**
- Uses only classical algorithms (RSA, ECDH, DH)
- Vulnerable to future quantum attacks
- **Action Required:** Plan migration to PQ crypto

**❓ Unknown**
- Cannot determine PQ security level
- May need manual inspection

### Critical Findings

**[CRITICAL] Broken Cipher Suite**
- RC4, DES, 3DES, MD5 detected
- **Immediate Action:** Disable these ciphers

**[HIGH] Post-Quantum Vulnerability**
- Many connections quantum-vulnerable
- **Action:** Plan PQ migration

**[HIGH] Deprecated TLS Version**
- SSL 3.0, TLS 1.0, or TLS 1.1 in use
- **Action:** Enforce TLS 1.2 minimum

**[MEDIUM] No Forward Secrecy**
- RSA key exchange without DHE/ECDHE
- **Action:** Enable ECDHE cipher suites

### Recommendations Priority

**CRITICAL**
- Address immediately
- Security vulnerabilities actively exploited
- Examples: Broken ciphers, deprecated TLS

**HIGH**
- Address urgently (within days/weeks)
- Significant security risk
- Examples: Post-quantum vulnerability, weak TLS

**MEDIUM**
- Address in next maintenance window
- Security improvement needed
- Examples: No forward secrecy

**LOW**
- Address when convenient
- Best practice, not urgent
- Examples: Continued PQ hybrid deployment

## Output Format Details

### Text Format

- Console-friendly
- 80-column width
- Uses ASCII box drawing
- Color-safe (no ANSI codes)
- Good for: Terminal display, email, logs

### Markdown Format

- GitHub-compatible
- Tables for data
- Headers for structure
- Good for: Documentation, wikis, GitHub issues

### HTML Format

- Styled with CSS
- Responsive layout
- Color-coded severity
- Good for: Web viewing, management reports, dashboards

### JSON Format

- Machine-readable
- Complete data structure
- Good for: Automation, APIs, monitoring systems

## Troubleshooting

### No data loaded

```
ERROR: File not found: stinky.json
```

**Solution:** Run stinky.py first to generate captures.

### Invalid JSON

```
ERROR: Invalid JSON in stinky.json
```

**Solution:** Check if stinky.json is corrupted or incomplete. Delete and regenerate.

### Empty report

If report shows 0 captures:
- Check if stinky.py is capturing data
- Verify filter criteria (--since, --before)
- Generate traffic: `curl https://example.com`

### Wrong risk level

Risk calculation depends on:
1. Data quality (real traffic vs test traffic)
2. Sample size (more captures = more accurate)
3. Network environment (production vs lab)

Capture longer to get representative sample.

## Advanced Usage

### Filter by Time Range

Last 24 hours:
```bash
./analyze.py --since "$(date -d '24 hours ago' -Iseconds)"
```

Last week:
```bash
./analyze.py --since "$(date -d '7 days ago' -Iseconds)"
```

Specific day:
```bash
./analyze.py --since "2026-04-05T00:00:00" --before "2026-04-05T23:59:59"
```

### Compare Multiple Captures

```bash
# Production
./analyze.py prod_captures.json -o prod_report.txt

# Staging
./analyze.py stage_captures.json -o stage_report.txt

# Dev
./analyze.py dev_captures.json -o dev_report.txt

# Compare risk scores
grep "Risk Score" *_report.txt
```

### Extract Specific Data

Using JSON output:

```bash
# Get risk score
./analyze.py -F json | jq '.stats.risk_score'

# Get PQ vulnerable count
./analyze.py -F json | jq '.stats.pq_vulnerable'

# Get all recommendations
./analyze.py -F json | jq '.recommendations[]'

# Get critical risks only
./analyze.py -F json | jq '.risks[] | select(.severity == "CRITICAL")'
```

### Batch Processing

```bash
# Analyze all JSON files in directory
for file in captures_*.json; do
    echo "Analyzing $file"
    ./analyze.py "$file" -o "report_${file%.json}.txt"
done
```

## Best Practices

1. **Regular Analysis** - Run daily or weekly
2. **Trend Tracking** - Compare reports over time
3. **Act on CRITICAL** - Address critical issues immediately
4. **Plan PQ Migration** - Start hybrid deployment
5. **Document Findings** - Keep reports for audit trail
6. **Automate** - Integrate with CI/CD and monitoring

## Support

For issues or questions:
- Check this documentation
- Review example_output.json
- See main README.md
- Check QUICKSTART.md for analysis examples

---

**Quick Start:**
```bash
cd ~/stinky
./analyze.py
```

Enjoy comprehensive crypto security analysis! 🔐
