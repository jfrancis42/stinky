# Quick Start Guide - Extended stinky

## Installation

```bash
cd ~/stinky
pip3 install -r requirements.txt
```

## Basic Usage

### Monitor Encrypted Protocols (Default)

```bash
sudo ./stinky.py
```

Press Ctrl+C to stop.

### Monitor All Protocols

```bash
sudo ./stinky.py --all
```

### Specific Interface

```bash
sudo ./stinky.py eth0
sudo ./stinky.py -i wlan0
```

## Generate Test Traffic

```bash
# Terminal 2 (while sniffer running):

# TLS/HTTPS
curl https://example.com
curl https://google.com

# SSH
ssh user@host

# DNS over TLS (if supported)
dig @1.1.1.1 example.com

# STARTTLS (if mail server available)
openssl s_client -connect mail.example.com:587 -starttls smtp
```

## View Results

### Pretty Print JSON

```bash
cat stinky.json | jq .
```

### Count Captures

```bash
jq 'length' stinky.json
```

### Post-Quantum Security Summary

```bash
jq 'group_by(.post_quantum_secure) | map({status: .[0].post_quantum_secure, count: length})' stinky.json
```

Example output:
```json
[
  { "status": "No", "count": 145 },
  { "status": "Hybrid", "count": 12 },
  { "status": "Yes", "count": 3 },
  { "status": "Unknown", "count": 5 }
]
```

### Find Post-Quantum Secure Connections

```bash
jq '.[] | select(.post_quantum_secure == "Yes" or .post_quantum_secure == "Hybrid")' stinky.json
```

### Find Quantum-Vulnerable Connections

```bash
jq '.[] | select(.post_quantum_secure == "No")' stinky.json
```

### Protocol Distribution

```bash
jq 'group_by(.protocol) | map({protocol: .[0].protocol, count: length})' stinky.json
```

### Server Names (SNI)

```bash
jq '.[] | select(.server_name) | .server_name' stinky.json | sort -u
```

### Cipher Suites Used

```bash
jq '.[] | select(.selected_cipher) | .selected_cipher.name' stinky.json | sort | uniq -c | sort -rn
```

### Find Weak TLS Versions

```bash
jq '.[] | select(.tls_version == "TLS 1.0" or .tls_version == "TLS 1.1" or .tls_version == "SSL 3.0")' stinky.json
```

### Find Deprecated Ciphers

```bash
# RC4 (broken)
jq '.[] | select(.selected_cipher.name | contains("RC4"))' stinky.json

# 3DES (weak)
jq '.[] | select(.selected_cipher.name | contains("3DES"))' stinky.json

# MD5 (broken)
jq '.[] | select(.selected_cipher.name | contains("MD5"))' stinky.json
```

### SSH Versions

```bash
jq '.[] | select(.protocol == "SSH") | .ssh_software_version' stinky.json | sort | uniq -c
```

### WireGuard Activity

```bash
jq '.[] | select(.protocol == "WireGuard")' stinky.json
```

### IPsec/IKE Negotiations

```bash
jq '.[] | select(.protocol == "IPsec/IKE")' stinky.json
```

### STARTTLS Upgrades

```bash
jq '.[] | select(.type | contains("STARTTLS"))' stinky.json
```

## Analysis Examples

### 1. Quantum Readiness Audit

Find all classical crypto (needs upgrade):
```bash
echo "=== Quantum-Vulnerable Connections ==="
jq -r '.[] | select(.post_quantum_secure == "No") | "\(.timestamp) \(.protocol) \(.connection)"' stinky.json | head -20
```

### 2. Security Score by Protocol

```bash
jq 'group_by(.protocol) | map({
  protocol: .[0].protocol,
  total: length,
  pq_safe: [.[] | select(.post_quantum_secure == "Yes")] | length,
  hybrid: [.[] | select(.post_quantum_secure == "Hybrid")] | length,
  vulnerable: [.[] | select(.post_quantum_secure == "No")] | length
})' stinky.json
```

### 3. Worst Offenders (Weak Crypto)

```bash
echo "=== Weak TLS Versions ==="
jq '.[] | select(.tls_version == "TLS 1.0" or .tls_version == "TLS 1.1")' stinky.json | jq -s 'length'

echo "=== Weak Ciphers ==="
jq '.[] | select(.selected_cipher.name | contains("RC4") or contains("3DES") or contains("MD5"))' stinky.json | jq -s 'length'

echo "=== No Forward Secrecy ==="
jq '.[] | select(.selected_cipher.name | contains("RSA_WITH"))' stinky.json | jq -s 'length'
```

### 4. Timeline Analysis

Connections per hour:
```bash
jq -r '.[] | .timestamp[:13]' stinky.json | sort | uniq -c
```

### 5. Top Talkers

Most active source IPs:
```bash
jq -r '.[] | .src_ip' stinky.json | sort | uniq -c | sort -rn | head -10
```

Most active destination IPs:
```bash
jq -r '.[] | .dst_ip' stinky.json | sort | uniq -c | sort -rn | head -10
```

## Export Formats

### CSV for Excel

```bash
jq -r '.[] | [
  .timestamp,
  .protocol,
  .type,
  .connection,
  .post_quantum_secure,
  .tls_version // "-",
  .selected_cipher.name // "-"
] | @csv' stinky.json > crypto_report.csv
```

### Summary Report

```bash
cat > report.txt << EOF
Crypto Analysis Report
Generated: $(date)

Total Captures: $(jq 'length' stinky.json)

Post-Quantum Security:
  ✅ PQ Secure:   $(jq '[.[] | select(.post_quantum_secure == "Yes")] | length' stinky.json)
  🔐 Hybrid:      $(jq '[.[] | select(.post_quantum_secure == "Hybrid")] | length' stinky.json)
  ⚠️  Vulnerable: $(jq '[.[] | select(.post_quantum_secure == "No")] | length' stinky.json)
  ❓ Unknown:     $(jq '[.[] | select(.post_quantum_secure == "Unknown")] | length' stinky.json)

Protocols Detected:
$(jq -r 'group_by(.protocol) | .[] | "  \(.[0].protocol): \(length)"' stinky.json)

Weak Crypto Issues:
  TLS 1.0/1.1:    $(jq '[.[] | select(.tls_version == "TLS 1.0" or .tls_version == "TLS 1.1")] | length' stinky.json)
  RC4/3DES/MD5:   $(jq '[.[] | select(.selected_cipher.name | contains("RC4") or contains("3DES") or contains("MD5"))] | length' stinky.json)
  No Forward Sec: $(jq '[.[] | select(.selected_cipher.name | contains("RSA_WITH"))] | length' stinky.json)
EOF
cat report.txt
```

## Integration Examples

### Continuous Monitoring

Run in background:
```bash
cd ~/stinky
sudo nohup ./stinky.py > stinky.log 2>&1 &

# Check it's running
ps aux | grep stinky

# Stop it
sudo pkill -f stinky.py
```

### Scheduled Analysis

Add to crontab:
```bash
# Run analysis every hour
0 * * * * cd ~/stinky && sudo ./stinky.py &
```

## Troubleshooting

### No Captures

```bash
# Check interface
ip link show

# Test with known traffic
curl https://example.com

# Check for scapy issues
python3 -c "from scapy.all import *; print('OK')"
```

### Performance Issues

If capturing too many packets:
```bash
# Monitor specific IPs only
# Edit stinky.py, add to filter_str:
"and (host 10.1.1.100 or host 10.1.1.200)"
```

### Permission Issues

```bash
# Must run as root
sudo ./stinky.py

# Or grant capabilities (Linux)
sudo setcap cap_net_raw+ep $(which python3)
./stinky.py
```

## Next Steps

1. Run for 24 hours to get full picture
2. Analyze post-quantum readiness
3. Identify weak crypto
4. Generate security report
5. Plan migration to PQ-safe algorithms
6. Re-test after upgrades

## References

- Full documentation: `README.md`
- Example output: `example_output.json`

Happy crypto sniffing! 🔐
