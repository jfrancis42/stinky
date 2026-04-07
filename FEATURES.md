# stinky Feature List

## Core Features

### 1. Multi-Protocol Support
- **15+ encrypted protocols** monitored by default
- **10+ unencrypted protocols** with --all flag
- Automatic protocol detection and classification
- Bidirectional capture (both directions)

### 2. Post-Quantum Security Analysis
**✅ Industry First:** Real-time post-quantum cryptography detection

**Detection Capabilities:**
- Identifies post-quantum safe algorithms (Kyber, NTRU, Dilithium)
- Detects hybrid key exchange (transitional security)
- Flags classical-only crypto (quantum-vulnerable)
- Provides security recommendations

**Status Indicators:**
- ✅ **Post-Quantum Secure** - Uses PQ algorithms
- 🔐 **Hybrid** - Mix of PQ and classical (recommended for transition)
- ⚠️ **Classical** - Quantum-vulnerable (needs upgrade)
- ❓ **Unknown** - Cannot determine

### 3. Comprehensive Crypto Analysis

**TLS/DTLS:**
- Protocol versions (SSL 3.0 through TLS 1.3)
- All cipher suites (offered and selected)
- Key exchange methods with PQ detection
- Server Name Indication (SNI)
- TLS extensions parsing
- Forward secrecy verification

**SSH:**
- Protocol version detection
- Software implementation identification
- Post-quantum SSH recognition

**IPsec/IKE:**
- IKE version (IKEv1, IKEv2)
- Encryption proposals
- DH group identification
- Integrity algorithms

**VPN Protocols:**
- WireGuard handshake detection
- OpenVPN TLS analysis
- IPsec tunnel establishment

**Application Protocols:**
- STARTTLS upgrade detection (SMTP, IMAP, POP3, FTP, LDAP)
- Database encryption (MySQL, PostgreSQL, MongoDB)
- SMB encryption capabilities
- MQTT over TLS
- SIP over TLS

### 4. Dual Output Format

**Screen (Real-time):**
- Color-coded post-quantum indicators
- Pretty formatted connection details
- Highlighted security issues
- Progress indicators
- Summary statistics

**JSON Log (stinky.json):**
- Complete structured data
- Machine-readable format
- All captured fields preserved
- Suitable for automation
- Easy integration with tools

### 5. Flexible Filtering

**Default Mode:** Encrypted protocols only
```bash
sudo ./stinky.py
```

**All Protocols:**
```bash
sudo ./stinky.py --all
```

**Specific Interface:**
```bash
sudo ./stinky.py -i eth0
```

### 6. Smart Protocol Detection

**Heuristic Analysis:**
- Port-based initial classification
- Packet structure validation
- Magic byte verification
- Header parsing

**Supported Detection:**
- Standard ports (443, 22, 500, etc.)
- Non-standard ports (custom services)
- Multiple protocols on same port
- Protocol upgrades (STARTTLS)

### 7. Security Assessment

**Identifies Weak Crypto:**
- Deprecated TLS versions (1.0, 1.1)
- Broken ciphers (RC4, DES, 3DES)
- Weak hashing (MD5, SHA1)
- No forward secrecy (RSA key exchange)

**Quantum Readiness:**
- Counts PQ-safe connections
- Identifies vulnerable systems
- Tracks hybrid deployments
- Migration progress monitoring

### 8. Session Tracking

**Connection Management:**
- Unique connection identifiers
- Bidirectional flow tracking
- Client/server role identification
- Timestamp precision

### 9. Extensive Protocol Coverage

**Encrypted (Default):**
1. TLS/HTTPS (TCP 443)
2. SSH (TCP 22)
3. IPsec/IKE (UDP 500, 4500)
4. WireGuard (UDP 51820)
5. DTLS (UDP various)
6. QUIC/HTTP3 (UDP 443)
7. DNS over TLS (TCP 853)
8. LDAPS (TCP 636)
9. IMAPS (TCP 993)
10. POP3S (TCP 995)
11. FTPS (TCP 989, 990)
12. SMTPS (TCP 465)
13. MQTT/TLS (TCP 8883)
14. SIP/TLS (TCP 5061)
15. SMB3 (TCP 445)

**Plus STARTTLS for:**
- SMTP, IMAP, POP3, FTP, LDAP, XMPP, PostgreSQL, MySQL

### 10. Statistical Analysis

**Real-time Summaries:**
- Protocol distribution
- Post-quantum security breakdown
- Weak crypto count
- Total captures

**Exit Statistics:**
```
Protocol Summary:
  TLS: 145
  SSH: 23
  WireGuard: 12
  
Post-Quantum Security:
  ✅ PQ Secure: 15
  🔐 Hybrid: 32
  ⚠️ Classical: 133
  ❓ Unknown: 8
```

### 11. Integration Ready

**JSON Processing:**
```bash
jq '.[] | select(.post_quantum_secure == "No")' stinky.json
```

**CSV Export:**
```bash
jq -r '.[] | [.timestamp, .protocol, .post_quantum_secure] | @csv' stinky.json
```

### 12. Performance Optimized

**Efficient Capture:**
- BPF filters for targeted capture
- Store=0 mode (no packet buffering)
- Selective protocol analysis
- Minimal memory footprint

**Scalability:**
- Handles high-volume networks
- Real-time processing
- Log rotation support
- Background operation

### 13. Detailed Metadata

**Captured Per Connection:**
- Source/destination IP and port
- Protocol and version
- Direction (inbound/outbound)
- Timestamp (ISO 8601)
- Encryption status
- Post-quantum security
- Algorithm details
- Extension information
- Server names (SNI)
- Software versions

### 14. Security Research Tools

**Identify:**
- Zero-day crypto vulnerabilities
- Misconfigurations
- Downgrade attacks
- Weak implementations
- Legacy protocol usage

**Track:**
- PQ adoption rates
- Cipher suite preferences
- TLS version distribution
- SSH software diversity

### 15. Compliance Auditing

**Verify:**
- TLS 1.2+ enforcement
- Strong cipher requirements
- Forward secrecy usage
- Certificate validation (future)

**Document:**
- Crypto inventory
- Security posture
- Upgrade requirements
- Risk assessment data

## Advanced Features

### 16. Hybrid Detection
Identifies transitional cryptography:
- x25519kyber768 (classical + PQ)
- Other hybrid schemes
- Migration path tracking

### 17. Extension Parsing
Extracts TLS extensions:
- Server Name Indication (SNI)
- Supported versions
- Supported groups
- Key share information
- ALPN protocols

### 18. Algorithm Recognition
Comprehensive crypto database:
- 40+ cipher suites
- 15+ key exchange methods
- 10+ signature algorithms
- 8+ TLS versions
- Post-quantum variants

### 19. Error Resilience
Robust packet processing:
- Malformed packet handling
- Partial data recovery
- Exception handling
- Continues on errors

### 20. Extensible Architecture
Easy to extend:
- Plugin-style analyzers
- Modular protocol detection
- Configurable filters
- Custom output formats

## Command-Line Interface

### Arguments

```
-a, --all          Include unencrypted protocols
-i, --interface    Specify network interface
-h, --help         Show help message
```

### Examples

```bash
# Basic encrypted monitoring
sudo ./stinky.py

# All protocols on eth0
sudo ./stinky.py -a -i eth0

# Specific interface
sudo ./stinky.py wlan0
```

## Output Features

### Screen Display
- Unicode support (emojis for status)
- Color coding (if terminal supports)
- Structured format (80-column)
- Real-time updates
- Summary statistics on exit

### JSON Log
- Valid JSON array
- Indented (2 spaces)
- UTF-8 encoding
- Append mode (preserves data)
- Atomic writes

### Log Fields

Every entry includes:
```json
{
  "protocol": "TLS",
  "type": "TLS ClientHello",
  "timestamp": "2026-04-05T12:34:56.789",
  "src_ip": "10.1.1.100",
  "src_port": 54321,
  "dst_ip": "93.184.216.34",
  "dst_port": 443,
  "connection": "10.1.1.100:54321 -> 93.184.216.34:443",
  "direction": "outbound",
  "encrypted": true,
  "post_quantum_secure": "Hybrid",
  ...protocol-specific fields...
}
```

## Use Cases

1. **Security Auditing** - Find weak crypto
2. **Quantum Readiness** - Assess PQ migration
3. **Compliance** - Verify crypto policies
4. **Incident Response** - Analyze connections
5. **Research** - Study crypto deployment
6. **Monitoring** - Track security posture
7. **Education** - Learn about protocols
8. **Troubleshooting** - Debug TLS issues

## Limitations

**What stinky CAN do:**
- ✅ Capture and analyze handshakes
- ✅ Identify crypto algorithms
- ✅ Detect post-quantum usage
- ✅ Track connection metadata
- ✅ Monitor protocol versions

**What stinky CANNOT do:**
- ❌ Decrypt encrypted traffic
- ❌ Break cryptography
- ❌ Capture payload content
- ❌ Perform man-in-the-middle
- ❌ Bypass encryption

## System Requirements

- Python 3.6+
- scapy library
- Root/sudo access
- Linux/Unix system
- Network interface

## Future Roadmap

**Planned Features:**
- Certificate extraction and analysis
- Real-time alerting (weak crypto detected)
- Web dashboard
- Database backend (PostgreSQL)
- Machine learning anomaly detection
- PCAP file analysis mode
- Historical comparison
- Trend analysis
- Automated reporting

**Protocol Additions:**
- Full Kerberos analysis
- RDP detailed parsing
- Certificate chain extraction
- Complete IKE proposal parsing
- More post-quantum variants

## Getting Started

See QUICKSTART.md for:
- Installation instructions
- Basic usage examples
- Common analysis patterns
- Integration guides

See README.md for:
- Complete documentation
- Protocol details
- Security analysis
- Troubleshooting

Enjoy comprehensive crypto analysis! 🔐
