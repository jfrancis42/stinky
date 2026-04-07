# stinky v2.0 - Comprehensive Crypto Sniffer

## What's New in v2.0

### 🔐 Post-Quantum Security Analysis (NEW!)
Every captured connection is now analyzed for quantum resistance:
- **✅ Post-Quantum Secure** - Uses quantum-safe algorithms
- **🔐 Hybrid** - Transitional (PQ + classical)
- **⚠️ Classical Only** - Vulnerable to quantum attacks
- **❓ Unknown** - Cannot determine

### 🌐 Extended Protocol Support (NEW!)
Monitors **15+ encrypted protocols** by default:
- TLS/HTTPS, SSH, IPsec/IKE, WireGuard
- DTLS, QUIC/HTTP3, DNS over TLS
- STARTTLS (SMTP, IMAP, POP3, FTP, LDAP, etc.)
- SMB, LDAPS, IMAPS, POP3S, FTPS, MQTT/TLS

### 📊 Dual Output with PQ Indicators
Both screen and JSON output now include `post_quantum_secure` field.

## Installation

```bash
cd ~/stinky
pip3 install -r requirements.txt
```

## Quick Start

### Monitor Encrypted Protocols (Default)

```bash
sudo ./stinky.py
```

### Monitor All Protocols

```bash
sudo ./stinky.py --all
```

### Specific Interface

```bash
sudo ./stinky.py -i eth0
```

## Example Output

### Screen

```
================================================================================
[2026-04-05T12:34:56.789] TLS ClientHello
Post-Quantum: 🔐 HYBRID (PQ + Classical)
================================================================================
Connection: 10.1.1.100:54321 -> 93.184.216.34:443
Direction:  outbound
Protocol:   TLS
TLS Version: TLS 1.3 (0x0304)
Server Name (SNI): example.com

Supported Key Exchange Groups:
  - x25519kyber768 ⭐ [POST-QUANTUM]
  - x25519
  - secp256r1
================================================================================
```

### JSON (stinky.json)

```json
{
  "protocol": "TLS",
  "type": "TLS ClientHello",
  "timestamp": "2026-04-05T12:34:56.789",
  "connection": "10.1.1.100:54321 -> 93.184.216.34:443",
  "encrypted": true,
  "tls_version": "TLS 1.3",
  "server_name": "example.com",
  "supported_groups": ["x25519kyber768", "x25519", "secp256r1"],
  "post_quantum_secure": "Hybrid"
}
```

## Key Features

### 1. Comprehensive Protocol Coverage
- **TLS/DTLS:** Full handshake analysis, cipher suites, SNI
- **SSH:** Version detection, software identification
- **VPNs:** IPsec/IKE, WireGuard, OpenVPN
- **Modern:** QUIC/HTTP3, DNS over TLS
- **Legacy:** STARTTLS upgrades, native TLS services

### 2. Post-Quantum Analysis
- Detects hybrid key exchange (x25519kyber768, etc.)
- Identifies PQ-safe signatures (Dilithium, Falcon)
- Flags quantum-vulnerable classical crypto
- Tracks migration progress

### 3. Security Auditing
- Identifies weak TLS versions (1.0, 1.1)
- Detects broken ciphers (RC4, 3DES, MD5)
- Verifies forward secrecy
- Monitors compliance

### 4. Flexible Operation
- Encrypted-only mode (default)
- All protocols mode (--all)
- Interface selection (-i)
- Real-time display + JSON log

### 5. Statistical Analysis
Exit summary shows:
- Protocol distribution
- Post-quantum security breakdown
- Total captures
- Weak crypto count

## Common Analysis Tasks

### Find Quantum-Vulnerable Connections

```bash
jq '.[] | select(.post_quantum_secure == "No")' stinky.json
```

### Count Post-Quantum Security

```bash
jq 'group_by(.post_quantum_secure) | map({status: .[0].post_quantum_secure, count: length})' stinky.json
```

### Identify Weak Crypto

```bash
# TLS 1.0/1.1
jq '.[] | select(.tls_version == "TLS 1.0" or .tls_version == "TLS 1.1")' stinky.json

# Broken ciphers
jq '.[] | select(.selected_cipher.name | contains("RC4") or contains("3DES"))' stinky.json

# No forward secrecy
jq '.[] | select(.selected_cipher.name | contains("RSA_WITH"))' stinky.json
```

### Protocol Distribution

```bash
jq 'group_by(.protocol) | map({protocol: .[0].protocol, count: length})' stinky.json
```

### Server Names (SNI)

```bash
jq '.[] | select(.server_name) | .server_name' stinky.json | sort -u
```

## Files in ~/stinky/

```
stinky.py              - Main executable (v2.0)
requirements.txt       - Dependencies (scapy)
README.md             - Complete documentation
QUICKSTART.md         - Quick examples
PROTOCOLS.md          - Protocol details
FEATURES.md           - Feature list
SUMMARY.md            - This file
example_output.json   - Sample output with PQ fields
```

## What It Can Do

✅ **Capture and analyze** encrypted handshakes
✅ **Identify crypto algorithms** and versions
✅ **Detect post-quantum** cryptography
✅ **Track connection metadata**
✅ **Monitor protocol usage**
✅ **Audit security posture**
✅ **Verify compliance**
✅ **Export to JSON/CSV**

## What It Cannot Do

❌ Decrypt encrypted traffic
❌ Break cryptography
❌ Capture payload content
❌ Perform man-in-the-middle
❌ Bypass encryption

## Use Cases

### 1. Quantum Readiness Assessment
Identify systems using quantum-vulnerable crypto that need upgrading.

### 2. Security Auditing
Find weak TLS versions, broken ciphers, and missing forward secrecy.

### 3. Compliance Verification
Verify enforcement of TLS 1.2+, strong ciphers, and security policies.

### 4. Protocol Monitoring
Track what encrypted protocols are used in your environment.

### 5. Migration Tracking
Monitor adoption of post-quantum cryptography during migration.

### 6. Incident Response
Analyze connection patterns and crypto usage during security incidents.

### 7. Research & Education
Study real-world cryptography deployment and protocol usage.

## Integration with UPCE

Monitor UPCE's encrypted connections:

```bash
# Terminal 1: Start sniffer
cd ~/stinky && sudo ./stinky.py

# Terminal 2: Run UPCE operations
cd ~/back-end && ./provision.sh
```

All TLS connections (Ansible, API calls) are captured and analyzed.

## System Requirements

- Python 3.6+
- scapy library
- Root/sudo privileges
- Linux/Unix system
- Network interface

## Quick Installation

```bash
cd ~/stinky
pip3 install scapy
sudo ./stinky.py
```

## Documentation

- **README.md** - Complete documentation with all details
- **QUICKSTART.md** - Quick start with jq examples
- **PROTOCOLS.md** - All supported protocols explained
- **FEATURES.md** - Complete feature list
- **example_output.json** - Sample JSON with all fields

## Support

For issues or questions:
1. Check QUICKSTART.md for common tasks
2. Review README.md for detailed info
3. See PROTOCOLS.md for protocol details
4. Check ~/docs/ for UPCE integration

## Legal Notice

**Authorized use only:**
- Your own networks
- Networks with permission
- Authorized security testing
- Educational environments

**Unauthorized monitoring may violate laws.**

## Next Steps

1. **Install:** `pip3 install scapy`
2. **Run:** `sudo ./stinky.py`
3. **Generate traffic:** `curl https://example.com`
4. **Analyze:** `cat stinky.json | jq .`
5. **Assess:** Check post-quantum security
6. **Report:** Generate security report
7. **Upgrade:** Migrate to PQ-safe crypto

## Version History

**v2.0** (Current)
- ✨ Post-quantum security analysis
- ✨ Extended protocol support (15+ protocols)
- ✨ Bidirectional capture
- ✨ Statistical summaries
- ✨ Comprehensive documentation

**v1.0**
- Basic TLS and SSH monitoring
- JSON logging
- Real-time display

## Future Roadmap

- Certificate extraction and analysis
- Real-time alerting
- Web dashboard
- Database backend
- Machine learning anomaly detection
- PCAP file analysis mode
- Automated reporting

---

**Get Started:** `sudo ./stinky.py`

Enjoy comprehensive crypto analysis with post-quantum security assessment! 🔐
