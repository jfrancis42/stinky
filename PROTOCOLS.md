# Supported Protocols in stinky

## Encrypted Protocols (Default Mode)

These protocols are monitored by default when running `sudo ./stinky.py`.

### 1. TLS/HTTPS (TCP 443)
**Captures:**
- ClientHello/ServerHello handshakes
- TLS versions (SSL 3.0, TLS 1.0-1.3)
- Cipher suites offered and selected
- Key exchange groups (ECDHE, DHE, RSA, Kyber)
- Server Name Indication (SNI)
- TLS extensions

**Post-Quantum Detection:**
- Hybrid key exchange (x25519kyber768, etc.)
- Post-quantum cipher suites
- Classical-only (ECDHE, DHE, RSA)

### 2. SSH (TCP 22)
**Captures:**
- Protocol version (SSH-1.x, SSH-2.0)
- Software implementation (OpenSSH, libssh, etc.)
- Version numbers

**Post-Quantum Detection:**
- PQ SSH implementations (sntrup761x25519, etc.)
- Classical SSH (standard ECDH, DH)

### 3. IPsec/IKE (UDP 500, 4500)
**Captures:**
- IKE version (IKEv1, IKEv2)
- Key exchange proposals
- Encryption algorithms (AES, ChaCha20, 3DES)
- Integrity algorithms (HMAC-SHA256, etc.)
- Diffie-Hellman groups

**Post-Quantum Detection:**
- Future PQ IKE extensions
- Currently: Classical DH groups

**Ports:**
- UDP 500: IKE main mode
- UDP 4500: IKE NAT traversal

### 4. WireGuard (UDP 51820)
**Captures:**
- Handshake initiation/response
- Cookie reply
- Transport data (encrypted)
- Message types

**Crypto:**
- Curve25519 (key exchange)
- ChaCha20-Poly1305 (encryption)

**Post-Quantum:** No (classical only)

### 5. DTLS (UDP, various ports)
**Captures:**
- DTLS handshake messages
- Protocol version (DTLS 1.0, 1.2, 1.3)
- Content types (handshake, alert, data)

**Post-Quantum Detection:**
- Same as TLS (DTLS is TLS over UDP)

**Common uses:**
- WebRTC
- VPN protocols
- IoT secure communication

### 6. QUIC/HTTP3 (UDP 443)
**Captures:**
- QUIC initial packets
- Protocol version
- Long header packets

**Crypto:**
- Uses TLS 1.3 internally
- Encrypted by default

**Post-Quantum:** Depends on TLS 1.3 implementation

### 7. DNS over TLS (DoT) (TCP 853)
**Captures:**
- TLS handshake on port 853
- All TLS details (same as HTTPS)

**Post-Quantum Detection:**
- Same as TLS

### 8. STARTTLS Upgrades
**Protocols:**
- SMTP (TCP 25, 587) - Email submission
- IMAP (TCP 143) - Email retrieval
- POP3 (TCP 110) - Email retrieval
- FTP (TCP 21) - File transfer
- LDAP (TCP 389) - Directory access
- XMPP (TCP 5222) - Chat/messaging
- PostgreSQL (TCP 5432) - Database
- MySQL (TCP 3306) - Database

**Captures:**
- STARTTLS command detection
- Subsequent TLS upgrade

**Post-Quantum Detection:**
- Depends on TLS implementation after upgrade

### 9. Native TLS Services

**IMAPS (TCP 993):** IMAP over TLS
**POP3S (TCP 995):** POP3 over TLS
**LDAPS (TCP 636):** LDAP over SSL
**FTPS (TCP 989, 990):** FTP over TLS
**SMTPS (TCP 465):** SMTP over TLS (deprecated port)

All capture standard TLS handshakes.

### 10. SMB (TCP 445)
**Captures:**
- SMB dialect negotiation
- SMB2/SMB3 detection
- Encryption capability

**Versions:**
- SMB1: No encryption
- SMB2: Limited encryption
- SMB3: Full encryption support

**Post-Quantum:** No (uses AES)

### 11. MQTT over TLS (TCP 8883)
**Captures:**
- TLS handshake
- MQTT over encrypted channel

**Post-Quantum Detection:**
- Same as TLS

### 12. SIP over TLS (TCP 5061)
**Captures:**
- SIP signaling over TLS
- VoIP security

**Post-Quantum Detection:**
- Same as TLS

### 13. OpenVPN
**Captures:**
- TLS handshake (uses TLS 1.2 or 1.3)
- Control channel negotiation

**Post-Quantum Detection:**
- Depends on TLS implementation
- OpenVPN 2.6+ can support PQ

### 14. Database Protocols with SSL/TLS

**PostgreSQL (TCP 5432):**
- STARTTLS upgrade detection
- SSL/TLS handshake

**MySQL (TCP 3306):**
- STARTTLS detection
- SSL/TLS handshake

**MongoDB (TCP 27017):**
- TLS handshake

**Redis (TCP 6379):**
- TLS handshake (if enabled)

## Unencrypted Protocols (--all mode)

These are monitored only with `sudo ./stinky.py --all`:

### DNS (UDP/TCP 53)
**Captures:**
- Query types (A, AAAA, MX, TXT, etc.)
- Domain names queried
- DNSSEC validation

**Post-Quantum:** N/A (unencrypted)

### HTTP (TCP 80)
**Captures:**
- HTTP headers
- User-agents
- Requested URLs

**Post-Quantum:** N/A (unencrypted)

### DHCP (UDP 67, 68)
**Captures:**
- Client identifiers
- Hostnames
- Vendor options

**Post-Quantum:** N/A (unencrypted)

### NTP (UDP 123)
**Captures:**
- Time synchronization
- System configuration hints

**Post-Quantum:** N/A (unencrypted)

### SNMP (UDP 161, 162)
**Captures:**
- Management queries
- Community strings (if visible)

**Post-Quantum:** N/A (unencrypted)

### Syslog (UDP 514)
**Captures:**
- Log messages
- System events

**Post-Quantum:** N/A (unencrypted)

## Post-Quantum Algorithm Reference

### Key Exchange Algorithms

**Post-Quantum Safe:**
- Kyber512, Kyber768, Kyber1024 (NIST standard)
- NTRU
- FrodoKEM
- SIKE (note: recently broken, included for detection)

**Hybrid (Transitional):**
- x25519kyber512
- x25519kyber768
- x448kyber768
- mlkem768x25519

**Classical (Quantum-Vulnerable):**
- RSA
- Diffie-Hellman (DH)
- Elliptic Curve Diffie-Hellman (ECDH)
- x25519, x448
- secp256r1, secp384r1, secp521r1
- ffdhe2048, ffdhe3072, ffdhe4096

### Signature Algorithms

**Post-Quantum Safe:**
- Dilithium2, Dilithium3, Dilithium5 (NIST standard)
- Falcon512, Falcon1024
- SPHINCS+ variants

**Classical (Quantum-Vulnerable):**
- RSA signatures
- ECDSA
- DSA
- EdDSA (Ed25519, Ed448)

### Encryption Algorithms

**Note:** Symmetric encryption (AES, ChaCha20) is quantum-resistant.
The vulnerability is in key exchange and signatures (asymmetric crypto).

**Symmetric (Quantum-Safe):**
- AES-128, AES-256
- ChaCha20-Poly1305

**Symmetric (Weak/Deprecated):**
- DES, 3DES
- RC4
- Blowfish

## Protocol Detection Methods

### TLS/DTLS
- Scapy TLS layer parsing
- ClientHello/ServerHello packet analysis
- Extension parsing

### SSH
- Banner string matching ("SSH-2.0-...")
- Port 22 detection

### IPsec/IKE
- UDP ports 500, 4500
- IKE header validation
- Version detection from packet structure

### WireGuard
- Message type field validation
- Packet size verification
- UDP any port (common: 51820)

### QUIC
- UDP port 443
- Long header detection
- Version field extraction

### STARTTLS
- Text-based command parsing
- Protocol-specific port detection
- Case-insensitive "STARTTLS" matching

### SMB
- TCP port 445
- SMB header magic bytes (0xFE 'S' 'M' 'B')

## Adding New Protocol Support

To add a new protocol analyzer to stinky:

1. Create analyzer method in `CryptoSniffer` class:
```python
def analyze_newprotocol(self, pkt):
    # Port/protocol detection
    # Packet parsing
    # Extract crypto info
    # Determine PQ security
    return info_dict
```

2. Add to analyzers list in `process_packet()`:
```python
analyzers = [
    # ... existing analyzers ...
    self.analyze_newprotocol,
]
```

3. Add port to filter if encrypted by default:
```python
filter_parts = [
    # ... existing ports ...
    "tcp port XXXX",  # Your new protocol
]
```

4. Update documentation (README.md, PROTOCOLS.md)

## Future Protocol Support

Protocols that could be added:

- **Kerberos** (UDP/TCP 88) - Authentication, encryption types
- **RADIUS** (UDP 1812, 1813) - Authentication attempts
- **TACACS+** (TCP 49) - Cisco authentication
- **RDP** (TCP 3389) - Full security negotiation parsing
- **Certificate Analysis** - X.509 parsing from TLS
- **CoAP over DTLS** (UDP 5684) - IoT protocol
- **Zigbee/Z-Wave** - IoT protocols (requires special hardware)

## References

- TLS 1.3: RFC 8446
- DTLS 1.2: RFC 6347
- IKEv2: RFC 7296
- SSH: RFC 4253
- WireGuard: https://www.wireguard.com/protocol/
- QUIC: RFC 9000
- Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
