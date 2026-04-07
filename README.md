# stinky - TLS/SSH Crypto Sniffer

A network traffic analyzer that captures and analyzes cryptographic information from TLS and SSH connections.

## Features

- **TLS Analysis**: Captures ClientHello and ServerHello handshakes
  - TLS versions (1.0, 1.1, 1.2, 1.3)
  - Cipher suites offered and selected
  - Server Name Indication (SNI)
  - Supported key exchange groups (ECDHE, DHE, etc.)
  - TLS extensions

- **SSH Analysis**: Captures SSH protocol exchange
  - SSH protocol version
  - SSH software version
  - Connection details

- **Bidirectional Capture**: Monitors traffic in both directions
- **Real-time Display**: Shows crypto info on screen as it's captured
- **JSON Logging**: Saves all data to `stinky.json` for later analysis

## Installation

### Requirements
- Python 3.6+
- scapy library

### Install Dependencies

```bash
pip3 install scapy
```

Or:

```bash
pip3 install -r requirements.txt
```

## Usage

### Basic Usage

```bash
sudo ./stinky.py
```

This captures on the default network interface.

### Specify Interface

```bash
sudo ./stinky.py eth0
```

### Why Root?

Packet capture requires root privileges (or CAP_NET_RAW capability).

## Output

### Screen Output

Real-time display showing:
- Connection endpoints (IP:port)
- TLS version
- Cipher suites
- Server name (SNI)
- Key exchange groups
- Extensions

Example:
```
================================================================================
[2026-04-05T12:34:56.789] TLS ClientHello
================================================================================
Connection: 10.1.1.100:54321 -> 1.2.3.4:443
Direction:  outbound
TLS Version: TLS 1.2 (0x0303)
Server Name (SNI): example.com

Client Offered Ciphers (15):
  1. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
  2. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
  3. TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
  ...

Supported TLS Versions: TLS 1.3, TLS 1.2
Supported Key Exchange Groups:
  - x25519
  - secp256r1
  - secp384r1

TLS Extensions: server_name, supported_versions, supported_groups, ...
================================================================================
```

### JSON Log File

All captured data is saved to `stinky.json`:

```json
[
  {
    "type": "TLS ClientHello",
    "timestamp": "2026-04-05T12:34:56.789",
    "src_ip": "10.1.1.100",
    "src_port": 54321,
    "dst_ip": "1.2.3.4",
    "dst_port": 443,
    "connection": "10.1.1.100:54321 -> 1.2.3.4:443",
    "direction": "outbound",
    "tls_version": "TLS 1.2",
    "tls_version_value": "0x0303",
    "server_name": "example.com",
    "client_cipher_suites": [
      {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "value": "0xc02f"
      }
    ],
    "cipher_count": 15,
    "supported_versions": ["TLS 1.3", "TLS 1.2"],
    "supported_groups": ["x25519", "secp256r1", "secp384r1"],
    "extensions": ["server_name", "supported_versions", "supported_groups"]
  }
]
```

## What It Detects

### TLS Cipher Suites
- Modern: AES-GCM, ChaCha20-Poly1305
- Legacy: AES-CBC, 3DES, RC4
- Key Exchange: ECDHE, DHE, RSA
- Authentication: RSA, ECDSA
- Hash: SHA256, SHA384

### TLS Versions
- TLS 1.3 (modern, secure)
- TLS 1.2 (secure)
- TLS 1.1 (deprecated)
- TLS 1.0 (deprecated)
- SSL 3.0 (insecure, should not be used)

### Key Exchange Groups
- Elliptic Curves: x25519, x448, secp256r1, secp384r1, secp521r1
- Finite Field: ffdhe2048, ffdhe3072, ffdhe4096

### SSH Information
- Protocol version (1.x or 2.0)
- Software implementation (OpenSSH, libssh, etc.)
- Version numbers

## Security Analysis

Use this tool to:

1. **Audit TLS Configuration**
   - Check if servers accept weak ciphers
   - Verify TLS 1.3 support
   - Identify deprecated protocols (TLS 1.0/1.1)

2. **Monitor Key Exchange**
   - Ensure ECDHE or DHE is used (forward secrecy)
   - Avoid plain RSA key exchange

3. **Detect Weak Crypto**
   - Find RC4, 3DES, or other weak ciphers
   - Identify MD5 or SHA1 usage

4. **Verify SNI**
   - Check server names in encrypted connections
   - Useful for troubleshooting TLS issues

5. **SSH Version Tracking**
   - Identify SSH software versions
   - Detect outdated SSH servers

## Limitations

- **Encrypted Payload**: Cannot decrypt actual data (only analyzes handshakes)
- **Perfect Forward Secrecy**: With ECDHE/DHE, session keys cannot be recovered
- **TLS 1.3**: Some details hidden due to encrypted extensions
- **Filter Scope**: Only captures ports 22 (SSH) and 443 (HTTPS)
  - Modify `filter_str` in code to capture other ports

## Tips

### Capture All TLS Traffic (Any Port)

Edit `stinky.py` and change:
```python
filter_str = "tcp port 443 or tcp port 22"
```

To:
```python
filter_str = "tcp"  # Captures all TCP, but slower
```

### Analyze Saved PCAP Files

If you have existing packet captures:

```python
from scapy.all import *

sniffer = CryptoSniffer(log_file="analysis.json")
packets = rdpcap("capture.pcap")
for pkt in packets:
    sniffer.process_packet(pkt)
```

### Filter by IP

Modify `filter_str`:
```python
filter_str = "(tcp port 443 or tcp port 22) and host 10.1.1.100"
```

## Troubleshooting

### "Permission denied"
Run with `sudo`:
```bash
sudo ./stinky.py
```

### "scapy not installed"
Install scapy:
```bash
pip3 install scapy
```

### No packets captured
- Check interface name: `ip link show`
- Verify firewall rules aren't blocking
- Generate traffic: `curl https://example.com`
- Try specifying interface: `sudo ./stinky.py eth0`

### Can't see local traffic
Some systems don't capture localhost traffic. Use external connections.

## Legal Notice

This tool is for authorized security testing and network analysis only. Use only on:
- Your own networks
- Networks you have explicit permission to analyze
- Authorized penetration testing engagements

Unauthorized network monitoring may violate laws and regulations.

## License

This tool is provided as-is for educational and authorized security testing purposes.
