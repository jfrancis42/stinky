# stinky - Crypto Sniffer Installation Summary

## What Was Created

Created in `~/stinky/`:

```
stinky/
├── stinky.py              # Main sniffer program (executable)
├── requirements.txt       # Python dependencies
├── README.md             # Full documentation
├── QUICKSTART.md         # Quick start guide
├── example_output.json   # Example of what JSON output looks like
└── SUMMARY.md           # This file
```

## Installation

### 1. Install Dependencies

```bash
cd ~/stinky
pip3 install -r requirements.txt
```

Or manually:
```bash
pip3 install scapy
```

### 2. Test Installation

```bash
python3 -c "import scapy; print('scapy installed OK')"
```

## Usage

### Basic Usage

```bash
cd ~/stinky
sudo ./stinky.py
```

### With Specific Interface

```bash
sudo ./stinky.py eth0
```

### Stop Capture

Press `Ctrl+C`

## What It Does

**Captures in real-time:**
- TLS ClientHello (client offers cipher suites)
- TLS ServerHello (server selects cipher)
- SSH protocol exchange (version banners)

**Extracts:**
- TLS versions (1.0, 1.1, 1.2, 1.3)
- Cipher suites (AES-GCM, ChaCha20, etc.)
- Key exchange methods (ECDHE, DHE, RSA)
- Server names (SNI)
- SSH versions and software

**Outputs:**
- Real-time display to terminal (pretty formatted)
- JSON log to `stinky.json` (machine readable)

## Output Files

### stinky.json

JSON array of captured crypto exchanges:

```json
[
  {
    "type": "TLS ClientHello",
    "timestamp": "2026-04-05T12:34:56.123",
    "src_ip": "10.1.1.100",
    "dst_ip": "93.184.216.34",
    "connection": "10.1.1.100:54321 -> 93.184.216.34:443",
    "server_name": "example.com",
    "tls_version": "TLS 1.2",
    "client_cipher_suites": [...],
    "supported_groups": ["x25519", "secp256r1"]
  }
]
```

See `example_output.json` for full example.

## Security Analysis Use Cases

1. **Audit Crypto Strength**
   - Identify weak ciphers (RC4, 3DES)
   - Find deprecated TLS versions (1.0, 1.1)
   - Check for forward secrecy (ECDHE/DHE)

2. **Monitor Network Security**
   - See what crypto is actually being used
   - Detect misconfigured clients/servers
   - Verify security policies are followed

3. **Troubleshoot TLS Issues**
   - See cipher negotiation
   - Check SNI values
   - Verify supported versions

4. **Track SSH Versions**
   - Find outdated SSH servers
   - Identify SSH software in use
   - Monitor SSH connections

## Viewing Results

### Pretty print JSON:
```bash
cat stinky.json | jq .
```

### Count captures:
```bash
jq 'length' stinky.json
```

### Show server names:
```bash
jq '.[] | .server_name' stinky.json | sort -u
```

### Show selected ciphers:
```bash
jq '.[] | select(.selected_cipher) | .selected_cipher.name' stinky.json
```

### Find weak TLS:
```bash
jq '.[] | select(.tls_version == "TLS 1.0" or .tls_version == "TLS 1.1")' stinky.json
```

## Quick Test

Generate some traffic to capture:

```bash
# Terminal 1: Start sniffer
cd ~/stinky
sudo ./stinky.py

# Terminal 2: Generate TLS traffic
curl https://example.com
curl https://google.com
curl https://github.com

# Back in Terminal 1: Press Ctrl+C to stop
# Check the output:
cat stinky.json | jq .
```

## Documentation

- **README.md** - Full documentation with all features
- **QUICKSTART.md** - Quick start with examples
- **example_output.json** - Sample JSON output

## Requirements

- Python 3.6+
- scapy library
- Root privileges (for packet capture)
- Linux/Unix system with network interface

## Limitations

- **Cannot decrypt traffic** - Only analyzes handshakes
- **Ports 22 and 443 only** - By default (can be changed)
- **No payload inspection** - Only protocol-level crypto info
- **Localhost may not work** - Some systems don't capture loopback

## Integration with UPCE

This tool can monitor UPCE's encrypted connections:

```bash
# Start sniffer
cd ~/stinky
sudo ./stinky.py

# In another terminal, run UPCE operations
cd ~/back-end
./upce.py ../common/inventory.json ../common/policy.json ../config.json

# Or run provisioning
./provision.sh

# Or use the API
./api.py --config ../common --port 8000
```

All TLS connections (Ansible, API calls) will be captured.

## Legal Notice

✅ **Authorized use only:**
- Your own networks
- Networks with explicit permission
- Authorized security testing

❌ **Unauthorized network monitoring may be illegal**

This tool is for security auditing and network analysis by authorized personnel.

## Next Steps

1. Install scapy: `pip3 install scapy`
2. Start capture: `sudo ./stinky.py`
3. Generate traffic: `curl https://example.com`
4. View results: `cat stinky.json | jq .`
5. Read documentation: `less README.md`

## Support

For detailed usage, see:
- `README.md` - Complete documentation
- `QUICKSTART.md` - Quick examples with jq commands

For Python/scapy issues:
- Scapy docs: https://scapy.readthedocs.io/
- UPCE docs: ~/docs/

Enjoy sniffing! 🦨
