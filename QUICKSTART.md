# Quick Start Guide

## 1. Install Dependencies

```bash
cd ~/stinky
pip3 install -r requirements.txt
```

## 2. Run the Sniffer

```bash
sudo ./stinky.py
```

Press Ctrl+C to stop.

## 3. Generate Some Traffic

In another terminal:

```bash
# TLS traffic
curl https://example.com
curl https://google.com
curl https://github.com

# SSH traffic (if you have an SSH server)
ssh user@192.168.1.50
```

## 4. Check the Results

### View JSON log:
```bash
cat stinky.json | jq .
```

Or:
```bash
python3 -m json.tool stinky.json
```

### Count captures:
```bash
jq 'length' stinky.json
```

### Filter by type:
```bash
# Show only TLS ClientHello
jq '.[] | select(.type == "TLS ClientHello")' stinky.json

# Show only SSH
jq '.[] | select(.type | startswith("SSH"))' stinky.json
```

### Extract server names (SNI):
```bash
jq '.[] | select(.server_name) | .server_name' stinky.json
```

### Show selected ciphers:
```bash
jq '.[] | select(.selected_cipher) | .selected_cipher.name' stinky.json
```

### Find weak TLS versions:
```bash
jq '.[] | select(.tls_version == "TLS 1.0" or .tls_version == "TLS 1.1")' stinky.json
```

## 5. Common Issues

### "Permission denied"
```bash
# Solution: Use sudo
sudo ./stinky.py
```

### "scapy not installed"
```bash
# Solution: Install scapy
pip3 install scapy
```

### Not capturing anything
```bash
# Generate traffic in another terminal
curl https://example.com

# Or specify your network interface
sudo ./stinky.py eth0
sudo ./stinky.py wlan0
```

### List available interfaces:
```bash
ip link show
```

## 6. Analysis Examples

### Find all cipher suites used
```bash
jq '[.[] | select(.selected_cipher) | .selected_cipher.name] | unique' stinky.json
```

### Count connections per server
```bash
jq 'group_by(.server_name) | map({server: .[0].server_name, count: length})' stinky.json
```

### Show TLS versions distribution
```bash
jq 'group_by(.tls_version) | map({version: .[0].tls_version, count: length})' stinky.json
```

### Find servers with weak key exchange
```bash
# Look for RSA key exchange (no forward secrecy)
jq '.[] | select(.selected_cipher.name | contains("RSA_WITH"))' stinky.json
```

### SSH version summary
```bash
jq '.[] | select(.ssh_software_version) | .ssh_software_version' stinky.json | sort | uniq -c
```

## 7. Advanced: Continuous Monitoring

Run in background and rotate logs:

```bash
# Start in background
sudo nohup ./stinky.py > stinky.log 2>&1 &

# Check it's running
ps aux | grep stinky

# Stop it later
sudo pkill -f stinky.py
```

## 8. Integration with UPCE

To monitor UPCE-managed traffic:

```bash
# Run on your UPCE management host
cd ~/stinky
sudo ./stinky.py

# In another terminal, generate traffic
cd ~/back-end
./upce.py ../common/inventory.json ../common/policy.json ../config.json
```

This will capture all TLS connections made by UPCE (API calls, Ansible provisioning, etc.)

## 9. Analyze Specific Hosts

Monitor only specific IPs:

Edit `stinky.py` line ~250:
```python
# Before:
filter_str = "tcp port 443 or tcp port 22"

# After (monitor only 10.1.1.100):
filter_str = "(tcp port 443 or tcp port 22) and host 10.1.1.100"
```

## 10. Export for Reporting

Convert to CSV:

```bash
jq -r '.[] | [.timestamp, .type, .connection, .tls_version // .ssh_protocol_version, .selected_cipher.name // .ssh_software_version] | @csv' stinky.json > report.csv
```

Open in Excel/LibreOffice or process further.
