#!/usr/bin/env python3
"""
stinky - TLS/SSH Crypto Sniffer

Captures and analyzes TLS and SSH traffic to extract cryptographic information.
Outputs to screen and logs to stinky.json.

Usage: sudo ./stinky.py [interface]
       If no interface specified, uses first available interface.

Requires: scapy
Install: pip3 install scapy
"""

import sys
import json
import time
from datetime import datetime
from collections import defaultdict
from pathlib import Path

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
except ImportError:
    print("ERROR: scapy not installed")
    print("Install with: pip3 install scapy")
    sys.exit(1)


# TLS cipher suite names (mapping from RFC values)
TLS_CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
}

# TLS versions
TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0300: "SSL 3.0",
}

# TLS extensions
TLS_EXTENSIONS = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    23: "extended_master_secret",
    35: "session_ticket",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
}


class CryptoSniffer:
    def __init__(self, interface=None, log_file="stinky.json"):
        self.interface = interface
        self.log_file = Path(log_file)
        self.connections = defaultdict(dict)
        self.log_entries = []

    def get_cipher_name(self, cipher_value):
        """Get human-readable cipher suite name."""
        return TLS_CIPHER_SUITES.get(cipher_value, f"UNKNOWN_0x{cipher_value:04x}")

    def get_version_name(self, version_value):
        """Get human-readable TLS version name."""
        return TLS_VERSIONS.get(version_value, f"UNKNOWN_0x{version_value:04x}")

    def analyze_tls_client_hello(self, pkt):
        """Analyze TLS ClientHello packet."""
        if not pkt.haslayer(TLSClientHello):
            return None

        client_hello = pkt[TLSClientHello]
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Extract connection tuple
        conn_id = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"

        info = {
            "type": "TLS ClientHello",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "connection": conn_id,
            "direction": "outbound",
        }

        # TLS version
        if hasattr(client_hello, 'version'):
            info["tls_version"] = self.get_version_name(client_hello.version)
            info["tls_version_value"] = f"0x{client_hello.version:04x}"

        # Cipher suites offered by client
        if hasattr(client_hello, 'ciphers') and client_hello.ciphers:
            cipher_list = []
            for cipher in client_hello.ciphers:
                cipher_name = self.get_cipher_name(cipher)
                cipher_list.append({
                    "name": cipher_name,
                    "value": f"0x{cipher:04x}"
                })
            info["client_cipher_suites"] = cipher_list
            info["cipher_count"] = len(cipher_list)

        # Extensions
        if hasattr(client_hello, 'ext') and client_hello.ext:
            extensions = []
            server_name = None
            supported_versions = []
            supported_groups = []

            for ext in client_hello.ext:
                ext_type = ext.type if hasattr(ext, 'type') else None
                ext_name = TLS_EXTENSIONS.get(ext_type, f"unknown_{ext_type}")

                # Extract server name (SNI)
                if ext_type == 0 and hasattr(ext, 'servernames'):
                    for sn in ext.servernames:
                        if hasattr(sn, 'servername'):
                            server_name = sn.servername.decode('utf-8', errors='ignore')

                # Extract supported versions
                if ext_type == 43 and hasattr(ext, 'versions'):
                    for ver in ext.versions:
                        supported_versions.append(self.get_version_name(ver))

                # Extract supported groups (key exchange)
                if ext_type == 10 and hasattr(ext, 'groups'):
                    group_names = {
                        23: "secp256r1",
                        24: "secp384r1",
                        25: "secp521r1",
                        29: "x25519",
                        30: "x448",
                        256: "ffdhe2048",
                        257: "ffdhe3072",
                        258: "ffdhe4096",
                    }
                    for grp in ext.groups:
                        supported_groups.append(group_names.get(grp, f"group_{grp}"))

                extensions.append(ext_name)

            info["extensions"] = extensions
            if server_name:
                info["server_name"] = server_name
            if supported_versions:
                info["supported_versions"] = supported_versions
            if supported_groups:
                info["supported_groups"] = supported_groups

        return info

    def analyze_tls_server_hello(self, pkt):
        """Analyze TLS ServerHello packet."""
        if not pkt.haslayer(TLSServerHello):
            return None

        server_hello = pkt[TLSServerHello]
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Extract connection tuple (reversed for server response)
        conn_id = f"{ip_layer.dst}:{tcp_layer.dport} -> {ip_layer.src}:{tcp_layer.sport}"

        info = {
            "type": "TLS ServerHello",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "connection": conn_id,
            "direction": "inbound",
        }

        # TLS version
        if hasattr(server_hello, 'version'):
            info["tls_version"] = self.get_version_name(server_hello.version)
            info["tls_version_value"] = f"0x{server_hello.version:04x}"

        # Chosen cipher suite
        if hasattr(server_hello, 'cipher'):
            cipher_name = self.get_cipher_name(server_hello.cipher)
            info["selected_cipher"] = {
                "name": cipher_name,
                "value": f"0x{server_hello.cipher:04x}"
            }

        # Extensions
        if hasattr(server_hello, 'ext') and server_hello.ext:
            extensions = []
            for ext in server_hello.ext:
                ext_type = ext.type if hasattr(ext, 'type') else None
                ext_name = TLS_EXTENSIONS.get(ext_type, f"unknown_{ext_type}")
                extensions.append(ext_name)
            info["extensions"] = extensions

        return info

    def analyze_ssh(self, pkt):
        """Analyze SSH traffic."""
        if not pkt.haslayer(TCP):
            return None

        tcp_layer = pkt[TCP]
        ip_layer = pkt[IP]

        # SSH typically on port 22
        if tcp_layer.dport != 22 and tcp_layer.sport != 22:
            return None

        # Try to extract SSH protocol exchange
        if not pkt.haslayer(Raw):
            return None

        payload = bytes(pkt[Raw].load)

        # SSH version string starts with "SSH-"
        if not payload.startswith(b'SSH-'):
            return None

        try:
            ssh_banner = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
        except:
            return None

        conn_id = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"

        info = {
            "type": "SSH Protocol Exchange",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "connection": conn_id,
            "direction": "outbound" if tcp_layer.dport == 22 else "inbound",
            "ssh_banner": ssh_banner,
        }

        # Parse SSH version
        parts = ssh_banner.split('-')
        if len(parts) >= 3:
            info["ssh_protocol_version"] = parts[1]
            info["ssh_software_version"] = '-'.join(parts[2:])

        return info

    def process_packet(self, pkt):
        """Process a captured packet."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        info = None

        # Check for TLS ClientHello
        if pkt.haslayer(TLSClientHello):
            info = self.analyze_tls_client_hello(pkt)

        # Check for TLS ServerHello
        elif pkt.haslayer(TLSServerHello):
            info = self.analyze_tls_server_hello(pkt)

        # Check for SSH
        else:
            info = self.analyze_ssh(pkt)

        if info:
            # Print to screen
            self.print_info(info)

            # Save to log
            self.log_entries.append(info)
            self.save_log()

    def print_info(self, info):
        """Pretty print crypto info to screen."""
        print("\n" + "=" * 80)
        print(f"[{info['timestamp']}] {info['type']}")
        print("=" * 80)
        print(f"Connection: {info['connection']}")
        print(f"Direction:  {info['direction']}")

        if "tls_version" in info:
            print(f"TLS Version: {info['tls_version']} ({info['tls_version_value']})")

        if "server_name" in info:
            print(f"Server Name (SNI): {info['server_name']}")

        if "client_cipher_suites" in info:
            print(f"\nClient Offered Ciphers ({info['cipher_count']}):")
            for i, cipher in enumerate(info['client_cipher_suites'][:10], 1):
                print(f"  {i}. {cipher['name']} ({cipher['value']})")
            if info['cipher_count'] > 10:
                print(f"  ... and {info['cipher_count'] - 10} more")

        if "selected_cipher" in info:
            print(f"\nServer Selected Cipher:")
            print(f"  {info['selected_cipher']['name']} ({info['selected_cipher']['value']})")

        if "supported_versions" in info:
            print(f"\nSupported TLS Versions: {', '.join(info['supported_versions'])}")

        if "supported_groups" in info:
            print(f"\nSupported Key Exchange Groups:")
            for grp in info['supported_groups']:
                print(f"  - {grp}")

        if "extensions" in info:
            print(f"\nTLS Extensions: {', '.join(info['extensions'])}")

        if "ssh_banner" in info:
            print(f"SSH Banner: {info['ssh_banner']}")
            if "ssh_protocol_version" in info:
                print(f"SSH Protocol: {info['ssh_protocol_version']}")
                print(f"SSH Software: {info['ssh_software_version']}")

        print("=" * 80)

    def save_log(self):
        """Save log entries to JSON file."""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.log_entries, f, indent=2)
        except Exception as e:
            print(f"ERROR: Failed to write log file: {e}", file=sys.stderr)

    def start_sniffing(self):
        """Start packet capture."""
        print(f"[*] Starting crypto sniffer...")
        print(f"[*] Interface: {self.interface or 'default'}")
        print(f"[*] Log file: {self.log_file}")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            # Capture TLS (443) and SSH (22) traffic
            filter_str = "tcp port 443 or tcp port 22"

            if self.interface:
                sniff(iface=self.interface, filter=filter_str, prn=self.process_packet, store=0)
            else:
                sniff(filter=filter_str, prn=self.process_packet, store=0)

        except KeyboardInterrupt:
            print("\n\n[*] Stopping sniffer...")
            print(f"[*] Captured {len(self.log_entries)} crypto exchanges")
            print(f"[*] Log saved to: {self.log_file}")

        except PermissionError:
            print("\nERROR: Permission denied. This tool requires root privileges.", file=sys.stderr)
            print("Run with: sudo ./stinky.py", file=sys.stderr)
            sys.exit(1)

        except Exception as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                            STINKY                                 ║
║                   TLS/SSH Crypto Sniffer                          ║
║                                                                   ║
║  Captures and analyzes cryptographic handshakes                   ║
║  Logs to: stinky.json                                             ║
╚═══════════════════════════════════════════════════════════════════╝
""")

    interface = sys.argv[1] if len(sys.argv) > 1 else None

    sniffer = CryptoSniffer(interface=interface, log_file="stinky.json")
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()
