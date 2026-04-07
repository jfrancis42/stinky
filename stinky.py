#!/usr/bin/env python3
"""
stinky - Comprehensive Crypto Protocol Sniffer

Captures and analyzes encrypted protocol handshakes including TLS, SSH, IPsec,
DTLS, QUIC, WireGuard, and more. Identifies post-quantum secure connections.

Usage: sudo ./stinky.py [options] [interface]
       -a, --all          Include unencrypted protocols (default: encrypted only)
       -i, --interface    Network interface to monitor

Requires: scapy
Install: pip3 install scapy
"""

import sys
import json
import time
import struct
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    print("ERROR: scapy not installed")
    print("Install with: pip3 install scapy")
    sys.exit(1)


# Post-quantum safe algorithms
PQ_SAFE_KEX = {
    # TLS 1.3 post-quantum key exchange
    "x25519kyber512", "x25519kyber768", "x448kyber768",
    "kyber512", "kyber768", "kyber1024",
    "ntru", "sike", "frodokem",
    # SSH post-quantum KEX
    "sntrup761x25519-sha512@openssh.com",
    "sntrup4591761x25519-sha512@tinyssh.org",
    "mlkem768x25519-sha256",
    # IKE post-quantum
    "kyber-ike",
}

PQ_SAFE_SIG = {
    "dilithium2", "dilithium3", "dilithium5",
    "falcon512", "falcon1024",
    "sphincssha256128f", "sphincssha256192f", "sphincssha256256f",
}

# Classical crypto (NOT post-quantum safe)
CLASSICAL_KEX = {
    "x25519", "x448", "secp256r1", "secp384r1", "secp521r1",
    "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192",
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
}

# TLS cipher suite mappings (extended)
TLS_CIPHER_SUITES = {
    # TLS 1.3 ciphers
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # TLS 1.2 ECDHE ciphers
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    # TLS 1.2 DHE ciphers
    0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    # TLS 1.2 RSA ciphers (no forward secrecy)
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    # Weak/deprecated ciphers
    0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
}

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0300: "SSL 3.0",
}

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

# IKEv2 transform types
IKE_ENCR = {
    1: "DES-IV64", 2: "DES", 3: "3DES", 5: "CAST",
    7: "BLOWFISH", 11: "NULL", 12: "AES-CBC-128",
    13: "AES-CBC-192", 14: "AES-CBC-256",
    18: "AES-CTR", 20: "AES-GCM-128", 21: "AES-GCM-192", 22: "AES-GCM-256",
    23: "NULL_AUTH_AES-GMAC", 28: "CHACHA20-POLY1305",
}

IKE_PRF = {
    1: "PRF_HMAC_MD5", 2: "PRF_HMAC_SHA1", 3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC", 5: "PRF_HMAC_SHA2_256", 6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
}

IKE_INTEG = {
    1: "AUTH_HMAC_MD5_96", 2: "AUTH_HMAC_SHA1_96", 3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5", 5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128", 13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

IKE_DH = {
    1: "768-bit MODP", 2: "1024-bit MODP", 5: "1536-bit MODP",
    14: "2048-bit MODP", 15: "3072-bit MODP", 16: "4096-bit MODP",
    17: "6144-bit MODP", 18: "8192-bit MODP",
    19: "256-bit ECP", 20: "384-bit ECP", 21: "521-bit ECP",
    31: "Curve25519", 32: "Curve448",
}


class CryptoSniffer:
    def __init__(self, interface=None, log_file="stinky.json", encrypted_only=True):
        self.interface = interface
        self.log_file = Path(log_file)
        self.encrypted_only = encrypted_only
        self.connections = defaultdict(dict)
        self.log_entries = []
        
    def get_cipher_name(self, cipher_value):
        """Get human-readable cipher suite name."""
        return TLS_CIPHER_SUITES.get(cipher_value, f"UNKNOWN_0x{cipher_value:04x}")
    
    def get_version_name(self, version_value):
        """Get human-readable TLS version name."""
        return TLS_VERSIONS.get(version_value, f"UNKNOWN_0x{version_value:04x}")
    
    def check_pq_security(self, info):
        """
        Determine if connection is post-quantum secure.
        
        Returns:
            "Yes" - Post-quantum safe
            "Hybrid" - Mix of PQ and classical
            "No" - Classical crypto only (vulnerable to quantum attacks)
            "Unknown" - Cannot determine
        """
        # Check key exchange algorithms
        pq_kex = False
        classical_kex = False
        
        # TLS: Check supported groups
        if "supported_groups" in info:
            for group in info["supported_groups"]:
                group_lower = group.lower()
                if any(pq in group_lower for pq in PQ_SAFE_KEX):
                    pq_kex = True
                if any(classical in group_lower for classical in CLASSICAL_KEX):
                    classical_kex = True
        
        # SSH: Check key exchange from banner or algorithms
        if "ssh_kex_algorithms" in info:
            for kex in info["ssh_kex_algorithms"]:
                if kex.lower() in PQ_SAFE_KEX:
                    pq_kex = True
                if any(classical in kex.lower() for classical in CLASSICAL_KEX):
                    classical_kex = True
        
        # IPsec: Check DH group
        if "ike_dh_group" in info:
            dh_group = info["ike_dh_group"].lower()
            if "kyber" in dh_group or "ntru" in dh_group:
                pq_kex = True
            else:
                classical_kex = True
        
        # Check cipher suite for PQ indicators
        if "selected_cipher" in info:
            cipher_name = info["selected_cipher"].get("name", "").lower()
            if any(pq in cipher_name for pq in ["kyber", "ntru", "frodo", "sike"]):
                pq_kex = True
        
        # Determine overall PQ security
        if pq_kex and classical_kex:
            return "Hybrid"
        elif pq_kex:
            return "Yes"
        elif classical_kex:
            return "No"
        else:
            return "Unknown"
    
    def analyze_tls_client_hello(self, pkt):
        """Analyze TLS ClientHello packet."""
        if not pkt.haslayer(TLSClientHello):
            return None
        
        client_hello = pkt[TLSClientHello]
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        
        conn_id = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
        
        info = {
            "protocol": "TLS",
            "type": "TLS ClientHello",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
        }
        
        if hasattr(client_hello, 'version'):
            info["tls_version"] = self.get_version_name(client_hello.version)
            info["tls_version_value"] = f"0x{client_hello.version:04x}"
        
        if hasattr(client_hello, 'ciphers') and client_hello.ciphers:
            cipher_list = []
            for cipher in client_hello.ciphers:
                cipher_name = self.get_cipher_name(cipher)
                cipher_list.append({"name": cipher_name, "value": f"0x{cipher:04x}"})
            info["client_cipher_suites"] = cipher_list
            info["cipher_count"] = len(cipher_list)
        
        if hasattr(client_hello, 'ext') and client_hello.ext:
            extensions = []
            server_name = None
            supported_versions = []
            supported_groups = []
            
            for ext in client_hello.ext:
                ext_type = ext.type if hasattr(ext, 'type') else None
                ext_name = TLS_EXTENSIONS.get(ext_type, f"unknown_{ext_type}")
                
                if ext_type == 0 and hasattr(ext, 'servernames'):
                    for sn in ext.servernames:
                        if hasattr(sn, 'servername'):
                            server_name = sn.servername.decode('utf-8', errors='ignore')
                
                if ext_type == 43 and hasattr(ext, 'versions'):
                    for ver in ext.versions:
                        supported_versions.append(self.get_version_name(ver))
                
                if ext_type == 10 and hasattr(ext, 'groups'):
                    group_names = {
                        23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
                        29: "x25519", 30: "x448",
                        256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096",
                        # Post-quantum (hypothetical assignments)
                        512: "kyber512", 513: "kyber768", 514: "kyber1024",
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
        
        # Determine post-quantum security
        info["post_quantum_secure"] = self.check_pq_security(info)
        
        return info
    
    def analyze_tls_server_hello(self, pkt):
        """Analyze TLS ServerHello packet."""
        if not pkt.haslayer(TLSServerHello):
            return None
        
        server_hello = pkt[TLSServerHello]
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        
        conn_id = f"{ip_layer.dst}:{tcp_layer.dport} -> {ip_layer.src}:{tcp_layer.sport}"
        
        info = {
            "protocol": "TLS",
            "type": "TLS ServerHello",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "connection": conn_id,
            "direction": "inbound",
            "encrypted": True,
        }
        
        if hasattr(server_hello, 'version'):
            info["tls_version"] = self.get_version_name(server_hello.version)
            info["tls_version_value"] = f"0x{server_hello.version:04x}"
        
        if hasattr(server_hello, 'cipher'):
            cipher_name = self.get_cipher_name(server_hello.cipher)
            info["selected_cipher"] = {
                "name": cipher_name,
                "value": f"0x{server_hello.cipher:04x}"
            }
        
        if hasattr(server_hello, 'ext') and server_hello.ext:
            extensions = []
            supported_groups = []
            
            for ext in server_hello.ext:
                ext_type = ext.type if hasattr(ext, 'type') else None
                ext_name = TLS_EXTENSIONS.get(ext_type, f"unknown_{ext_type}")
                extensions.append(ext_name)
                
                # Extract key share for PQ detection
                if ext_type == 51 and hasattr(ext, 'group'):
                    group_names = {29: "x25519", 30: "x448", 512: "kyber768"}
                    supported_groups.append(group_names.get(ext.group, f"group_{ext.group}"))
            
            info["extensions"] = extensions
            if supported_groups:
                info["supported_groups"] = supported_groups
        
        info["post_quantum_secure"] = self.check_pq_security(info)
        
        return info
    
    def analyze_ssh(self, pkt):
        """Analyze SSH traffic."""
        if not pkt.haslayer(TCP):
            return None
        
        tcp_layer = pkt[TCP]
        ip_layer = pkt[IP]
        
        if tcp_layer.dport != 22 and tcp_layer.sport != 22:
            return None
        
        if not pkt.haslayer(Raw):
            return None
        
        payload = bytes(pkt[Raw].load)
        
        if not payload.startswith(b'SSH-'):
            return None
        
        try:
            ssh_banner = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
        except:
            return None
        
        conn_id = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
        
        info = {
            "protocol": "SSH",
            "type": "SSH Protocol Exchange",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "connection": conn_id,
            "direction": "outbound" if tcp_layer.dport == 22 else "inbound",
            "ssh_banner": ssh_banner,
            "encrypted": True,
        }
        
        parts = ssh_banner.split('-')
        if len(parts) >= 3:
            info["ssh_protocol_version"] = parts[1]
            info["ssh_software_version"] = '-'.join(parts[2:])
        
        # Check for post-quantum SSH implementations
        ssh_sw = info.get("ssh_software_version", "").lower()
        if "post-quantum" in ssh_sw or "pq" in ssh_sw or "kyber" in ssh_sw:
            info["post_quantum_secure"] = "Yes"
        else:
            # Standard SSH uses classical crypto (ECDH, DH)
            info["post_quantum_secure"] = "No"
        
        return info
    
    def analyze_ipsec_ike(self, pkt):
        """Analyze IPsec IKEv2 packets."""
        if not pkt.haslayer(UDP):
            return None
        
        udp_layer = pkt[UDP]
        ip_layer = pkt[IP]
        
        # IKE uses UDP port 500 (main) and 4500 (NAT-T)
        if udp_layer.dport not in [500, 4500] and udp_layer.sport not in [500, 4500]:
            return None
        
        if not pkt.haslayer(Raw):
            return None
        
        payload = bytes(pkt[Raw].load)
        
        # IKE header is at least 28 bytes
        if len(payload) < 28:
            return None
        
        # Check for IKE header (simple validation)
        # Byte 17 should be IKE major version (typically 0x20 for IKEv2)
        if len(payload) > 17 and payload[17] not in [0x10, 0x20]:
            return None
        
        conn_id = f"{ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}"
        
        info = {
            "protocol": "IPsec/IKE",
            "type": "IKE Negotiation",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": udp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": udp_layer.dport,
            "connection": conn_id,
            "direction": "outbound" if udp_layer.dport in [500, 4500] else "inbound",
            "encrypted": True,
        }
        
        # Try to extract IKE version
        if len(payload) > 17:
            ike_version = (payload[17] >> 4) & 0x0F
            info["ike_version"] = f"IKEv{ike_version}"
        
        # Try to parse proposals (this is simplified - real IKE parsing is complex)
        # For now, just indicate that IKE negotiation is happening
        info["note"] = "IKE key exchange detected (full proposal parsing not implemented)"
        
        # IKE typically uses classical DH groups (not post-quantum yet)
        info["post_quantum_secure"] = "No"
        
        return info
    
    def analyze_wireguard(self, pkt):
        """Analyze WireGuard VPN packets."""
        if not pkt.haslayer(UDP):
            return None
        
        udp_layer = pkt[UDP]
        ip_layer = pkt[IP]
        
        # WireGuard default port is 51820, but can be any port
        # WireGuard packets have specific message types in first byte
        if not pkt.haslayer(Raw):
            return None
        
        payload = bytes(pkt[Raw].load)
        
        if len(payload) < 4:
            return None
        
        # WireGuard message types:
        # 1 = Handshake Initiation (148 bytes)
        # 2 = Handshake Response (92 bytes)
        # 3 = Cookie Reply (64 bytes)
        # 4 = Transport Data (variable)
        msg_type = payload[0]
        
        if msg_type not in [1, 2, 3, 4]:
            return None
        
        # Additional validation: check expected packet sizes
        if msg_type == 1 and len(payload) != 148:
            return None
        if msg_type == 2 and len(payload) != 92:
            return None
        if msg_type == 3 and len(payload) != 64:
            return None
        
        conn_id = f"{ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}"
        
        msg_types = {
            1: "Handshake Initiation",
            2: "Handshake Response",
            3: "Cookie Reply",
            4: "Transport Data"
        }
        
        info = {
            "protocol": "WireGuard",
            "type": f"WireGuard {msg_types.get(msg_type, 'Unknown')}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": udp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": udp_layer.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
            "message_type": msg_types.get(msg_type, f"Unknown ({msg_type})"),
        }
        
        # WireGuard uses Curve25519 (classical) + ChaCha20-Poly1305
        # Not post-quantum secure yet
        info["crypto_algorithms"] = "Curve25519, ChaCha20-Poly1305"
        info["post_quantum_secure"] = "No"
        
        return info
    
    def analyze_dtls(self, pkt):
        """Analyze DTLS (TLS over UDP) packets."""
        if not pkt.haslayer(UDP):
            return None
        
        udp_layer = pkt[UDP]
        ip_layer = pkt[IP]
        
        if not pkt.haslayer(Raw):
            return None
        
        payload = bytes(pkt[Raw].load)
        
        # DTLS header: content type (1 byte) + version (2 bytes)
        # Content types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application
        if len(payload) < 13:
            return None
        
        content_type = payload[0]
        if content_type not in [20, 21, 22, 23]:
            return None
        
        # Check for DTLS version (0xFEFF for DTLS 1.0, 0xFEFD for DTLS 1.2)
        version = struct.unpack('>H', payload[1:3])[0]
        if version not in [0xFEFF, 0xFEFD]:
            return None
        
        conn_id = f"{ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}"
        
        content_types = {
            20: "ChangeCipherSpec",
            21: "Alert",
            22: "Handshake",
            23: "Application Data"
        }
        
        dtls_versions = {
            0xFEFF: "DTLS 1.0",
            0xFEFD: "DTLS 1.2",
            0xFEFC: "DTLS 1.3"
        }
        
        info = {
            "protocol": "DTLS",
            "type": f"DTLS {content_types.get(content_type, 'Unknown')}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": udp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": udp_layer.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
            "dtls_version": dtls_versions.get(version, f"Unknown (0x{version:04x})"),
            "content_type": content_types.get(content_type, f"Unknown ({content_type})"),
        }
        
        # DTLS uses same crypto as TLS, typically classical
        info["post_quantum_secure"] = "No"
        
        return info
    
    def analyze_quic(self, pkt):
        """Analyze QUIC (HTTP/3) packets."""
        if not pkt.haslayer(UDP):
            return None
        
        udp_layer = pkt[UDP]
        ip_layer = pkt[IP]
        
        # QUIC typically uses port 443
        if udp_layer.dport != 443 and udp_layer.sport != 443:
            return None
        
        if not pkt.haslayer(Raw):
            return None
        
        payload = bytes(pkt[Raw].load)
        
        if len(payload) < 1:
            return None
        
        # QUIC packets start with flags byte
        # Long header: first bit = 1
        # Short header: first bit = 0
        first_byte = payload[0]
        is_long_header = (first_byte & 0x80) != 0
        
        if not is_long_header:
            # Short header packets are encrypted data, skip
            return None
        
        # Long header has version field
        if len(payload) < 5:
            return None
        
        version = struct.unpack('>I', payload[1:5])[0]
        
        conn_id = f"{ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}"
        
        info = {
            "protocol": "QUIC",
            "type": "QUIC Initial",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": udp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": udp_layer.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
            "quic_version": f"0x{version:08x}",
        }
        
        # QUIC uses TLS 1.3 internally
        info["note"] = "QUIC uses TLS 1.3 for crypto"
        info["post_quantum_secure"] = "No"
        
        return info
    
    def analyze_dns_over_tls(self, pkt):
        """Analyze DNS over TLS (DoT) on port 853."""
        if not pkt.haslayer(TCP):
            return None
        
        tcp_layer = pkt[TCP]
        
        if tcp_layer.dport != 853 and tcp_layer.sport != 853:
            return None
        
        # DoT uses TLS, so look for TLS handshake
        if pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello):
            info = self.analyze_tls_client_hello(pkt) or self.analyze_tls_server_hello(pkt)
            if info:
                info["protocol"] = "DNS over TLS (DoT)"
                info["type"] = f"DoT {info['type']}"
            return info
        
        return None
    
    def analyze_starttls(self, pkt):
        """Analyze STARTTLS commands in various protocols."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        
        tcp_layer = pkt[TCP]
        ip_layer = pkt[IP]
        payload = bytes(pkt[Raw].load)
        
        # Common STARTTLS ports
        starttls_ports = {
            25: "SMTP",
            587: "SMTP Submission",
            143: "IMAP",
            110: "POP3",
            21: "FTP",
            389: "LDAP",
            5222: "XMPP",
            5432: "PostgreSQL",
            3306: "MySQL"
        }
        
        if tcp_layer.dport not in starttls_ports and tcp_layer.sport not in starttls_ports:
            return None
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore').upper()
        except:
            return None
        
        # Look for STARTTLS command
        if "STARTTLS" not in payload_str:
            return None
        
        protocol = starttls_ports.get(tcp_layer.dport) or starttls_ports.get(tcp_layer.sport, "Unknown")
        conn_id = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
        
        info = {
            "protocol": f"{protocol} STARTTLS",
            "type": f"{protocol} STARTTLS Upgrade",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
            "note": "Protocol upgrading to TLS",
        }
        
        info["post_quantum_secure"] = "Unknown"
        
        return info
    
    def analyze_smb(self, pkt):
        """Analyze SMB encryption negotiation."""
        if not pkt.haslayer(TCP):
            return None
        
        tcp_layer = pkt[TCP]
        
        if tcp_layer.dport != 445 and tcp_layer.sport != 445:
            return None
        
        if not pkt.haslayer(Raw):
            return None
        
        payload = bytes(pkt[Raw].load)
        
        # SMB2/3 packets start with 0xFE 'S' 'M' 'B'
        if len(payload) < 4 or payload[0:4] not in [b'\xffSMB', b'\xfeSMB']:
            return None
        
        ip_layer = pkt[IP]
        conn_id = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
        
        info = {
            "protocol": "SMB",
            "type": "SMB Negotiate",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "connection": conn_id,
            "direction": "outbound" if tcp_layer.dport == 445 else "inbound",
            "encrypted": True,
            "note": "SMB3 supports encryption",
        }
        
        info["post_quantum_secure"] = "No"
        
        return info
    
    def process_packet(self, pkt):
        """Process a captured packet."""
        if not pkt.haslayer(IP):
            return
        
        info = None
        
        # Try each protocol analyzer
        analyzers = [
            self.analyze_tls_client_hello,
            self.analyze_tls_server_hello,
            self.analyze_ssh,
            self.analyze_ipsec_ike,
            self.analyze_wireguard,
            self.analyze_dtls,
            self.analyze_quic,
            self.analyze_dns_over_tls,
            self.analyze_starttls,
            self.analyze_smb,
        ]
        
        for analyzer in analyzers:
            try:
                info = analyzer(pkt)
                if info:
                    break
            except Exception as e:
                # Continue to next analyzer on error
                pass
        
        if info:
            # Skip if encrypted_only mode and this is not encrypted
            if self.encrypted_only and not info.get("encrypted", False):
                return
            
            # Print to screen
            self.print_info(info)
            
            # Save to log
            self.log_entries.append(info)
            self.save_log()
    
    def print_info(self, info):
        """Pretty print crypto info to screen."""
        pq_status = info.get("post_quantum_secure", "Unknown")
        pq_indicator = {
            "Yes": "🔒 POST-QUANTUM SECURE",
            "Hybrid": "🔐 HYBRID (PQ + Classical)",
            "No": "⚠️  CLASSICAL CRYPTO (quantum-vulnerable)",
            "Unknown": "❓ UNKNOWN"
        }.get(pq_status, "❓ UNKNOWN")
        
        print("\n" + "=" * 80)
        print(f"[{info['timestamp']}] {info['type']}")
        print(f"Post-Quantum: {pq_indicator}")
        print("=" * 80)
        print(f"Connection: {info['connection']}")
        print(f"Direction:  {info['direction']}")
        print(f"Protocol:   {info.get('protocol', 'Unknown')}")
        
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
                # Highlight post-quantum groups
                if any(pq in grp.lower() for pq in ["kyber", "ntru", "frodo", "sike"]):
                    print(f"  - {grp} ⭐ [POST-QUANTUM]")
                else:
                    print(f"  - {grp}")
        
        if "extensions" in info:
            print(f"\nTLS Extensions: {', '.join(info['extensions'])}")
        
        if "ssh_banner" in info:
            print(f"SSH Banner: {info['ssh_banner']}")
            if "ssh_protocol_version" in info:
                print(f"SSH Protocol: {info['ssh_protocol_version']}")
                print(f"SSH Software: {info['ssh_software_version']}")
        
        if "ike_version" in info:
            print(f"IKE Version: {info['ike_version']}")
        
        if "message_type" in info:
            print(f"Message Type: {info['message_type']}")
        
        if "crypto_algorithms" in info:
            print(f"Crypto: {info['crypto_algorithms']}")
        
        if "note" in info:
            print(f"Note: {info['note']}")
        
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
        print(f"[*] Starting comprehensive crypto sniffer...")
        print(f"[*] Interface: {self.interface or 'default'}")
        print(f"[*] Log file: {self.log_file}")
        print(f"[*] Mode: {'Encrypted protocols only' if self.encrypted_only else 'All protocols'}")
        print(f"[*] Press Ctrl+C to stop\n")
        
        try:
            # Build filter string for encrypted protocols
            if self.encrypted_only:
                filter_parts = [
                    "tcp port 443",     # HTTPS/TLS
                    "tcp port 22",      # SSH
                    "tcp port 853",     # DNS over TLS
                    "tcp port 636",     # LDAPS
                    "tcp port 989",     # FTPS data
                    "tcp port 990",     # FTPS control
                    "tcp port 992",     # Telnet over TLS
                    "tcp port 993",     # IMAPS
                    "tcp port 995",     # POP3S
                    "tcp port 8883",    # MQTT over TLS
                    "tcp port 5061",    # SIP over TLS
                    "tcp port 445",     # SMB (can be encrypted)
                    "udp port 500",     # IKE
                    "udp port 4500",    # IKE NAT-T
                    "udp port 443",     # QUIC
                    "udp port 51820",   # WireGuard
                ]
                filter_str = " or ".join(filter_parts)
            else:
                filter_str = None
            
            if self.interface:
                sniff(iface=self.interface, filter=filter_str, prn=self.process_packet, store=0)
            else:
                sniff(filter=filter_str, prn=self.process_packet, store=0)
        
        except KeyboardInterrupt:
            print("\n\n[*] Stopping sniffer...")
            print(f"[*] Captured {len(self.log_entries)} crypto exchanges")
            print(f"[*] Log saved to: {self.log_file}")
            
            # Summary statistics
            if self.log_entries:
                protocols = {}
                pq_stats = {"Yes": 0, "Hybrid": 0, "No": 0, "Unknown": 0}
                
                for entry in self.log_entries:
                    proto = entry.get("protocol", "Unknown")
                    protocols[proto] = protocols.get(proto, 0) + 1
                    
                    pq = entry.get("post_quantum_secure", "Unknown")
                    pq_stats[pq] = pq_stats.get(pq, 0) + 1
                
                print("\n[*] Protocol Summary:")
                for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                    print(f"    {proto}: {count}")
                
                print("\n[*] Post-Quantum Security Summary:")
                print(f"    ✅ Post-Quantum Secure: {pq_stats['Yes']}")
                print(f"    🔐 Hybrid (PQ + Classical): {pq_stats['Hybrid']}")
                print(f"    ⚠️  Classical Only (vulnerable): {pq_stats['No']}")
                print(f"    ❓ Unknown: {pq_stats['Unknown']}")
        
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
    parser = argparse.ArgumentParser(
        description="stinky - Comprehensive Crypto Protocol Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo ./stinky.py                    # Monitor encrypted protocols on default interface
  sudo ./stinky.py -a                 # Monitor all protocols (including unencrypted)
  sudo ./stinky.py -i eth0            # Monitor specific interface
  sudo ./stinky.py -a -i wlan0        # All protocols on specific interface

Monitored Encrypted Protocols (default):
  - TLS/HTTPS (TCP 443)
  - SSH (TCP 22)
  - IPsec/IKE (UDP 500, 4500)
  - WireGuard (UDP 51820)
  - DTLS (various UDP ports)
  - QUIC/HTTP3 (UDP 443)
  - DNS over TLS (TCP 853)
  - STARTTLS (SMTP, IMAP, POP3, FTP, LDAP)
  - SMB with encryption (TCP 445)
  - Database SSL/TLS (MySQL, PostgreSQL)
  - MQTT over TLS (TCP 8883)
  - And more...

Post-Quantum Security:
  Each connection is analyzed to determine if it uses post-quantum safe
  cryptography (resistant to quantum computer attacks).
  
  Status indicators:
    ✅ Post-Quantum Secure - Uses PQ-safe algorithms
    🔐 Hybrid - Mix of PQ and classical algorithms  
    ⚠️  Classical - Vulnerable to quantum attacks
    ❓ Unknown - Cannot determine
        """
    )
    
    parser.add_argument('-a', '--all', action='store_true',
                      help='Include unencrypted protocols (default: encrypted only)')
    parser.add_argument('-i', '--interface', type=str,
                      help='Network interface to monitor')
    parser.add_argument('interface_positional', nargs='?',
                      help='Network interface (alternative positional argument)')
    
    args = parser.parse_args()
    
    # Handle interface from either -i flag or positional argument
    interface = args.interface or args.interface_positional
    encrypted_only = not args.all
    
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                            STINKY                                 ║
║            Comprehensive Crypto Protocol Sniffer                  ║
║                                                                   ║
║  Analyzes TLS, SSH, IPsec, WireGuard, DTLS, QUIC, and more      ║
║  Identifies Post-Quantum Secure connections                      ║
║  Logs to: stinky.json                                            ║
╚═══════════════════════════════════════════════════════════════════╝
""")
    
    sniffer = CryptoSniffer(interface=interface, log_file="stinky.json", 
                           encrypted_only=encrypted_only)
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()
