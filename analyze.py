#!/usr/bin/env python3
"""
analyze.py - Security Analysis Tool for stinky.json

Analyzes captured crypto protocol data and generates security reports.

Usage:
    ./analyze.py [options] [file]
    
Options:
    -f, --file FILE       Input JSON file (default: stinky.json)
    -o, --output FILE     Output report file (default: stdout)
    -F, --format FORMAT   Output format: text, markdown, html, json (default: text)
    -v, --verbose         Verbose output
    --no-pdf              Disable automatic PDF generation from markdown
    --since TIMESTAMP     Only analyze captures after this time
    --before TIMESTAMP    Only analyze captures before this time

PDF Generation:
    When markdown format is selected, automatically generates PDF if available:
    - Requires: markdown, weasyprint (or pdfkit + wkhtmltopdf)
    - Install: pip3 install markdown weasyprint
    - Output: same filename with .pdf extension
"""

import json
import sys
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

# Try to import PDF generation libraries
PDF_AVAILABLE = False
PDF_METHOD = None

try:
    import markdown
    try:
        from weasyprint import HTML, CSS
        PDF_AVAILABLE = True
        PDF_METHOD = 'weasyprint'
    except ImportError:
        try:
            import pdfkit
            PDF_AVAILABLE = True
            PDF_METHOD = 'pdfkit'
        except ImportError:
            pass
except ImportError:
    pass


class CryptoAnalyzer:
    def __init__(self, data):
        """Initialize analyzer with captured data."""
        self.data = data
        self.stats = {}
        self.risks = []
        self.recommendations = []
        
    def analyze(self):
        """Run all analysis modules."""
        self.analyze_basic_stats()
        self.analyze_post_quantum()
        self.analyze_tls_versions()
        self.analyze_cipher_suites()
        self.analyze_forward_secrecy()
        self.analyze_protocols()
        self.analyze_weak_crypto()
        self.analyze_connections()
        self.analyze_timeline()
        self.generate_risk_score()
        self.generate_recommendations()
        
        return self.stats, self.risks, self.recommendations
    
    def analyze_basic_stats(self):
        """Calculate basic statistics."""
        self.stats['total_captures'] = len(self.data)
        self.stats['encrypted_count'] = sum(1 for d in self.data if d.get('encrypted', False))
        self.stats['unencrypted_count'] = self.stats['total_captures'] - self.stats['encrypted_count']
        
        # Time range
        if self.data:
            timestamps = [datetime.fromisoformat(d['timestamp']) for d in self.data if 'timestamp' in d]
            if timestamps:
                self.stats['first_capture'] = min(timestamps).isoformat()
                self.stats['last_capture'] = max(timestamps).isoformat()
                duration = max(timestamps) - min(timestamps)
                self.stats['duration_hours'] = duration.total_seconds() / 3600
    
    def analyze_post_quantum(self):
        """Analyze post-quantum security status."""
        pq_counts = Counter(d.get('post_quantum_secure', 'Unknown') for d in self.data)
        
        self.stats['pq_secure'] = pq_counts.get('Yes', 0)
        self.stats['pq_hybrid'] = pq_counts.get('Hybrid', 0)
        self.stats['pq_vulnerable'] = pq_counts.get('No', 0)
        self.stats['pq_unknown'] = pq_counts.get('Unknown', 0)
        
        # Calculate percentages
        if self.stats['total_captures'] > 0:
            total = self.stats['total_captures']
            self.stats['pq_vulnerable_pct'] = (self.stats['pq_vulnerable'] / total) * 100
            self.stats['pq_secure_pct'] = (self.stats['pq_secure'] / total) * 100
            self.stats['pq_hybrid_pct'] = (self.stats['pq_hybrid'] / total) * 100
        
        # Risk assessment
        if self.stats['pq_vulnerable'] > 0:
            self.risks.append({
                'severity': 'HIGH',
                'category': 'Post-Quantum Vulnerability',
                'count': self.stats['pq_vulnerable'],
                'description': f"{self.stats['pq_vulnerable']} connections use quantum-vulnerable cryptography",
                'impact': "Vulnerable to future quantum computer attacks (store-now-decrypt-later)"
            })
    
    def analyze_tls_versions(self):
        """Analyze TLS version usage."""
        tls_versions = Counter(d.get('tls_version') for d in self.data if 'tls_version' in d)
        self.stats['tls_versions'] = dict(tls_versions)
        
        # Check for weak versions
        weak_versions = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1']
        weak_count = sum(tls_versions.get(v, 0) for v in weak_versions)
        self.stats['weak_tls_count'] = weak_count
        
        if weak_count > 0:
            self.risks.append({
                'severity': 'HIGH',
                'category': 'Deprecated TLS Version',
                'count': weak_count,
                'description': f"{weak_count} connections use deprecated TLS versions (SSL 3.0, TLS 1.0, TLS 1.1)",
                'impact': "Vulnerable to known attacks (POODLE, BEAST, etc.)"
            })
    
    def analyze_cipher_suites(self):
        """Analyze cipher suite usage."""
        cipher_counts = Counter()
        weak_ciphers = []
        
        for entry in self.data:
            if 'selected_cipher' in entry:
                cipher = entry['selected_cipher']['name']
                cipher_counts[cipher] += 1
                
                # Check for weak ciphers
                if any(weak in cipher for weak in ['RC4', '3DES', 'DES', 'MD5', 'NULL', 'EXPORT']):
                    weak_ciphers.append({
                        'cipher': cipher,
                        'connection': entry.get('connection'),
                        'timestamp': entry.get('timestamp')
                    })
        
        self.stats['cipher_suites'] = dict(cipher_counts.most_common(10))
        self.stats['unique_ciphers'] = len(cipher_counts)
        self.stats['weak_cipher_count'] = len(weak_ciphers)
        
        if weak_ciphers:
            self.risks.append({
                'severity': 'CRITICAL',
                'category': 'Broken Cipher Suite',
                'count': len(weak_ciphers),
                'description': f"{len(weak_ciphers)} connections use broken/weak cipher suites",
                'impact': "Vulnerable to cryptographic attacks, potential plaintext recovery",
                'examples': weak_ciphers[:5]
            })
    
    def analyze_forward_secrecy(self):
        """Analyze forward secrecy support."""
        no_fs_count = 0
        no_fs_examples = []
        
        for entry in self.data:
            if 'selected_cipher' in entry:
                cipher = entry['selected_cipher']['name']
                # RSA key exchange (not ECDHE or DHE) lacks forward secrecy
                if 'RSA_WITH_' in cipher and not any(x in cipher for x in ['ECDHE', 'DHE']):
                    no_fs_count += 1
                    no_fs_examples.append({
                        'cipher': cipher,
                        'connection': entry.get('connection'),
                        'server': entry.get('server_name', entry.get('dst_ip'))
                    })
        
        self.stats['no_forward_secrecy'] = no_fs_count
        
        if no_fs_count > 0:
            self.risks.append({
                'severity': 'MEDIUM',
                'category': 'No Forward Secrecy',
                'count': no_fs_count,
                'description': f"{no_fs_count} connections lack forward secrecy (RSA key exchange)",
                'impact': "Past communications vulnerable if private key is compromised",
                'examples': no_fs_examples[:5]
            })
    
    def analyze_protocols(self):
        """Analyze protocol distribution."""
        protocol_counts = Counter(d.get('protocol', 'Unknown') for d in self.data)
        self.stats['protocols'] = dict(protocol_counts)
        
        # Identify protocols by encryption level
        encrypted_protocols = {}
        for entry in self.data:
            if entry.get('encrypted'):
                proto = entry.get('protocol', 'Unknown')
                encrypted_protocols[proto] = encrypted_protocols.get(proto, 0) + 1
        
        self.stats['encrypted_protocols'] = encrypted_protocols
    
    def analyze_weak_crypto(self):
        """Comprehensive weak crypto analysis."""
        weak_issues = []
        
        for entry in self.data:
            issues = []
            
            # Check TLS version
            tls_ver = entry.get('tls_version')
            if tls_ver in ['SSL 3.0', 'TLS 1.0', 'TLS 1.1']:
                issues.append(f"Weak TLS: {tls_ver}")
            
            # Check cipher
            if 'selected_cipher' in entry:
                cipher = entry['selected_cipher']['name']
                if 'RC4' in cipher:
                    issues.append("Cipher: RC4 (broken)")
                elif '3DES' in cipher:
                    issues.append("Cipher: 3DES (weak)")
                elif 'MD5' in cipher:
                    issues.append("Cipher: MD5 (broken hash)")
            
            # Check PQ status
            if entry.get('post_quantum_secure') == 'No':
                issues.append("Post-quantum: vulnerable")
            
            # Check forward secrecy
            if 'selected_cipher' in entry:
                cipher = entry['selected_cipher']['name']
                if 'RSA_WITH_' in cipher:
                    issues.append("Forward secrecy: none")
            
            if issues:
                weak_issues.append({
                    'connection': entry.get('connection'),
                    'server': entry.get('server_name', entry.get('dst_ip')),
                    'timestamp': entry.get('timestamp'),
                    'issues': issues
                })
        
        self.stats['weak_crypto_connections'] = len(weak_issues)
        self.stats['weak_crypto_examples'] = weak_issues[:10]
    
    def analyze_connections(self):
        """Analyze connection patterns."""
        src_ips = Counter(d.get('src_ip') for d in self.data if 'src_ip' in d)
        dst_ips = Counter(d.get('dst_ip') for d in self.data if 'dst_ip' in d)
        server_names = Counter(d.get('server_name') for d in self.data if 'server_name' in d)
        
        self.stats['top_source_ips'] = dict(src_ips.most_common(10))
        self.stats['top_destination_ips'] = dict(dst_ips.most_common(10))
        self.stats['top_server_names'] = dict(server_names.most_common(10))
        self.stats['unique_sources'] = len(src_ips)
        self.stats['unique_destinations'] = len(dst_ips)
    
    def analyze_timeline(self):
        """Analyze temporal patterns."""
        if not self.data:
            return
        
        hourly = defaultdict(int)
        for entry in self.data:
            if 'timestamp' in entry:
                ts = datetime.fromisoformat(entry['timestamp'])
                hour = ts.replace(minute=0, second=0, microsecond=0)
                hourly[hour.isoformat()] += 1
        
        self.stats['hourly_distribution'] = dict(sorted(hourly.items())[:24])
    
    def generate_risk_score(self):
        """Calculate overall risk score (0-100, higher = more risk)."""
        score = 0
        max_score = 100
        
        if self.stats['total_captures'] == 0:
            self.stats['risk_score'] = 0
            self.stats['risk_level'] = 'UNKNOWN'
            return
        
        # PQ vulnerability (25 points)
        pq_ratio = self.stats['pq_vulnerable'] / self.stats['total_captures']
        score += pq_ratio * 25
        
        # Weak TLS versions (25 points)
        if self.stats.get('weak_tls_count', 0) > 0:
            weak_ratio = self.stats['weak_tls_count'] / self.stats['total_captures']
            score += weak_ratio * 25
        
        # Weak ciphers (30 points)
        if self.stats.get('weak_cipher_count', 0) > 0:
            weak_cipher_ratio = self.stats['weak_cipher_count'] / self.stats['total_captures']
            score += weak_cipher_ratio * 30
        
        # No forward secrecy (20 points)
        if self.stats.get('no_forward_secrecy', 0) > 0:
            no_fs_ratio = self.stats['no_forward_secrecy'] / self.stats['total_captures']
            score += no_fs_ratio * 20
        
        self.stats['risk_score'] = min(score, max_score)
        
        # Risk level classification
        if score >= 75:
            self.stats['risk_level'] = 'CRITICAL'
        elif score >= 50:
            self.stats['risk_level'] = 'HIGH'
        elif score >= 25:
            self.stats['risk_level'] = 'MEDIUM'
        elif score > 0:
            self.stats['risk_level'] = 'LOW'
        else:
            self.stats['risk_level'] = 'MINIMAL'
    
    def generate_recommendations(self):
        """Generate actionable recommendations."""
        # PQ recommendations
        if self.stats.get('pq_vulnerable', 0) > 0:
            self.recommendations.append({
                'priority': 'HIGH',
                'category': 'Post-Quantum Migration',
                'action': 'Upgrade to post-quantum safe cryptography',
                'details': [
                    f"{self.stats['pq_vulnerable']} connections are quantum-vulnerable",
                    "Plan migration to hybrid or PQ-only algorithms",
                    "Prioritize systems with long data retention requirements",
                    "Consider 'store-now-decrypt-later' attack threat"
                ]
            })
        
        # TLS version recommendations
        if self.stats.get('weak_tls_count', 0) > 0:
            self.recommendations.append({
                'priority': 'CRITICAL',
                'category': 'TLS Version Upgrade',
                'action': 'Disable TLS 1.0, TLS 1.1, and SSL 3.0',
                'details': [
                    f"{self.stats['weak_tls_count']} connections use deprecated TLS versions",
                    "Enforce TLS 1.2 as minimum (TLS 1.3 preferred)",
                    "Update client and server configurations",
                    "Test for compatibility issues before deployment"
                ]
            })
        
        # Cipher suite recommendations
        if self.stats.get('weak_cipher_count', 0) > 0:
            self.recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Cipher Suite Update',
                'action': 'Remove broken and weak cipher suites',
                'details': [
                    f"{self.stats['weak_cipher_count']} connections use weak ciphers",
                    "Disable: RC4, 3DES, DES, MD5, NULL, EXPORT ciphers",
                    "Prefer: AES-GCM, ChaCha20-Poly1305",
                    "Update cipher suite priority order"
                ]
            })
        
        # Forward secrecy recommendations
        if self.stats.get('no_forward_secrecy', 0) > 0:
            self.recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Forward Secrecy',
                'action': 'Enable forward secrecy on all connections',
                'details': [
                    f"{self.stats['no_forward_secrecy']} connections lack forward secrecy",
                    "Use ECDHE or DHE key exchange",
                    "Disable RSA key exchange",
                    "Protects past communications if keys compromised"
                ]
            })
        
        # General recommendations
        if self.stats.get('pq_hybrid', 0) > 0:
            self.recommendations.append({
                'priority': 'LOW',
                'category': 'PQ Migration Progress',
                'action': 'Continue hybrid deployment, plan for PQ-only',
                'details': [
                    f"{self.stats['pq_hybrid']} connections use hybrid crypto (good!)",
                    "Hybrid provides transitional security",
                    "Monitor for full PQ support availability",
                    "Plan eventual migration to PQ-only"
                ]
            })


class ReportGenerator:
    def __init__(self, stats, risks, recommendations):
        self.stats = stats
        self.risks = risks
        self.recommendations = recommendations
    
    def generate_text(self):
        """Generate text report."""
        report = []
        report.append("=" * 80)
        report.append("CRYPTO SECURITY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Executive summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 80)
        report.append(f"Risk Level: {self.stats.get('risk_level', 'UNKNOWN')}")
        report.append(f"Risk Score: {self.stats.get('risk_score', 0):.1f}/100")
        report.append(f"Total Captures: {self.stats.get('total_captures', 0)}")
        report.append(f"Analysis Period: {self.stats.get('first_capture', 'N/A')} to {self.stats.get('last_capture', 'N/A')}")
        report.append(f"Duration: {self.stats.get('duration_hours', 0):.1f} hours")
        report.append("")
        
        # Post-quantum status
        report.append("POST-QUANTUM SECURITY STATUS")
        report.append("-" * 80)
        report.append(f"✅ Post-Quantum Secure:    {self.stats.get('pq_secure', 0):5d} ({self.stats.get('pq_secure_pct', 0):.1f}%)")
        report.append(f"🔐 Hybrid (PQ+Classical):  {self.stats.get('pq_hybrid', 0):5d} ({self.stats.get('pq_hybrid_pct', 0):.1f}%)")
        report.append(f"⚠️  Quantum-Vulnerable:     {self.stats.get('pq_vulnerable', 0):5d} ({self.stats.get('pq_vulnerable_pct', 0):.1f}%)")
        report.append(f"❓ Unknown:                {self.stats.get('pq_unknown', 0):5d}")
        report.append("")
        
        # Critical findings
        if self.risks:
            report.append("CRITICAL FINDINGS")
            report.append("-" * 80)
            for risk in sorted(self.risks, key=lambda r: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(r['severity'], 4)):
                report.append(f"[{risk['severity']}] {risk['category']}")
                report.append(f"  Count: {risk['count']}")
                report.append(f"  Description: {risk['description']}")
                report.append(f"  Impact: {risk['impact']}")
                if 'examples' in risk and risk['examples']:
                    report.append(f"  Examples:")
                    for ex in risk['examples'][:3]:
                        if isinstance(ex, dict):
                            report.append(f"    - {ex}")
                report.append("")
        
        # TLS versions
        if self.stats.get('tls_versions'):
            report.append("TLS VERSION DISTRIBUTION")
            report.append("-" * 80)
            for version, count in sorted(self.stats['tls_versions'].items(), key=lambda x: x[1], reverse=True):
                pct = (count / self.stats['total_captures']) * 100 if self.stats['total_captures'] > 0 else 0
                indicator = "⚠️" if version in ['SSL 3.0', 'TLS 1.0', 'TLS 1.1'] else "✓"
                report.append(f"  {indicator} {version:15s} {count:5d} ({pct:5.1f}%)")
            report.append("")
        
        # Cipher suites
        if self.stats.get('cipher_suites'):
            report.append("TOP 10 CIPHER SUITES")
            report.append("-" * 80)
            for cipher, count in list(self.stats['cipher_suites'].items())[:10]:
                pct = (count / self.stats['total_captures']) * 100 if self.stats['total_captures'] > 0 else 0
                report.append(f"  {cipher[:60]:60s} {count:4d} ({pct:4.1f}%)")
            report.append("")
        
        # Protocol distribution
        if self.stats.get('protocols'):
            report.append("PROTOCOL DISTRIBUTION")
            report.append("-" * 80)
            for protocol, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                pct = (count / self.stats['total_captures']) * 100 if self.stats['total_captures'] > 0 else 0
                report.append(f"  {protocol:20s} {count:5d} ({pct:5.1f}%)")
            report.append("")
        
        # Top talkers
        if self.stats.get('top_server_names'):
            report.append("TOP 10 SERVER NAMES (SNI)")
            report.append("-" * 80)
            for server, count in list(self.stats['top_server_names'].items())[:10]:
                report.append(f"  {server:50s} {count:5d}")
            report.append("")
        
        # Recommendations
        if self.recommendations:
            report.append("RECOMMENDATIONS")
            report.append("-" * 80)
            for i, rec in enumerate(self.recommendations, 1):
                report.append(f"{i}. [{rec['priority']}] {rec['category']}")
                report.append(f"   Action: {rec['action']}")
                report.append(f"   Details:")
                for detail in rec['details']:
                    report.append(f"     • {detail}")
                report.append("")
        
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def generate_markdown(self):
        """Generate Markdown report."""
        report = []
        report.append("# Crypto Security Analysis Report")
        report.append("")
        
        # Executive summary
        report.append("## Executive Summary")
        report.append("")
        report.append(f"**Risk Level:** {self.stats.get('risk_level', 'UNKNOWN')}")
        report.append(f"**Risk Score:** {self.stats.get('risk_score', 0):.1f}/100")
        report.append("")
        report.append(f"- **Total Captures:** {self.stats.get('total_captures', 0)}")
        report.append(f"- **Analysis Period:** {self.stats.get('first_capture', 'N/A')} to {self.stats.get('last_capture', 'N/A')}")
        report.append(f"- **Duration:** {self.stats.get('duration_hours', 0):.1f} hours")
        report.append("")
        
        # Post-quantum status
        report.append("## Post-Quantum Security Status")
        report.append("")
        report.append("| Status | Count | Percentage |")
        report.append("|--------|-------|------------|")
        report.append(f"| ✅ Post-Quantum Secure | {self.stats.get('pq_secure', 0)} | {self.stats.get('pq_secure_pct', 0):.1f}% |")
        report.append(f"| 🔐 Hybrid (PQ+Classical) | {self.stats.get('pq_hybrid', 0)} | {self.stats.get('pq_hybrid_pct', 0):.1f}% |")
        report.append(f"| ⚠️ Quantum-Vulnerable | {self.stats.get('pq_vulnerable', 0)} | {self.stats.get('pq_vulnerable_pct', 0):.1f}% |")
        report.append(f"| ❓ Unknown | {self.stats.get('pq_unknown', 0)} | - |")
        report.append("")
        
        # Critical findings
        if self.risks:
            report.append("## Critical Findings")
            report.append("")
            for risk in sorted(self.risks, key=lambda r: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(r['severity'], 4)):
                report.append(f"### [{risk['severity']}] {risk['category']}")
                report.append("")
                report.append(f"- **Count:** {risk['count']}")
                report.append(f"- **Description:** {risk['description']}")
                report.append(f"- **Impact:** {risk['impact']}")
                report.append("")
        
        # TLS versions
        if self.stats.get('tls_versions'):
            report.append("## TLS Version Distribution")
            report.append("")
            report.append("| Version | Count | Percentage | Status |")
            report.append("|---------|-------|------------|--------|")
            for version, count in sorted(self.stats['tls_versions'].items(), key=lambda x: x[1], reverse=True):
                pct = (count / self.stats['total_captures']) * 100 if self.stats['total_captures'] > 0 else 0
                status = "⚠️ Deprecated" if version in ['SSL 3.0', 'TLS 1.0', 'TLS 1.1'] else "✓ OK"
                report.append(f"| {version} | {count} | {pct:.1f}% | {status} |")
            report.append("")
        
        # Protocol distribution
        if self.stats.get('protocols'):
            report.append("## Protocol Distribution")
            report.append("")
            report.append("| Protocol | Count | Percentage |")
            report.append("|----------|-------|------------|")
            for protocol, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
                pct = (count / self.stats['total_captures']) * 100 if self.stats['total_captures'] > 0 else 0
                report.append(f"| {protocol} | {count} | {pct:.1f}% |")
            report.append("")
        
        # Recommendations
        if self.recommendations:
            report.append("## Recommendations")
            report.append("")
            for i, rec in enumerate(self.recommendations, 1):
                report.append(f"### {i}. [{rec['priority']}] {rec['category']}")
                report.append("")
                report.append(f"**Action:** {rec['action']}")
                report.append("")
                report.append("**Details:**")
                for detail in rec['details']:
                    report.append(f"- {detail}")
                report.append("")
        
        return "\n".join(report)
    
    def generate_json(self):
        """Generate JSON report."""
        return json.dumps({
            'stats': self.stats,
            'risks': self.risks,
            'recommendations': self.recommendations
        }, indent=2)
    
    def generate_html(self):
        """Generate HTML report."""
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("<title>Crypto Security Analysis Report</title>")
        html.append("<style>")
        html.append("body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }")
        html.append(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }")
        html.append("h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }")
        html.append("h2 { color: #34495e; margin-top: 30px; border-bottom: 2px solid #ecf0f1; padding-bottom: 5px; }")
        html.append("h3 { color: #7f8c8d; }")
        html.append(".risk-critical { background: #e74c3c; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }")
        html.append(".risk-high { background: #e67e22; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }")
        html.append(".risk-medium { background: #f39c12; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }")
        html.append(".risk-low { background: #3498db; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }")
        html.append(".stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }")
        html.append(".stat-box { background: #ecf0f1; padding: 20px; border-radius: 5px; text-align: center; }")
        html.append(".stat-value { font-size: 36px; font-weight: bold; color: #2c3e50; }")
        html.append(".stat-label { color: #7f8c8d; margin-top: 5px; }")
        html.append("table { width: 100%; border-collapse: collapse; margin: 20px 0; }")
        html.append("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }")
        html.append("th { background: #34495e; color: white; }")
        html.append("tr:hover { background: #ecf0f1; }")
        html.append(".recommendation { background: #ecf0f1; padding: 15px; margin: 10px 0; border-left: 5px solid #3498db; }")
        html.append("</style>")
        html.append("</head>")
        html.append("<body>")
        html.append("<div class='container'>")
        
        html.append("<h1>Crypto Security Analysis Report</h1>")
        
        # Stats boxes
        html.append("<div class='stats'>")
        html.append(f"<div class='stat-box'><div class='stat-value'>{self.stats.get('risk_level', 'UNKNOWN')}</div><div class='stat-label'>Risk Level</div></div>")
        html.append(f"<div class='stat-box'><div class='stat-value'>{self.stats.get('risk_score', 0):.0f}</div><div class='stat-label'>Risk Score (0-100)</div></div>")
        html.append(f"<div class='stat-box'><div class='stat-value'>{self.stats.get('total_captures', 0)}</div><div class='stat-label'>Total Captures</div></div>")
        html.append(f"<div class='stat-box'><div class='stat-value'>{self.stats.get('pq_vulnerable', 0)}</div><div class='stat-label'>Quantum-Vulnerable</div></div>")
        html.append("</div>")
        
        # Post-quantum status
        html.append("<h2>Post-Quantum Security Status</h2>")
        html.append("<table>")
        html.append("<tr><th>Status</th><th>Count</th><th>Percentage</th></tr>")
        html.append(f"<tr><td>✅ Post-Quantum Secure</td><td>{self.stats.get('pq_secure', 0)}</td><td>{self.stats.get('pq_secure_pct', 0):.1f}%</td></tr>")
        html.append(f"<tr><td>🔐 Hybrid (PQ+Classical)</td><td>{self.stats.get('pq_hybrid', 0)}</td><td>{self.stats.get('pq_hybrid_pct', 0):.1f}%</td></tr>")
        html.append(f"<tr><td>⚠️ Quantum-Vulnerable</td><td>{self.stats.get('pq_vulnerable', 0)}</td><td>{self.stats.get('pq_vulnerable_pct', 0):.1f}%</td></tr>")
        html.append(f"<tr><td>❓ Unknown</td><td>{self.stats.get('pq_unknown', 0)}</td><td>-</td></tr>")
        html.append("</table>")
        
        # Critical findings
        if self.risks:
            html.append("<h2>Critical Findings</h2>")
            for risk in self.risks:
                severity_class = f"risk-{risk['severity'].lower()}"
                html.append(f"<div class='{severity_class}'>")
                html.append(f"<h3>[{risk['severity']}] {risk['category']}</h3>")
                html.append(f"<p><strong>Count:</strong> {risk['count']}</p>")
                html.append(f"<p><strong>Description:</strong> {risk['description']}</p>")
                html.append(f"<p><strong>Impact:</strong> {risk['impact']}</p>")
                html.append("</div>")
        
        # Recommendations
        if self.recommendations:
            html.append("<h2>Recommendations</h2>")
            for i, rec in enumerate(self.recommendations, 1):
                html.append("<div class='recommendation'>")
                html.append(f"<h3>{i}. [{rec['priority']}] {rec['category']}</h3>")
                html.append(f"<p><strong>Action:</strong> {rec['action']}</p>")
                html.append("<p><strong>Details:</strong></p><ul>")
                for detail in rec['details']:
                    html.append(f"<li>{detail}</li>")
                html.append("</ul></div>")
        
        html.append("</div>")
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)


def generate_pdf_from_markdown(markdown_file, pdf_file, verbose=False):
    """Generate PDF from markdown file using available library."""
    if not PDF_AVAILABLE:
        if verbose:
            print("PDF generation not available (install: pip3 install markdown weasyprint)", file=sys.stderr)
        return False
    
    try:
        # Read markdown file
        with open(markdown_file, 'r') as f:
            markdown_content = f.read()
        
        # Convert markdown to HTML
        import markdown as md
        html_content = md.markdown(markdown_content, extensions=['tables'])
        
        # Add CSS styling
        styled_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
h2 {{ color: #34495e; margin-top: 30px; border-bottom: 2px solid #ecf0f1; padding-bottom: 5px; }}
h3 {{ color: #7f8c8d; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
th, td {{ padding: 10px; text-align: left; border: 1px solid #ddd; }}
th {{ background-color: #34495e; color: white; }}
tr:nth-child(even) {{ background-color: #f9f9f9; }}
ul, ol {{ margin-left: 20px; }}
li {{ margin: 5px 0; }}
code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
strong {{ color: #2c3e50; }}
</style>
</head>
<body>
{html_content}
</body>
</html>
"""
        
        # Generate PDF
        if PDF_METHOD == 'weasyprint':
            HTML(string=styled_html).write_pdf(pdf_file)
            if verbose:
                print(f"✓ PDF generated: {pdf_file} (using weasyprint)", file=sys.stderr)
        elif PDF_METHOD == 'pdfkit':
            pdfkit.from_string(styled_html, pdf_file)
            if verbose:
                print(f"✓ PDF generated: {pdf_file} (using pdfkit)", file=sys.stderr)
        
        return True
        
    except Exception as e:
        if verbose:
            print(f"Warning: PDF generation failed: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Analyze stinky.json crypto captures and generate security reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PDF Generation:
  When markdown format is selected (-F markdown), automatically generates PDF
  if markdown and weasyprint (or pdfkit) libraries are installed.
  
  Install: pip3 install markdown weasyprint
  
  Use --no-pdf to disable automatic PDF generation.
        """
    )
    
    parser.add_argument('file', nargs='?', default='stinky.json',
                       help='Input JSON file (default: stinky.json)')
    parser.add_argument('-f', '--file', dest='file_flag',
                       help='Input JSON file')
    parser.add_argument('-o', '--output', 
                       help='Output file (default: stdout)')
    parser.add_argument('-F', '--format', choices=['text', 'markdown', 'html', 'json'],
                       default='text',
                       help='Output format (default: text)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-pdf', action='store_true',
                       help='Disable automatic PDF generation from markdown')
    parser.add_argument('--since',
                       help='Only analyze captures after this timestamp')
    parser.add_argument('--before',
                       help='Only analyze captures before this timestamp')
    
    args = parser.parse_args()
    
    # Handle file argument
    input_file = args.file_flag if args.file_flag else args.file
    
    # Load data
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {input_file}", file=sys.stderr)
        print(f"Run stinky.py first to generate captures.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {input_file}: {e}", file=sys.stderr)
        sys.exit(1)
    
    if args.verbose:
        print(f"Loaded {len(data)} captures from {input_file}", file=sys.stderr)
    
    # Filter by time range if specified
    if args.since or args.before:
        filtered_data = []
        for entry in data:
            if 'timestamp' not in entry:
                continue
            
            ts = datetime.fromisoformat(entry['timestamp'])
            
            if args.since:
                since_dt = datetime.fromisoformat(args.since)
                if ts < since_dt:
                    continue
            
            if args.before:
                before_dt = datetime.fromisoformat(args.before)
                if ts > before_dt:
                    continue
            
            filtered_data.append(entry)
        
        data = filtered_data
        if args.verbose:
            print(f"Filtered to {len(data)} captures", file=sys.stderr)
    
    # Analyze
    analyzer = CryptoAnalyzer(data)
    stats, risks, recommendations = analyzer.analyze()
    
    if args.verbose:
        print(f"Analysis complete. Risk level: {stats.get('risk_level')}", file=sys.stderr)
    
    # Generate report
    generator = ReportGenerator(stats, risks, recommendations)
    
    if args.format == 'text':
        report = generator.generate_text()
    elif args.format == 'markdown':
        report = generator.generate_markdown()
    elif args.format == 'html':
        report = generator.generate_html()
    elif args.format == 'json':
        report = generator.generate_json()
    
    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        if args.verbose:
            print(f"Report written to {args.output}", file=sys.stderr)
        
        # Generate PDF from markdown if applicable
        if args.format == 'markdown' and not args.no_pdf and PDF_AVAILABLE:
            pdf_file = args.output.rsplit('.', 1)[0] + '.pdf'
            if generate_pdf_from_markdown(args.output, pdf_file, args.verbose):
                if not args.verbose:
                    print(f"✓ PDF report: {pdf_file}", file=sys.stderr)
    else:
        print(report)
        
        # Show PDF availability message if markdown format
        if args.format == 'markdown' and not args.no_pdf:
            if PDF_AVAILABLE:
                print("\nNote: To generate PDF, specify -o output.md", file=sys.stderr)
            else:
                print("\nNote: Install markdown + weasyprint for PDF generation:", file=sys.stderr)
                print("      pip3 install markdown weasyprint", file=sys.stderr)


if __name__ == "__main__":
    main()
