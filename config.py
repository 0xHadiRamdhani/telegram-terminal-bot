#!/usr/bin/env python3
"""
Configuration file for Telegram Terminal Bot
Centralized configuration management
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Configuration class for the bot"""
    
    # Bot Configuration
    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
    ALLOWED_USERS = set(os.getenv('ALLOWED_USERS', '').split(',')) if os.getenv('ALLOWED_USERS') else set()
    ADMIN_USERS = set(os.getenv('ADMIN_USERS', '').split(',')) if os.getenv('ADMIN_USERS') else set()
    
    # Security Configuration
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', '')
    RATE_LIMIT_SECONDS = int(os.getenv('RATE_LIMIT_SECONDS', '2'))
    COMMAND_TIMEOUT = int(os.getenv('COMMAND_TIMEOUT', '30'))
    MAX_OUTPUT_LENGTH = int(os.getenv('MAX_OUTPUT_LENGTH', '4000'))
    
    # API Keys
    CRYPTO_API_KEY = os.getenv('CRYPTO_API_KEY', '')
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/bot_activity.log')
    LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', '30'))
    
    # Network Configuration
    PING_TIMEOUT = int(os.getenv('PING_TIMEOUT', '10'))
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', '60'))
    MAX_SCAN_PORTS = int(os.getenv('MAX_SCAN_PORTS', '1000'))
    
    # Crypto Configuration
    CRYPTO_CACHE_SECONDS = int(os.getenv('CRYPTO_CACHE_SECONDS', '60'))
    DEFAULT_CRYPTO_CURRENCY = os.getenv('DEFAULT_CRYPTO_CURRENCY', 'USD')
    
    # File Paths
    BASE_DIR = Path(__file__).parent
    LOGS_DIR = BASE_DIR / 'logs'
    DATA_DIR = BASE_DIR / 'data'
    BACKUPS_DIR = BASE_DIR / 'backups'
    TEMP_DIR = BASE_DIR / 'temp'
    
    # Security Settings
    DANGEROUS_COMMANDS = [
        'rm -rf', 'dd', 'mkfs', 'fdisk', ':(){ :|:& };:', 
        'wget', 'curl', 'nc', 'netcat', 'bash -i', 'sh -i',
        'python -c', 'perl -e', 'ruby -e', 'php -r',
        'mysql', 'psql', 'mongo', 'redis-cli',
        'sudo', 'su', 'passwd', 'chown', 'chmod 777'
    ]
    
    ALLOWED_COMMANDS = [
        'ls', 'pwd', 'cd', 'cat', 'echo', 'grep', 'find',
        'ps', 'top', 'htop', 'df', 'du', 'free', 'uptime',
        'whoami', 'id', 'uname', 'date', 'cal', 'history',
        'which', 'whereis', 'file', 'stat', 'head', 'tail',
        'wc', 'sort', 'uniq', 'cut', 'awk', 'sed', 'tr',
        'zip', 'unzip', 'tar', 'gzip', 'gunzip'
    ]
    
    @classmethod
    def validate_config(cls):
        """Validate configuration settings"""
        errors = []
        
        if not cls.TELEGRAM_BOT_TOKEN:
            errors.append("TELEGRAM_BOT_TOKEN is required")
        
        if not cls.ENCRYPTION_KEY:
            errors.append("ENCRYPTION_KEY is required")
        
        if not cls.ALLOWED_USERS:
            errors.append("ALLOWED_USERS is required")
        
        return errors
    
    @classmethod
    def create_directories(cls):
        """Create necessary directories"""
        directories = [
            cls.LOGS_DIR,
            cls.DATA_DIR,
            cls.BACKUPS_DIR,
            cls.TEMP_DIR
        ]
        
        for directory in directories:
            directory.mkdir(exist_ok=True)
    
    @classmethod
    def is_user_allowed(cls, user_id: str) -> bool:
        """Check if user is allowed to use the bot"""
        return user_id in cls.ALLOWED_USERS or user_id in cls.ADMIN_USERS
    
    @classmethod
    def is_user_admin(cls, user_id: str) -> bool:
        """Check if user is admin"""
        return user_id in cls.ADMIN_USERS
    
    @classmethod
    def is_command_allowed(cls, command: str) -> bool:
        """Check if command is allowed"""
        command_lower = command.lower().strip()
        
        # Check for dangerous commands
        for dangerous in cls.DANGEROUS_COMMANDS:
            if dangerous.lower() in command_lower:
                return False
        
        # Check if command starts with allowed commands
        for allowed in cls.ALLOWED_COMMANDS:
            if command_lower.startswith(allowed.lower()):
                return True
        
        # Allow basic shell built-ins
        basic_commands = ['echo', 'printf', 'test', '[', 'true', 'false']
        for basic in basic_commands:
            if command_lower.startswith(basic):
                return True
        
        return False

# Create configuration instance
config = Config()

# Create directories on import
config.create_directories()

# Validate configuration
validation_errors = config.validate_config()
if validation_errors:
    raise ValueError(f"Configuration errors: {', '.join(validation_errors)}")

logger = logging.getLogger(__name__)
logger.info("✅ Configuration loaded successfully")