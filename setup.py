#!/usr/bin/env python3
"""
Setup script for Telegram Terminal Bot
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def install_requirements():
    """Install required packages"""
    logger.info("Installing required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        logger.info("✅ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to install requirements: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = [
        "logs",
        "data",
        "backups",
        "temp"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        logger.info(f"✅ Created directory: {directory}")
    
    return True

def generate_encryption_key():
    """Generate encryption key for secure communications"""
    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        
        # Save key to file
        with open(".env", "a") as f:
            f.write(f"\nENCRYPTION_KEY={key.decode()}\n")
        
        logger.info("✅ Generated encryption key")
        return True
    except ImportError:
        logger.error("❌ cryptography package not installed")
        return False
    except Exception as e:
        logger.error(f"❌ Error generating encryption key: {e}")
        return False

def create_env_file():
    """Create environment file if it doesn't exist"""
    if not os.path.exists(".env"):
        logger.info("Creating .env file...")
        
        # Copy example file
        if os.path.exists(".env.example"):
            with open(".env.example", "r") as src, open(".env", "w") as dst:
                dst.write(src.read())
            logger.info("✅ Created .env file from example")
            return True
        else:
            logger.error("❌ .env.example file not found")
            return False
    
    logger.info("✅ .env file already exists")
    return True

def check_system_dependencies():
    """Check for system dependencies"""
    dependencies = {
        'nmap': ['nmap', '--version'],
        'traceroute': ['traceroute', '--version'],
        'ping': ['ping', '-c', '1', 'localhost']
    }
    
    missing = []
    
    for dep, cmd in dependencies.items():
        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
            logger.info(f"✅ {dep} is available")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning(f"⚠️ {dep} is not available or not working")
            missing.append(dep)
    
    if missing:
        logger.warning(f"Missing system dependencies: {', '.join(missing)}")
        logger.warning("Some features may not work properly")
    
    return True

def main():
    """Main setup function"""
    logger.info("🚀 Starting Telegram Terminal Bot setup...")
    
    # Check Python version
    if sys.version_info < (3, 7):
        logger.error("❌ Python 3.7 or higher is required")
        return False
    
    logger.info(f"✅ Python version: {sys.version}")
    
    # Install requirements
    if not install_requirements():
        return False
    
    # Create directories
    if not create_directories():
        return False
    
    # Create environment file
    if not create_env_file():
        return False
    
    # Generate encryption key
    if not generate_encryption_key():
        return False
    
    # Check system dependencies
    check_system_dependencies()
    
    logger.info("\n🎉 Setup completed successfully!")
    logger.info("\nNext steps:")
    logger.info("1. Edit .env file with your Telegram bot token")
    logger.info("2. Add allowed user IDs to ALLOWED_USERS")
    logger.info("3. Run: python telegram_terminal_bot.py")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)