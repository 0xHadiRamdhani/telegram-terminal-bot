#!/usr/bin/env python3
"""
Test script for Telegram Terminal Bot
Comprehensive testing of all functionalities
"""

import asyncio
import os
import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BotTester:
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.test_results = []
    
    def log_test(self, test_name: str, passed: bool, message: str = ""):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.test_results.append(f"{status} - {test_name}: {message}")
        
        if passed:
            self.tests_passed += 1
            logger.info(f"✅ {test_name}: {message}")
        else:
            self.tests_failed += 1
            logger.error(f"❌ {test_name}: {message}")
    
    async def test_imports(self):
        """Test all imports"""
        test_name = "Import Tests"
        
        try:
            # Test basic imports
            import telegram
            self.log_test(f"{test_name} - telegram", True)
        except ImportError as e:
            self.log_test(f"{test_name} - telegram", False, str(e))
        
        try:
            import nmap
            self.log_test(f"{test_name} - nmap", True)
        except ImportError as e:
            self.log_test(f"{test_name} - nmap", False, str(e))
        
        try:
            import requests
            self.log_test(f"{test_name} - requests", True)
        except ImportError as e:
            self.log_test(f"{test_name} - requests", False, str(e))
        
        try:
            import cryptocompare
            self.log_test(f"{test_name} - cryptocompare", True)
        except ImportError as e:
            self.log_test(f"{test_name} - cryptocompare", False, str(e))
        
        try:
            from cryptography.fernet import Fernet
            self.log_test(f"{test_name} - cryptography", True)
        except ImportError as e:
            self.log_test(f"{test_name} - cryptography", False, str(e))
        
        try:
            from geopy.geocoders import Nominatim
            self.log_test(f"{test_name} - geopy", True)
        except ImportError as e:
            self.log_test(f"{test_name} - geopy", False, str(e))
    
    async def test_custom_modules(self):
        """Test custom utility modules"""
        test_name = "Custom Modules"
        
        try:
            from network_utils import NetworkAnalyzer, IPGeolocation, SecurityAnalyzer
            self.log_test(f"{test_name} - network_utils", True)
        except ImportError as e:
            self.log_test(f"{test_name} - network_utils", False, str(e))
        
        try:
            from crypto_utils import CryptoAnalyzer, CryptoPortfolio
            self.log_test(f"{test_name} - crypto_utils", True)
        except ImportError as e:
            self.log_test(f"{test_name} - crypto_utils", False, str(e))
    
    async def test_environment_variables(self):
        """Test environment variables"""
        test_name = "Environment Variables"
        
        # Check if .env file exists
        if os.path.exists(".env"):
            self.log_test(f"{test_name} - .env file exists", True)
        else:
            self.log_test(f"{test_name} - .env file exists", False, "File not found")
        
        # Test loading environment variables
        try:
            from dotenv import load_dotenv
            load_dotenv()
            self.log_test(f"{test_name} - dotenv load", True)
        except Exception as e:
            self.log_test(f"{test_name} - dotenv load", False, str(e))
        
        # Check critical variables
        required_vars = ['TELEGRAM_BOT_TOKEN', 'ALLOWED_USERS', 'ENCRYPTION_KEY']
        for var in required_vars:
            value = os.getenv(var)
            if value:
                self.log_test(f"{test_name} - {var}", True, f"Set to: {value[:20]}...")
            else:
                self.log_test(f"{test_name} - {var}", False, "Not set")
    
    async def test_encryption(self):
        """Test encryption functionality"""
        test_name = "Encryption"
        
        try:
            from cryptography.fernet import Fernet
            
            # Generate test key
            key = Fernet.generate_key()
            cipher = Fernet(key)
            
            # Test encryption/decryption
            test_data = "Test data for encryption"
            encrypted = cipher.encrypt(test_data.encode())
            decrypted = cipher.decrypt(encrypted).decode()
            
            if decrypted == test_data:
                self.log_test(f"{test_name} - encryption/decryption", True)
            else:
                self.log_test(f"{test_name} - encryption/decryption", False, "Data mismatch")
                
        except Exception as e:
            self.log_test(f"{test_name} - encryption/decryption", False, str(e))
    
    async def test_network_utils(self):
        """Test network utility functions"""
        test_name = "Network Utils"
        
        try:
            from network_utils import NetworkAnalyzer
            
            analyzer = NetworkAnalyzer()
            
            # Test local network info
            network_info = analyzer.get_local_network_info()
            if network_info and 'hostname' in network_info:
                self.log_test(f"{test_name} - local network info", True, f"Hostname: {network_info['hostname']}")
            else:
                self.log_test(f"{test_name} - local network info", False, "No data returned")
            
            # Test ping functionality
            ping_result = analyzer.ping_host("8.8.8.8", count=1)
            if ping_result and 'status' in ping_result:
                self.log_test(f"{test_name} - ping functionality", True, f"Status: {ping_result['status']}")
            else:
                self.log_test(f"{test_name} - ping functionality", False, "No response")
                
        except Exception as e:
            self.log_test(f"{test_name} - network utils", False, str(e))
    
    async def test_crypto_utils(self):
        """Test cryptocurrency utility functions"""
        test_name = "Crypto Utils"
        
        try:
            from crypto_utils import CryptoAnalyzer
            
            analyzer = CryptoAnalyzer()
            
            # Test crypto price fetching
            prices = await analyzer.get_multiple_prices(['BTC', 'ETH'], 'USD')
            if prices and 'BTC' in prices:
                self.log_test(f"{test_name} - crypto prices", True, f"BTC: ${prices['BTC']['USD']}")
            else:
                self.log_test(f"{test_name} - crypto prices", False, "No data returned")
            
            # Test top cryptocurrencies
            top_coins = await analyzer.get_top_cryptocurrencies(5)
            if top_coins and len(top_coins) > 0:
                self.log_test(f"{test_name} - top cryptocurrencies", True, f"Found {len(top_coins)} coins")
            else:
                self.log_test(f"{test_name} - top cryptocurrencies", False, "No data returned")
                
        except Exception as e:
            self.log_test(f"{test_name} - crypto utils", False, str(e))
    
    async def test_geolocation(self):
        """Test geolocation functionality"""
        test_name = "Geolocation"
        
        try:
            from network_utils import IPGeolocation
            
            geo = IPGeolocation()
            
            # Test IP geolocation
            ip_info = geo.get_ip_info("8.8.8.8")
            if ip_info:
                self.log_test(f"{test_name} - IP geolocation", True, "Data retrieved successfully")
            else:
                self.log_test(f"{test_name} - IP geolocation", False, "No data returned")
                
        except Exception as e:
            self.log_test(f"{test_name} - geolocation", False, str(e))
    
    async def test_file_structure(self):
        """Test file structure and permissions"""
        test_name = "File Structure"
        
        # Check required files
        required_files = [
            'telegram_terminal_bot.py',
            'requirements.txt',
            'setup.py',
            'README.md',
            '.env.example',
            'network_utils.py',
            'crypto_utils.py'
        ]
        
        for file in required_files:
            if os.path.exists(file):
                self.log_test(f"{test_name} - {file}", True)
            else:
                self.log_test(f"{test_name} - {file}", False, "File not found")
        
        # Check directories
        required_dirs = ['logs', 'data', 'backups', 'temp']
        for dir in required_dirs:
            path = Path(dir)
            if path.exists():
                self.log_test(f"{test_name} - {dir} directory", True)
            else:
                self.log_test(f"{test_name} - {dir} directory", False, "Directory not found")
    
    async def test_system_dependencies(self):
        """Test system dependencies"""
        test_name = "System Dependencies"
        
        import subprocess
        
        # Test nmap
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.log_test(f"{test_name} - nmap", True, "Available")
            else:
                self.log_test(f"{test_name} - nmap", False, "Not working properly")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.log_test(f"{test_name} - nmap", False, "Not installed or not accessible")
        
        # Test ping
        try:
            result = subprocess.run(['ping', '-c', '1', 'localhost'], capture_output=True, text=True, timeout=10)
            self.log_test(f"{test_name} - ping", True, "Available")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.log_test(f"{test_name} - ping", False, "Not available")
    
    async def run_all_tests(self):
        """Run all tests"""
        logger.info("🚀 Starting Telegram Terminal Bot tests...")
        
        # Run tests
        await self.test_imports()
        await self.test_custom_modules()
        await self.test_environment_variables()
        await self.test_encryption()
        await self.test_network_utils()
        await self.test_crypto_utils()
        await self.test_geolocation()
        await self.test_file_structure()
        await self.test_system_dependencies()
        
        # Print summary
        logger.info("\n" + "="*50)
        logger.info("📊 TEST SUMMARY")
        logger.info("="*50)
        
        for result in self.test_results:
            logger.info(result)
        
        logger.info(f"\n✅ Tests Passed: {self.tests_passed}")
        logger.info(f"❌ Tests Failed: {self.tests_failed}")
        logger.info(f"📈 Success Rate: {(self.tests_passed/(self.tests_passed + self.tests_failed)*100):.1f}%")
        
        if self.tests_failed == 0:
            logger.info("\n🎉 All tests passed! Bot is ready to run.")
            return True
        else:
            logger.warning(f"\n⚠️ {self.tests_failed} tests failed. Review and fix issues before running.")
            return False

async def main():
    """Main test function"""
    tester = BotTester()
    success = await tester.run_all_tests()
    
    if success:
        logger.info("\n💡 Next steps:")
        logger.info("1. Configure your .env file with Telegram bot token")
        logger.info("2. Add allowed user IDs")
        logger.info("3. Run: python3 telegram_terminal_bot.py")
    else:
        logger.info("\n🔧 Please fix the failed tests before proceeding.")
    
    return success

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)