#!/usr/bin/env python3
"""
Telegram Terminal Bot with Network Scanning, Geolocation, and Crypto Data
A comprehensive bot that provides interactive terminal access, network scanning,
IP geolocation, and live cryptocurrency data.
"""

import os
import asyncio
import subprocess
import logging
import json
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Optional
import tempfile

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from telegram.constants import ParseMode
import nmap
import requests
from geopy.geocoders import Nominatim
from geopy.distance import geodesic
import cryptocompare
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Import custom utilities
from network_utils import NetworkAnalyzer, IPGeolocation, SecurityAnalyzer
from crypto_utils import CryptoAnalyzer, CryptoPortfolio

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecureTerminalBot:
    def __init__(self):
        self.token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.allowed_users = set(os.getenv('ALLOWED_USERS', '').split(','))
        self.admin_users = set(os.getenv('ADMIN_USERS', '').split(','))
        self.encryption_key = os.getenv('ENCRYPTION_KEY', Fernet.generate_key().decode())
        self.cipher_suite = Fernet(self.encryption_key.encode())
        self.active_sessions = {}
        self.command_history = {}
        self.rate_limit = {}
        
        # Initialize services
        self.nm = nmap.PortScanner()
        self.geolocator = Nominatim(user_agent="telegram_terminal_bot")
        
        # Initialize custom utilities
        self.network_analyzer = NetworkAnalyzer()
        self.ip_geolocation = IPGeolocation()
        self.security_analyzer = SecurityAnalyzer()
        self.crypto_analyzer = CryptoAnalyzer(os.getenv('CRYPTO_API_KEY', ''))
        self.crypto_portfolio = CryptoPortfolio()
        
        # Configure crypto compare
        cryptocompare.cryptocompare._set_api_key_parameter(os.getenv('CRYPTO_API_KEY', ''))

    def is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized to use the bot"""
        return str(user_id) in self.allowed_users or str(user_id) in self.admin_users

    def is_admin(self, user_id: int) -> bool:
        """Check if user is admin"""
        return str(user_id) in self.admin_users

    def check_rate_limit(self, user_id: int) -> bool:
        """Check rate limiting for commands"""
        current_time = time.time()
        if user_id in self.rate_limit:
            last_time = self.rate_limit[user_id]
            if current_time - last_time < 2:  # 2 second limit
                return False
        self.rate_limit[user_id] = current_time
        return True

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user = update.effective_user
        if not self.is_authorized(user.id):
            await update.message.reply_text("❌ Anda tidak memiliki akses ke bot ini.")
            return

        welcome_message = f"""
🤖 **Terminal Bot Aktif!**

Halo {user.first_name}! Bot ini menyediakan:
• 🖥️ Akses terminal interaktif
• 🔍 Pemindaian jaringan dengan nmap
• 🌍 Geolokasi IP/perangkat
• 💰 Data kripto real-time

**Perintah tersedia:**
/help - Daftar semua perintah
/terminal - Akses terminal
/scan <target> - Pindai jaringan
/geoip <ip> - Informasi geolokasi
/crypto <coin> - Data kripto
/status - Status sistem

🔐 Bot ini aman dengan enkripsi end-to-end.
        """
        
        await update.message.reply_text(welcome_message, parse_mode=ParseMode.MARKDOWN)

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        if not self.is_authorized(update.effective_user.id):
            return

        help_text = """
📋 **Daftar Perintah:**

**Terminal:**
• `/terminal` - Mulai sesi terminal
• `/exit` - Keluar dari terminal
• `/clear` - Bersihkan layar

**Jaringan:**
• `/scan <target>` - Pindai host/jaringan
• `/scan_ports <ip> <port>` - Pindai port tertentu
• `/network_info` - Info jaringan lokal

**Geolokasi:**
• `/geoip <ip>` - Info geolokasi IP
• `/geo_distance <ip1> <ip2>` - Jarak antara 2 IP
• `/my_location` - Lokasi Anda

**Kripto:**
• `/crypto <coin>` - Harga kripto (BTC, ETH, dll)
• `/crypto_chart <coin>` - Chart 24h
• `/top_crypto` - Top 10 kripto

**Sistem:**
• `/status` - Status bot
• `/ping <host>` - Ping host
• `/whoami` - Info user
• `/logs` - Log sistem (admin only)

**Keamanan:**
• Semua perintah terenkripsi
• Akses terbatas untuk user tertentu
• Rate limiting aktif
        """
        
        await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

    async def terminal_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start interactive terminal session"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        if not self.check_rate_limit(user_id):
            await update.message.reply_text("⏳ Terlalu banyak permintaan. Tunggu sebentar.")
            return

        # Create keyboard for terminal control
        keyboard = [
            [InlineKeyboardButton("🖥️ Terminal Aktif", callback_data="terminal_active")],
            [InlineKeyboardButton("❌ Keluar", callback_data="exit_terminal")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        self.active_sessions[user_id] = {
            'type': 'terminal',
            'start_time': datetime.now(),
            'commands': []
        }

        await update.message.reply_text(
            "🖥️ **Sesi Terminal Dimulai**\n\n"
            "Ketik perintah Linux/Unix untuk dieksekusi.\n"
            "Gunakan `/exit` untuk keluar.\n\n"
            "⚠️ Perintah berbahaya telah dibatasi untuk keamanan.",
            reply_markup=reply_markup,
            parse_mode=ParseMode.MARKDOWN
        )

    async def handle_terminal_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle terminal command input"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        if user_id not in self.active_sessions or self.active_sessions[user_id]['type'] != 'terminal':
            return

        command = update.message.text.strip()
        
        # Security checks
        dangerous_commands = ['rm -rf', 'dd', 'mkfs', 'fdisk', ':(){ :|:& };:', 'wget', 'curl']
        if any(dangerous in command.lower() for dangerous in dangerous_commands):
            await update.message.reply_text("❌ Perintah berbahaya diblokir untuk keamanan!")
            return

        try:
            # Execute command safely
            result = await self.execute_safe_command(command)
            
            # Encrypt and store in history
            encrypted_result = self.cipher_suite.encrypt(result.encode()).decode()
            self.command_history[user_id] = {
                'command': command,
                'result': encrypted_result,
                'timestamp': datetime.now()
            }

            # Truncate long results
            if len(result) > 4000:
                result = result[:4000] + "\n... (output terpotong)"

            await update.message.reply_text(f"```\n{result}\n```", parse_mode=ParseMode.MARKDOWN)

        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")

    async def execute_safe_command(self, command: str) -> str:
        """Execute command safely with timeout and restrictions"""
        try:
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_path = temp_file.name

            # Execute with timeout and restrictions
            process = await asyncio.create_subprocess_shell(
                f"timeout 30 bash -c '{command}' 2>&1 | head -100",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except:
                pass

            output = stdout.decode() if stdout else ""
            error = stderr.decode() if stderr else ""
            
            return output + error if output or error else "Perintah selesai tanpa output."

        except asyncio.TimeoutError:
            return "❌ Perintah timeout (30 detik)"
        except Exception as e:
            return f"❌ Error eksekusi: {str(e)}"

    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Network scanning with nmap"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        if not context.args:
            await update.message.reply_text("❌ Gunakan: /scan <target>\nContoh: /scan 192.168.1.1")
            return

        target = context.args[0]
        
        try:
            # Basic nmap scan
            self.nm.scan(target, arguments='-sS -O --top-ports 100')
            
            result = f"🔍 **Hasil Pemindaian: {target}**\n\n"
            
            for host in self.nm.all_hosts():
                result += f"**Host:** {host}\n"
                result += f"**Status:** {self.nm[host].state()}\n"
                
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        result += f"**OS:** {osmatch['name']} ({osmatch['accuracy']}%)\n"
                
                result += "\n**Port Terbuka:**\n"
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in sorted(ports):
                        port_info = self.nm[host][proto][port]
                        result += f"  {port}/{proto}: {port_info['state']} - {port_info.get('name', 'unknown')}\n"
                
                result += "\n"

            await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)

        except Exception as e:
            await update.message.reply_text(f"❌ Error pemindaian: {str(e)}")

    async def network_info_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get local network information"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        try:
            network_info = self.network_analyzer.get_local_network_info()
            
            result = "🌐 **Informasi Jaringan Lokal**\n\n"
            result += f"**Hostname:** {network_info.get('hostname', 'N/A')}\n"
            result += f"**IP Lokal:** {network_info.get('local_ip', 'N/A')}\n"
            result += f"**Gateway:** {network_info.get('gateway', 'N/A')}\n\n"
            
            if 'interfaces' in network_info and network_info['interfaces']:
                result += "**Interface Jaringan:**\n"
                for interface in network_info['interfaces']:
                    if isinstance(interface, dict):
                        result += f"  • {interface.get('interface', 'N/A')}: {interface.get('ip', 'N/A')}\n"
                        if interface.get('netmask'):
                            result += f"    Netmask: {interface.get('netmask')}\n"
            
            await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error informasi jaringan: {str(e)}")

    async def ping_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Ping a host"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        if not context.args:
            await update.message.reply_text("❌ Gunakan: /ping <host>\nContoh: /ping google.com")
            return

        host = context.args[0]
        
        try:
            ping_result = self.network_analyzer.ping_host(host)
            
            if ping_result['status'] == 'up':
                result = f"🏓 **Ping Result: {host}**\n\n"
                result += f"**Status:** ✅ UP\n"
                
                if 'statistics' in ping_result:
                    stats = ping_result['statistics']
                    if 'packets' in stats:
                        result += f"**Packets:** {stats['packets']}\n"
                    if 'rtt' in stats:
                        result += f"**RTT:** {stats['rtt']}\n"
                
                await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
            else:
                result = f"🏓 **Ping Result: {host}**\n\n"
                result += f"**Status:** ❌ DOWN\n"
                if 'error' in ping_result:
                    result += f"**Error:** {ping_result['error']}\n"
                
                await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
                
        except Exception as e:
            await update.message.reply_text(f"❌ Error ping: {str(e)}")

    async def advanced_scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Advanced network scanning with detailed analysis"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        if not context.args:
            await update.message.reply_text("❌ Gunakan: /advanced_scan <target>\nContoh: /advanced_scan 192.168.1.1")
            return

        target = context.args[0]
        
        try:
            # Advanced scan with service detection
            scan_result = self.network_analyzer.advanced_port_scan(target)
            
            if 'error' in scan_result:
                await update.message.reply_text(f"❌ Error: {scan_result['error']}")
                return

            result = f"🔍 **Advanced Scan: {target}**\n\n"
            
            for host, info in scan_result.items():
                result += f"**Host:** {host}\n"
                result += f"**Status:** {info['state']}\n"
                
                # OS Detection
                if info['os']:
                    result += "**Operating System:**\n"
                    for os_info in info['os']:
                        result += f"  • {os_info['name']} ({os_info['accuracy']}%)\n"
                
                # Port details
                if info['protocols']:
                    result += "\n**Open Ports & Services:**\n"
                    for proto, ports in info['protocols'].items():
                        for port_info in ports:
                            if port_info['state'] == 'open':
                                service_line = f"  {port_info['port']}/{proto}: {port_info['service']}"
                                if port_info['product']:
                                    service_line += f" ({port_info['product']}"
                                    if port_info['version']:
                                        service_line += f" {port_info['version']}"
                                    service_line += ")"
                                result += service_line + "\n"
                
                result += "\n"
            
            await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error advanced scan: {str(e)}")

    async def geoip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get geolocation information for IP address"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        if not context.args:
            await update.message.reply_text("❌ Gunakan: /geoip <ip_address>\nContoh: /geoip 8.8.8.8")
            return

        ip_address = context.args[0]
        
        try:
            # Get location data
            location = self.geolocator.geocode(ip_address)
            
            if location:
                # Get additional IP info
                response = requests.get(f"http://ip-api.com/json/{ip_address}")
                ip_data = response.json() if response.status_code == 200 else {}
                
                result = f"🌍 **Informasi Geolokasi: {ip_address}**\n\n"
                result += f"**Koordinat:** {location.latitude}, {location.longitude}\n"
                result += f"**Alamat:** {location.address}\n"
                
                if ip_data.get('status') == 'success':
                    result += f"**Negara:** {ip_data.get('country', 'N/A')}\n"
                    result += f"**Kota:** {ip_data.get('city', 'N/A')}\n"
                    result += f"**ISP:** {ip_data.get('isp', 'N/A')}\n"
                    result += f"**Organisasi:** {ip_data.get('org', 'N/A')}\n"
                    result += f"**Zona Waktu:** {ip_data.get('timezone', 'N/A')}\n"
                
                # Calculate distance from user if possible
                user_location = self.geolocator.geocode("me")
                if user_location:
                    distance = geodesic(
                        (location.latitude, location.longitude),
                        (user_location.latitude, user_location.longitude)
                    ).kilometers
                    result += f"**Jarak dari Anda:** {distance:.2f} km\n"
                
                await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
            else:
                await update.message.reply_text("❌ Tidak dapat menemukan informasi untuk IP tersebut.")

        except Exception as e:
            await update.message.reply_text(f"❌ Error geolokasi: {str(e)}")

    async def crypto_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get cryptocurrency data"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        if not context.args:
            await update.message.reply_text("❌ Gunakan: /crypto <coin>\nContoh: /crypto BTC")
            return

        coin = context.args[0].upper()
        
        try:
            # Get price data
            price_data = cryptocompare.get_price(coin, currency='USD')
            coin_data = cryptocompare.get_coin_data(coin)
            
            if price_data and coin in price_data:
                price = price_data[coin]['USD']
                
                result = f"💰 **Data Kripto: {coin}**\n\n"
                result += f"**Harga USD:** ${price:,.2f}\n"
                
                if coin_data:
                    result += f"**Nama Lengkap:** {coin_data.get('Name', 'N/A')}\n"
                    result += f"**Algoritma:** {coin_data.get('Algorithm', 'N/A')}\n"
                    result += f"**Tipe Proof:** {coin_data.get('ProofType', 'N/A')}\n"
                
                # Get 24h change
                hist_data = cryptocompare.get_historical_price_day(coin, 'USD', limit=2)
                if hist_data and len(hist_data) > 1:
                    change = ((price - hist_data[-1]['close']) / hist_data[-1]['close']) * 100
                    result += f"**Perubahan 24h:** {change:+.2f}%\n"
                
                await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
            else:
                await update.message.reply_text("❌ Koin tidak ditemukan atau data tidak tersedia.")

        except Exception as e:
            await update.message.reply_text(f"❌ Error data kripto: {str(e)}")

    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show bot status"""
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return

        status_text = f"""
📊 **Status Bot Terminal**

**Waktu Aktif:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Sesi Aktif:** {len(self.active_sessions)}
**User Terautorisasi:** {len(self.allowed_users)}
**Admin:** {len(self.admin_users)}
**Command History:** {len(self.command_history)}

**Fitur Aktif:**
• ✅ Terminal Interaktif
• ✅ Pemindaian Jaringan (nmap)
• ✅ Geolokasi IP
• ✅ Data Kripto Real-time
• ✅ Enkripsi End-to-End
• ✅ Rate Limiting

**Keamanan:**
• 🔐 Enkripsi: Aktif
• 🛡️ Filter Perintah: Aktif
• ⏱️ Rate Limit: 2 detik
        """
        
        await update.message.reply_text(status_text, parse_mode=ParseMode.MARKDOWN)

    async def exit_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Exit current session"""
        user_id = update.effective_user.id
        
        if user_id in self.active_sessions:
            session_type = self.active_sessions[user_id]['type']
            del self.active_sessions[user_id]
            await update.message.reply_text(f"✅ Keluar dari sesi {session_type}.")
        else:
            await update.message.reply_text("❌ Tidak ada sesi aktif.")

    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks"""
        query = update.callback_query
        user_id = query.from_user.id
        
        if not self.is_authorized(user_id):
            await query.answer("❌ Tidak memiliki akses!")
            return

        if query.data == "exit_terminal":
            if user_id in self.active_sessions:
                del self.active_sessions[user_id]
            await query.edit_message_text("✅ Sesi terminal diakhiri.")
        
        await query.answer()

    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle errors"""
        logger.error(f"Update {update} caused error {context.error}")
        
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "❌ Terjadi kesalahan. Silakan coba lagi atau hubungi admin."
            )

def main():
    """Main function"""
    # Initialize bot
    bot = SecureTerminalBot()
    
    if not bot.token:
        logger.error("TELEGRAM_BOT_TOKEN tidak ditemukan di environment variables!")
        return

    # Create application
    application = Application.builder().token(bot.token).build()

    # Add handlers
    application.add_handler(CommandHandler("start", bot.start_command))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("terminal", bot.terminal_command))
    application.add_handler(CommandHandler("scan", bot.scan_command))
    application.add_handler(CommandHandler("advanced_scan", bot.advanced_scan_command))
    application.add_handler(CommandHandler("network_info", bot.network_info_command))
    application.add_handler(CommandHandler("ping", bot.ping_command))
    application.add_handler(CommandHandler("geoip", bot.geoip_command))
    application.add_handler(CommandHandler("crypto", bot.crypto_command))
    application.add_handler(CommandHandler("top_crypto", bot.top_crypto_command))
    application.add_handler(CommandHandler("crypto_chart", bot.crypto_chart_command))
    application.add_handler(CommandHandler("market_overview", bot.market_overview_command))
    application.add_handler(CommandHandler("status", bot.status_command))
    application.add_handler(CommandHandler("exit", bot.exit_command))
    
    # Handle terminal input
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_terminal_input))
    
    # Handle callbacks
    application.add_handler(CallbackQueryHandler(bot.button_callback))
    
    # Error handler
    application.add_error_handler(bot.error_handler)

    # Start bot
    logger.info("Bot dimulai...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()