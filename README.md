# Telegram Terminal Bot

Bot Telegram canggih dengan integrasi terminal interaktif, pemindaian jaringan, geolokasi IP, dan data kripto real-time dengan keamanan tingkat tinggi.

## Fitur Utama

### Terminal Interaktif
- Akses terminal Linux/Unix langsung dari chat Telegram
- Keamanan tinggi dengan filter perintah berbahaya
- Enkripsi end-to-end untuk semua komunikasi
- History perintah tersimpan dengan aman
- Timeout otomatis untuk mencegah hanging

### Pemindaian Jaringan
- Integrasi penuh dengan nmap
- Pemindaian port, layanan, dan OS detection
- Analisis kerentanan keamanan
- Pemindaian port tertentu
- Informasi jaringan lokal

### Geolokasi IP
- Informasi geolokasi lengkap untuk IP address
- Jarak antara dua lokasi IP
- Data ISP, organisasi, dan zona waktu
- Integrasi dengan multiple API geolokasi
- Koordinat GPS dan alamat lengkap

### Data Kripto Real-time
- Harga kripto terkini dari berbagai sumber
- Chart data dan analisis tren
- Top 10 cryptocurrency
- Perubahan harga 24 jam
- Portfolio tracking (fitur lanjutan)

### Keamanan
- Autentikasi user terenkripsi
- Rate limiting untuk mencegah spam
- Filter perintah berbahaya
- Akses terbatas untuk user tertentu
- Logging dan monitoring aktivitas

## Persyaratan Sistem

- Python 3.7 atau lebih tinggi
- Sistem operasi Linux/Unix (Ubuntu, Debian, CentOS, dll)
- Akses root untuk fitur nmap penuh
- Koneksi internet stabil
- Telegram Bot Token

## Instalasi Cepat

### 1. Clone Repository
```bash
git clone https://github.com/your-repo/telegram-terminal-bot.git
cd telegram-terminal-bot
```

### 2. Jalankan Setup Otomatis
```bash
python3 setup.py
```

### 3. Konfigurasi Environment
```bash
cp .env.example .env
nano .env  # Edit dengan informasi Anda
```

### 4. Dapatkan Telegram Bot Token
1. Buka @BotFather di Telegram
2. Buat bot baru: `/newbot`
3. Ikuti instruksi untuk mendapatkan token
4. Masukkan token ke file `.env`

### 5. Jalankan Bot
```bash
python3 telegram_terminal_bot.py
```

## Konfigurasi

### File .env
```env
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=your_bot_token_here
ALLOWED_USERS=123456789,987654321
ADMIN_USERS=123456789
ENCRYPTION_KEY=your_generated_key
CRYPTO_API_KEY=your_crypto_api_key
```

### User Management
- `ALLOWED_USERS`: Daftar user ID yang diizinkan (pisahkan dengan koma)
- `ADMIN_USERS`: Daftar admin user ID (memiliki akses penuh)
- Untuk mendapatkan user ID: kirim pesan ke bot dan cek log

## Perintah Bot

### Perintah Utama
- `/start` - Memulai bot dan menampilkan menu utama
- `/help` - Menampilkan daftar semua perintah
- `/status` - Status sistem dan informasi bot

### Terminal Commands
- `/terminal` - Mulai sesi terminal interaktif
- `/exit` - Keluar dari sesi terminal
- `/clear` - Bersihkan layar terminal

### Network Commands
- `/scan <target>` - Pindai host/jaringan
- `/scan_ports <ip> <ports>` - Pindai port tertentu
- `/network_info` - Informasi jaringan lokal
- `/ping <host>` - Ping host
- `/traceroute <host>` - Traceroute ke host

### Geolocation Commands
- `/geoip <ip>` - Informasi geolokasi IP
- `/geo_distance <ip1> <ip2>` - Jarak antara dua IP
- `/my_location` - Lokasi Anda saat ini

### Cryptocurrency Commands
- `/crypto <coin>` - Harga kripto (BTC, ETH, dll)
- `/crypto_chart <coin>` - Chart dan analisis
- `/top_crypto` - Top 10 cryptocurrency
- `/crypto_news <coin>` - Berita kripto terkini

## Penggunaan Lanjutan

### Terminal Security
Bot ini memiliki keamanan tinggi untuk terminal:
- Filter perintah berbahaya otomatis
- Timeout 30 detik per perintah
- Batasan output maksimal
- Enkripsi semua komunikasi

### Network Scanning
Gunakan dengan bijak untuk pemindaian jaringan:
- Pemindaian dasar: `/scan 192.168.1.1`
- Pemindaian port: `/scan_ports 192.168.1.1 80,443,8080`
- Analisis kerentanan tersedia untuk admin

### Crypto Portfolio (Fitur Premium)
Untuk fitur portfolio tracking:
- Tambahkan holding: `/portfolio_add BTC 0.5 50000`
- Update nilai: `/portfolio_update`
- Ringkasan: `/portfolio_summary`

## Keamanan & Best Practices

### 1. User Access Control
- Hanya tambahkan user yang terpercaya
- Gunakan user ID, bukan username
- Review akses secara berkala

### 2. Network Security
- Jalankan di jaringan terpercaya
- Gunakan VPN untuk akses remote
- Monitor log aktivitas

### 3. Command Safety
- Perintah berbahaya otomatis diblokir
- Review filter secara berkala
- Update keamanan secara rutin

### 4. Data Protection
- Semua data sensitif terenkripsi
- Backup konfigurasi secara berkala
- Gunakan firewall yang tepat

## Troubleshooting

### Bot tidak merespon
1. Cek token Telegram di .env
2. Pastikan bot running: `ps aux | grep python`
3. Cek log file di folder logs/

### Terminal tidak berfungsi
1. Pastikan user memiliki akses
2. Cek permission sistem
3. Restart bot

### Network scanning gagal
1. Pastikan nmap terinstall: `nmap --version`
2. Jalankan dengan sudo jika perlu
3. Cek firewall lokal

### Crypto data error
1. Pastikan koneksi internet
2. Cek API key di .env
3. Coba koin yang berbeda

## Monitoring & Logging

Bot mencatat semua aktivitas:
- Log file: `logs/bot_activity.log`
- Format: JSON dengan timestamp
- Rotation otomatis harian
- Retensi 30 hari

Untuk monitoring real-time:
```bash
tail -f logs/bot_activity.log
```

## Integrasi API

### Crypto APIs
- CryptoCompare (default)
- CoinGecko (backup)
- Binance API (opsional)

### Geolocation APIs
- IP-API.com
- IPInfo.io
- FreeGeoIP.app

### Rate Limiting
- 2 detik antara perintah
- Batasan harian per user
- Admin bypass untuk emergency

## Lisensi

Proyek ini dilisensikan di bawah MIT License. Lihat file LICENSE untuk detail.

## Kontribusi

Kontribusi sangat welcome! Silakan:
1. Fork repository
2. Buat branch fitur
3. Commit perubahan
4. Push ke branch
5. Buat Pull Request

## Dukungan

Untuk bantuan dan pertanyaan:
- Email: support@yourdomain.com
- Telegram: @YourSupportHandle
- GitHub Issues

## Update & Maintenance

Update rutin tersedia:
- Security patches
- Fitur baru
- Bug fixes
- Performance improvements

Untuk update:
```bash
git pull origin main
python3 setup.py
```

---

**Disclaimer**: Gunakan bot ini dengan bijak dan bertanggung jawab. Pemindaian jaringan hanya untuk jaringan yang Anda miliki atau memiliki izin. Kami tidak bertanggung jawab atas penyalahgunaan fitur ini.

**Security Notice**: Selalu update ke versi terbaru untuk patch keamanan. Laporkan vulnerability ke security@yourdomain.com