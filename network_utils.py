#!/usr/bin/env python3
"""
Network utilities for the Telegram Terminal Bot
Enhanced network scanning and analysis functions
"""

import socket
import subprocess
import json
import logging
from typing import Dict, List, Optional
import requests
import nmap

logger = logging.getLogger(__name__)

class NetworkAnalyzer:
    def __init__(self):
        self.nm = nmap.PortScanner()
        
    def get_local_network_info(self) -> Dict:
        """Get local network information"""
        try:
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Get gateway (router IP)
            try:
                gateway = subprocess.check_output(['ip', 'route'], text=True).split('default via ')[1].split()[0]
            except:
                gateway = "N/A"
            
            # Get network interfaces
            interfaces = []
            try:
                import psutil
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            interfaces.append({
                                'interface': interface,
                                'ip': addr.address,
                                'netmask': addr.netmask,
                                'broadcast': addr.broadcast
                            })
            except ImportError:
                interfaces = [{"info": "psutil not installed"}]
            
            return {
                'hostname': hostname,
                'local_ip': local_ip,
                'gateway': gateway,
                'interfaces': interfaces
            }
            
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return {'error': str(e)}
    
    def advanced_port_scan(self, target: str, ports: str = "1-1000") -> Dict:
        """Advanced port scanning with service detection"""
        try:
            # Comprehensive scan with service detection
            self.nm.scan(target, ports, arguments='-sS -sV -sC -O --top-ports 1000')
            
            results = {}
            for host in self.nm.all_hosts():
                host_info = {
                    'state': self.nm[host].state(),
                    'protocols': {},
                    'os': []
                }
                
                # OS Detection
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        host_info['os'].append({
                            'name': osmatch['name'],
                            'accuracy': osmatch['accuracy'],
                            'type': osmatch.get('osclass', [{}])[0].get('type', 'unknown')
                        })
                
                # Port scanning
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    host_info['protocols'][proto] = []
                    
                    for port in sorted(ports):
                        port_info = self.nm[host][proto][port]
                        service_info = {
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'cpe': port_info.get('cpe', [])
                        }
                        host_info['protocols'][proto].append(service_info)
                
                results[host] = host_info
            
            return results
            
        except Exception as e:
            logger.error(f"Error in advanced port scan: {e}")
            return {'error': str(e)}
    
    def vulnerability_scan(self, target: str) -> Dict:
        """Scan for common vulnerabilities"""
        try:
            # Scan for common vulnerable ports
            vulnerable_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
            port_list = ','.join(map(str, vulnerable_ports))
            
            self.nm.scan(target, port_list, arguments='-sS -sV --script vuln')
            
            vulnerabilities = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        port_info = self.nm[host][proto][port]
                        
                        # Check for vulnerability scripts
                        if 'script' in port_info:
                            for script_name, script_output in port_info['script'].items():
                                if 'vuln' in script_name.lower():
                                    vulnerabilities.append({
                                        'host': host,
                                        'port': port,
                                        'protocol': proto,
                                        'service': port_info.get('name', 'unknown'),
                                        'vulnerability': script_name,
                                        'details': script_output
                                    })
            
            return {
                'target': target,
                'vulnerabilities_found': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            }
            
        except Exception as e:
            logger.error(f"Error in vulnerability scan: {e}")
            return {'error': str(e)}
    
    def ping_host(self, host: str, count: int = 4) -> Dict:
        """Ping a host and return statistics"""
        try:
            # Use system ping command
            result = subprocess.run(
                ['ping', '-c', str(count), host],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse ping output
                lines = result.stdout.split('\n')
                stats = {}
                
                for line in lines:
                    if 'packets transmitted' in line:
                        stats['packets'] = line.strip()
                    elif 'round-trip' in line or 'rtt' in line:
                        stats['rtt'] = line.strip()
                    elif 'time=' in line:
                        if 'icmp_seq' not in stats:
                            stats['sample_ping'] = line.strip()
                
                return {
                    'host': host,
                    'status': 'up',
                    'statistics': stats,
                    'raw_output': result.stdout
                }
            else:
                return {
                    'host': host,
                    'status': 'down',
                    'error': result.stderr,
                    'raw_output': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {
                'host': host,
                'status': 'timeout',
                'error': 'Ping timeout'
            }
        except Exception as e:
            logger.error(f"Error pinging host: {e}")
            return {
                'host': host,
                'status': 'error',
                'error': str(e)
            }
    
    def traceroute(self, host: str) -> Dict:
        """Perform traceroute to host"""
        try:
            result = subprocess.run(
                ['traceroute', host],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                hops = []
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            hop_num = parts[0]
                            host_info = parts[1] if parts[1] != '*' else 'Timeout'
                            times = parts[2:] if len(parts) > 2 else []
                            
                            hops.append({
                                'hop': hop_num,
                                'host': host_info,
                                'times': times
                            })
                
                return {
                    'host': host,
                    'hops': hops,
                    'total_hops': len(hops),
                    'raw_output': result.stdout
                }
            else:
                return {
                    'host': host,
                    'status': 'error',
                    'error': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'host': host,
                'status': 'timeout',
                'error': 'Traceroute timeout'
            }
        except Exception as e:
            logger.error(f"Error in traceroute: {e}")
            return {
                'host': host,
                'status': 'error',
                'error': str(e)
            }

class IPGeolocation:
    def __init__(self):
        self.api_services = [
            "http://ip-api.com/json/{}",
            "https://ipinfo.io/{}/json",
            "https://freegeoip.app/json/{}"
        ]
    
    def get_ip_info(self, ip_address: str) -> Dict:
        """Get comprehensive IP geolocation information"""
        results = {}
        
        for service in self.api_services:
            try:
                url = service.format(ip_address)
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Standardize data format
                    if 'ip-api.com' in service:
                        results['ip_api'] = {
                            'country': data.get('country'),
                            'country_code': data.get('countryCode'),
                            'region': data.get('regionName'),
                            'city': data.get('city'),
                            'zip': data.get('zip'),
                            'lat': data.get('lat'),
                            'lon': data.get('lon'),
                            'timezone': data.get('timezone'),
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'as': data.get('as'),
                            'mobile': data.get('mobile', False),
                            'proxy': data.get('proxy', False),
                            'hosting': data.get('hosting', False)
                        }
                    elif 'ipinfo.io' in service:
                        results['ipinfo'] = {
                            'country': data.get('country'),
                            'region': data.get('region'),
                            'city': data.get('city'),
                            'loc': data.get('loc'),
                            'org': data.get('org'),
                            'postal': data.get('postal'),
                            'timezone': data.get('timezone')
                        }
                    elif 'freegeoip.app' in service:
                        results['freegeoip'] = {
                            'country': data.get('country_name'),
                            'country_code': data.get('country_code'),
                            'region': data.get('region_name'),
                            'city': data.get('city'),
                            'zip': data.get('zip_code'),
                            'lat': data.get('latitude'),
                            'lon': data.get('longitude'),
                            'timezone': data.get('time_zone')
                        }
                        
            except Exception as e:
                logger.error(f"Error getting IP info from {service}: {e}")
                continue
        
        return results
    
    def calculate_distance(self, ip1: str, ip2: str) -> Dict:
        """Calculate distance between two IP addresses"""
        try:
            info1 = self.get_ip_info(ip1)
            info2 = self.get_ip_info(ip2)
            
            # Extract coordinates
            coord1 = None
            coord2 = None
            
            if 'ip_api' in info1 and info1['ip_api'].get('lat') and info1['ip_api'].get('lon'):
                coord1 = (info1['ip_api']['lat'], info1['ip_api']['lon'])
            
            if 'ip_api' in info2 and info2['ip_api'].get('lat') and info2['ip_api'].get('lon'):
                coord2 = (info2['ip_api']['lat'], info2['ip_api']['lon'])
            
            if coord1 and coord2:
                from geopy.distance import geodesic
                distance_km = geodesic(coord1, coord2).kilometers
                distance_miles = geodesic(coord1, coord2).miles
                
                return {
                    'ip1': ip1,
                    'ip2': ip2,
                    'distance_km': distance_km,
                    'distance_miles': distance_miles,
                    'location1': info1,
                    'location2': info2
                }
            else:
                return {
                    'error': 'Could not get coordinates for one or both IPs'
                }
                
        except Exception as e:
            logger.error(f"Error calculating distance: {e}")
            return {'error': str(e)}

# Network security utilities
class SecurityAnalyzer:
    def __init__(self):
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "Windows RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP Alt"
        }
    
    def analyze_port_security(self, open_ports: List[int]) -> Dict:
        """Analyze security implications of open ports"""
        security_analysis = {
            'risk_level': 'low',
            'warnings': [],
            'recommendations': []
        }
        
        high_risk_ports = [23, 135, 139, 445, 1433, 3389]  # Telnet, Windows services, RDP
        medium_risk_ports = [21, 22, 25, 110, 143, 3306, 5432, 5900]  # Services that should be secured
        
        high_risk_found = [port for port in open_ports if port in high_risk_ports]
        medium_risk_found = [port for port in open_ports if port in medium_risk_ports]
        
        if high_risk_found:
            security_analysis['risk_level'] = 'high'
            security_analysis['warnings'].extend([
                f"High-risk ports detected: {', '.join(map(str, high_risk_found))}",
                "These ports are commonly targeted by attackers"
            ])
            security_analysis['recommendations'].extend([
                "Consider closing unnecessary high-risk ports",
                "Implement proper firewall rules",
                "Use VPN for remote access instead of direct port exposure"
            ])
        
        if medium_risk_found:
            if security_analysis['risk_level'] == 'low':
                security_analysis['risk_level'] = 'medium'
            security_analysis['warnings'].append(
                f"Medium-risk service ports: {', '.join(map(str, medium_risk_found))}"
            )
            security_analysis['recommendations'].extend([
                "Ensure services are properly configured and secured",
                "Use strong authentication mechanisms",
                "Keep services updated with latest security patches"
            ])
        
        return security_analysis
    
    def check_common_vulnerabilities(self, target: str) -> Dict:
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        # This is a simplified check - in real scenarios, you'd use more comprehensive tools
        common_checks = [
            {'name': 'Unencrypted Services', 'ports': [21, 23, 25, 110, 143]},
            {'name': 'Database Exposure', 'ports': [3306, 5432, 1433]},
            {'name': 'Remote Desktop', 'ports': [3389, 5900]},
            {'name': 'Windows Services', 'ports': [135, 139, 445]}
        ]
        
        try:
            nm = nmap.PortScanner()
            
            for check in common_checks:
                port_list = ','.join(map(str, check['ports']))
                nm.scan(target, port_list, arguments='-sS -T4')
                
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_info = nm[host][proto][port]
                            if port_info['state'] == 'open':
                                vulnerabilities.append({
                                    'category': check['name'],
                                    'port': port,
                                    'service': port_info.get('name', 'unknown'),
                                    'severity': 'high' if check['name'] in ['Unencrypted Services', 'Database Exposure'] else 'medium'
                                })
        
        except Exception as e:
            logger.error(f"Error checking vulnerabilities: {e}")
        
        return {
            'target': target,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'security_score': max(0, 100 - (len(vulnerabilities) * 10))
        }